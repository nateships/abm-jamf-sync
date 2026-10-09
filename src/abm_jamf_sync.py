"""Sync order and AppleCare data from Apple Business Manager into Jamf Pro.

The script reads devices from Jamf Pro, finds each serial number in Apple
Business Manager (or Apple School Manager), and writes the purchasing fields
that changed. It never clears a field in Jamf Pro.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import jwt

ABM_TOKEN_URL = "https://account.apple.com/auth/oauth2/token"
ABM_AUDIENCE = "https://account.apple.com/auth/oauth2/v2/token"
ABM_API = {"business": "https://api-business.apple.com", "school": "https://api-school.apple.com"}

# Logical field names. The value is the Jamf field name for computers and for mobile devices.
FIELD_NAMES = {
    "purchased": ("purchased", "purchased"),
    "poNumber": ("poNumber", "poNumber"),
    "poDate": ("poDate", "poDate"),
    "vendor": ("vendor", "vendor"),
    "warrantyDate": ("warrantyDate", "warrantyExpiresDate"),
    "appleCareId": ("appleCareId", "appleCareId"),
}
DATE_FIELDS = {"poDate", "warrantyDate"}
DEFAULT_FIELDS = "poNumber,poDate,vendor,warrantyDate,appleCareId"
MOBILE_PATCH_KEYS = {"iOS": "ios", "tvOS": "tvos"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")

MAX_RETRIES = 5
MAX_BACKOFF_SECONDS = 60


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


class HttpError(Exception):
    def __init__(self, status: int, url: str, body: str):
        super().__init__(f"HTTP {status} for {url}: {body[:300]}")
        self.status = status


def http_request(method: str, url: str, headers: dict[str, str] | None = None,
                 body: bytes | None = None) -> tuple[int, dict[str, str], bytes]:
    """Send one HTTP request. Return the status, the headers and the body."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers or {}), err.read()
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        # Report a network failure as status 599, so that call() retries it like a server error.
        return 599, {}, str(err).encode()


# Tests replace this function.
send: Callable[..., tuple[int, dict[str, str], bytes]] = http_request
sleep: Callable[[float], None] = time.sleep


def call(method: str, url: str, headers: dict[str, str] | None = None,
         body: bytes | None = None) -> tuple[int, bytes]:
    """Send a request. Retry on 429 and 5xx. Obey Retry-After."""
    for attempt in range(MAX_RETRIES + 1):
        status, resp_headers, data = send(method, url, headers, body)
        if status != 429 and status < 500:
            return status, data
        if attempt == MAX_RETRIES:
            return status, data
        retry_after = {k.lower(): v for k, v in resp_headers.items()}.get("retry-after", "")
        delay = float(retry_after) if retry_after.isdigit() else 2 ** attempt
        sleep(min(delay, MAX_BACKOFF_SECONDS))
    raise AssertionError("unreachable")


def mask(value: str) -> None:
    """Tell GitHub Actions to hide a value in the logs."""
    if value and os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{value}", flush=True)


class BearerClient:
    """Base for an API client that uses a bearer token with a short life."""

    def __init__(self) -> None:
        self._token = ""
        self._expires_at = 0.0

    def _fetch_token(self) -> tuple[str, int]:
        raise NotImplementedError

    def _token_value(self, force: bool = False) -> str:
        if force or time.time() >= self._expires_at:
            token, lifetime = self._fetch_token()
            mask(token)
            # Refresh before the token expires. Keep a margin of 25% of the lifetime, up to 60 seconds.
            self._token = token
            self._expires_at = time.time() + lifetime - min(60, lifetime / 4)
        return self._token

    def request(self, method: str, url: str, payload: Any = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        for force in (False, True):
            headers = {"Authorization": f"Bearer {self._token_value(force)}", "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            status, data = call(method, url, headers, body)
            if status == 401 and not force:
                continue
            if status >= 400:
                raise HttpError(status, url, data.decode(errors="replace"))
            return json.loads(data) if data else None
        raise AssertionError("unreachable")


# --------------------------------------------------------------------------
# Apple Business Manager / Apple School Manager
# --------------------------------------------------------------------------


class AxmClient(BearerClient):
    def __init__(self, client_id: str, key_id: str, private_key: str, scope: str):
        super().__init__()
        self.client_id = client_id
        self.key_id = key_id
        self.private_key = private_key
        self.scope = scope
        self.base = ABM_API[scope]

    def client_assertion(self) -> str:
        now = int(time.time())
        payload = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": ABM_AUDIENCE,
            "iat": now,
            "exp": now + 1200,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, self.private_key, algorithm="ES256", headers={"kid": self.key_id})

    def _fetch_token(self) -> tuple[str, int]:
        query = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.client_assertion(),
            "scope": f"{self.scope}.api",
        })
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, data = call("POST", f"{ABM_TOKEN_URL}?{query}", headers, b"")
        if status != 200:
            raise HttpError(status, ABM_TOKEN_URL, data.decode(errors="replace"))
        token = json.loads(data)
        return token["access_token"], int(token.get("expires_in", 3600))

    def devices(self) -> dict[str, dict]:
        """Return all organization devices, keyed by serial number."""
        result: dict[str, dict] = {}
        url: str | None = f"{self.base}/v1/orgDevices"
        while url:
            page = self.request("GET", url)
            for item in page.get("data", []):
                attrs = item.get("attributes", {})
                serial = normalize_serial(attrs.get("serialNumber") or item.get("id"))
                if serial:
                    result[serial] = {"id": item["id"], **attrs}
            url = (page.get("links") or {}).get("next")
        return result

    def coverage(self, device_id: str) -> list[dict]:
        url = f"{self.base}/v1/orgDevices/{urllib.parse.quote(device_id)}/appleCareCoverage"
        try:
            page = self.request("GET", url)
        except HttpError as err:
            if err.status == 404:
                return []
            raise
        return [item.get("attributes", {}) for item in page.get("data", [])]


# --------------------------------------------------------------------------
# Jamf Pro
# --------------------------------------------------------------------------


class JamfClient(BearerClient):
    PAGE_SIZE = 100

    def __init__(self, url: str, client_id: str, client_secret: str):
        super().__init__()
        self.base = url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret

    def _fetch_token(self) -> tuple[str, int]:
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, data = call("POST", f"{self.base}/api/oauth/token", headers, body)
        if status != 200:
            raise HttpError(status, f"{self.base}/api/oauth/token", data.decode(errors="replace"))
        token = json.loads(data)
        return token["access_token"], int(token.get("expires_in", 60))

    def _pages(self, path: str, sections: list[str], sort: str) -> list[dict]:
        records: list[dict] = []
        page = 0
        while True:
            query = [("section", s) for s in sections]
            query += [("page", str(page)), ("page-size", str(self.PAGE_SIZE)), ("sort", sort)]
            data = self.request("GET", f"{self.base}{path}?{urllib.parse.urlencode(query)}")
            results = data.get("results", [])
            records.extend(results)
            if not results or len(records) >= data.get("totalCount", 0):
                return records
            page += 1

    def computers(self, with_extension_attributes: bool) -> list[dict]:
        sections = ["HARDWARE", "PURCHASING"]
        if with_extension_attributes:
            # Jamf shows an extension attribute in the section that its Inventory Display setting names.
            sections += ["EXTENSION_ATTRIBUTES", "GENERAL", "OPERATING_SYSTEM", "USER_AND_LOCATION"]
        return self._pages("/api/v4/computers-inventory", sections, "id:asc")

    def mobile_devices(self) -> list[dict]:
        return self._pages("/api/v2/mobile-devices/detail", ["HARDWARE", "PURCHASING"], "mobileDeviceId:asc")

    def update_computer(self, device_id: str, purchasing: dict) -> None:
        self.request("PATCH", f"{self.base}/api/v4/computers-inventory-detail/{device_id}",
                     {"purchasing": purchasing})

    def update_mobile_device(self, device_id: str, patch_key: str, purchasing: dict) -> None:
        self.request("PATCH", f"{self.base}/api/v2/mobile-devices/{device_id}",
                     {patch_key: {"purchasing": purchasing}})


# --------------------------------------------------------------------------
# Planning: pure functions
# --------------------------------------------------------------------------


def normalize_serial(value: Any) -> str:
    return str(value or "").strip().upper()


def to_date(value: Any) -> str | None:
    """Return the YYYY-MM-DD part of a date or date-time value, in UTC."""
    if not value or not isinstance(value, str):
        return None
    if "T" in value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(UTC)
        return parsed.date().isoformat()
    return value[:10] if DATE_RE.match(value) else None


def pick_warranty_end(coverages: list[dict]) -> str | None:
    """Return the latest end date of the coverages that are not canceled."""
    ends = [to_date(c.get("endDateTime")) for c in coverages if not c.get("isCanceled")]
    ends = [e for e in ends if e]
    return max(ends) if ends else None


def pick_agreement(coverages: list[dict]) -> str | None:
    """Return the agreement number of the coverage that ends last and has one."""
    candidates = [c for c in coverages if not c.get("isCanceled") and c.get("agreementNumber")]
    if not candidates:
        return None
    candidates.sort(key=lambda c: to_date(c.get("endDateTime")) or "")
    return str(candidates[-1]["agreementNumber"])


def vendor_name(device: dict, vendor_map: dict[str, str]) -> str | None:
    source = device.get("purchaseSourceType")
    if source == "APPLE":
        return "Apple"
    if source == "RESELLER":
        return vendor_map.get(str(device.get("purchaseSourceUid") or ""))
    return None


def desired_from_abm(device: dict, coverages: list[dict], vendor_map: dict[str, str]) -> dict[str, Any]:
    """Return the logical field values that ABM supplies for a device. Leave out empty values."""
    values = {
        "purchased": True if device.get("purchaseSourceType") in ("APPLE", "RESELLER") else None,
        "poNumber": device.get("orderNumber") or None,
        "poDate": to_date(device.get("orderDateTime")),
        "vendor": vendor_name(device, vendor_map),
        "warrantyDate": pick_warranty_end(coverages),
        "appleCareId": pick_agreement(coverages),
    }
    return {k: v for k, v in values.items() if v is not None}


EA_SECTIONS = ("purchasing", "general", "hardware", "operatingSystem", "userAndLocation")


def desired_from_ea(computer: dict, ea_name: str) -> dict[str, Any]:
    """Return the warranty date from a computer extension attribute, if it has a valid date."""
    attributes = list(computer.get("extensionAttributes") or [])
    for section in EA_SECTIONS:
        attributes += (computer.get(section) or {}).get("extensionAttributes") or []
    for ea in attributes:
        if ea.get("name") == ea_name:
            values = ea.get("values") or []
            date = to_date(values[0]) if values else None
            return {"warrantyDate": date} if date else {}
    return {}


def plan_changes(desired: dict[str, Any], purchasing: dict, kind: str, fields: list[str]) -> dict[str, Any]:
    """Return the Jamf purchasing body for the fields that differ. Never clear a field."""
    index = 0 if kind == "computer" else 1
    changes: dict[str, Any] = {}
    for logical in fields:
        if logical not in desired:
            continue
        jamf_name = FIELD_NAMES[logical][index]
        want = desired[logical]
        have = purchasing.get(jamf_name)
        if logical in DATE_FIELDS:
            if to_date(have) == want:
                continue
            # Mobile devices take a date-time. Noon UTC keeps the same date in every server time zone.
            changes[jamf_name] = want if kind == "computer" else f"{want}T12:00:00Z"
        elif have != want:
            changes[jamf_name] = want
    return changes


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------


@dataclass
class Config:
    jamf_url: str
    jamf_client_id: str
    jamf_client_secret: str
    axm_client_id: str
    axm_key_id: str
    axm_private_key: str
    axm_scope: str = "business"
    dry_run: bool = True
    fields: list[str] = field(default_factory=lambda: DEFAULT_FIELDS.split(","))
    device_types: list[str] = field(default_factory=lambda: ["computers"])
    vendor_map: dict[str, str] = field(default_factory=dict)
    warranty_ea_name: str = ""
    serials: set[str] = field(default_factory=set)
    fail_on_error: bool = True


@dataclass
class Report:
    counts: dict[str, int] = field(default_factory=lambda: {
        "jamf_devices": 0, "matched_abm": 0, "matched_ea": 0, "no_data": 0, "unsupported": 0,
        "unchanged": 0, "changed": 0, "errors": 0,
    })
    changes: list[tuple[str, str, str, dict]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def split_list(value: str) -> list[str]:
    return [item for item in re.split(r"[\s,]+", value or "") if item]


def env_bool(value: str, default: bool) -> bool:
    if not value:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def config_from_env(env: dict[str, str]) -> Config:
    def required(name: str) -> str:
        value = env.get(name, "").strip()
        if not value:
            raise SystemExit(f"error: input {name} is required")
        return value

    fields = split_list(env.get("FIELDS") or DEFAULT_FIELDS)
    unknown = [f for f in fields if f not in FIELD_NAMES]
    if unknown:
        raise SystemExit(f"error: unknown fields: {', '.join(unknown)}. Use: {', '.join(FIELD_NAMES)}")
    device_types = split_list(env.get("DEVICE_TYPES") or "computers")
    bad_types = [t for t in device_types if t not in ("computers", "mobile")]
    if bad_types:
        raise SystemExit(f"error: unknown device types: {', '.join(bad_types)}. Use: computers, mobile")
    scope = (env.get("AXM_SCOPE") or "business").strip().lower()
    if scope not in ABM_API:
        raise SystemExit("error: AXM_SCOPE must be business or school")
    try:
        vendor_map = json.loads(env.get("VENDOR_MAP") or "{}")
    except json.JSONDecodeError as err:
        raise SystemExit(f"error: VENDOR_MAP is not valid JSON: {err}") from None
    if not isinstance(vendor_map, dict):
        raise SystemExit("error: VENDOR_MAP must be a JSON object")
    return Config(
        jamf_url=required("JAMF_URL"),
        jamf_client_id=required("JAMF_CLIENT_ID"),
        jamf_client_secret=required("JAMF_CLIENT_SECRET"),
        axm_client_id=required("AXM_CLIENT_ID"),
        axm_key_id=required("AXM_KEY_ID"),
        axm_private_key=required("AXM_PRIVATE_KEY"),
        axm_scope=scope,
        dry_run=env_bool(env.get("DRY_RUN", ""), True),
        fields=fields,
        device_types=device_types,
        vendor_map={str(k): str(v) for k, v in vendor_map.items()},
        warranty_ea_name=(env.get("WARRANTY_EA_NAME") or "").strip(),
        serials={normalize_serial(s) for s in split_list(env.get("SERIALS", ""))},
        fail_on_error=env_bool(env.get("FAIL_ON_ERROR", ""), True),
    )


def jamf_records(jamf: JamfClient, cfg: Config) -> list[dict]:
    """Return Jamf devices as uniform records."""
    records = []
    if "computers" in cfg.device_types:
        for c in jamf.computers(with_extension_attributes=bool(cfg.warranty_ea_name)):
            records.append({
                "kind": "computer", "id": str(c["id"]), "patch_key": "",
                "serial": normalize_serial((c.get("hardware") or {}).get("serialNumber")),
                "purchasing": c.get("purchasing") or {}, "raw": c,
            })
    if "mobile" in cfg.device_types:
        for m in jamf.mobile_devices():
            records.append({
                "kind": "mobile", "id": str(m["mobileDeviceId"]),
                "patch_key": MOBILE_PATCH_KEYS.get(m.get("deviceType", ""), ""),
                "serial": normalize_serial((m.get("hardware") or {}).get("serialNumber")),
                "purchasing": m.get("purchasing") or {}, "raw": m,
            })
    return records


def run(cfg: Config, jamf: JamfClient, axm: AxmClient, log: Callable[[str], None] = print) -> Report:
    report = Report()
    records = [r for r in jamf_records(jamf, cfg) if r["serial"]]
    if cfg.serials:
        records = [r for r in records if r["serial"] in cfg.serials]
    report.counts["jamf_devices"] = len(records)

    seen: dict[str, int] = {}
    for r in records:
        seen[r["serial"]] = seen.get(r["serial"], 0) + 1
    for serial, count in sorted(seen.items()):
        if count > 1:
            log(f"warning: serial {serial} is on {count} Jamf records. Every record gets the same data.")

    abm_devices = axm.devices()
    coverage_cache: dict[str, list[dict]] = {}
    unknown_resellers: set[str] = set()

    for r in records:
        label = f"{r['kind']} {r['id']} ({r['serial']})"
        try:
            if r["kind"] == "mobile" and not r["patch_key"]:
                report.counts["unsupported"] += 1
                continue
            device = abm_devices.get(r["serial"])
            if device:
                if r["serial"] not in coverage_cache:
                    coverage_cache[r["serial"]] = axm.coverage(device["id"])
                desired = desired_from_abm(device, coverage_cache[r["serial"]], cfg.vendor_map)
                report.counts["matched_abm"] += 1
                uid = str(device.get("purchaseSourceUid") or "")
                if device.get("purchaseSourceType") == "RESELLER" and uid not in cfg.vendor_map \
                        and uid not in unknown_resellers:
                    unknown_resellers.add(uid)
                    log(f"note: reseller {uid} is not in vendor-map, so the sync does not set Vendor "
                        f"(first seen on {r['serial']}).")
                # ABM has no coverage date for some devices, for example devices added with Apple Configurator.
                if "warrantyDate" not in desired and r["kind"] == "computer" and cfg.warranty_ea_name:
                    desired.update(desired_from_ea(r["raw"], cfg.warranty_ea_name))
            elif r["kind"] == "computer" and cfg.warranty_ea_name:
                desired = desired_from_ea(r["raw"], cfg.warranty_ea_name)
                if not desired:
                    report.counts["no_data"] += 1
                    continue
                report.counts["matched_ea"] += 1
            else:
                report.counts["no_data"] += 1
                continue

            changes = plan_changes(desired, r["purchasing"], r["kind"], cfg.fields)
            if not changes:
                report.counts["unchanged"] += 1
                continue
            report.counts["changed"] += 1
            report.changes.append((r["serial"], r["kind"], r["id"], changes))
            log(f"{'plan' if cfg.dry_run else 'update'} {label}: {json.dumps(changes, sort_keys=True)}")
            if not cfg.dry_run:
                if r["kind"] == "computer":
                    jamf.update_computer(r["id"], changes)
                else:
                    jamf.update_mobile_device(r["id"], r["patch_key"], changes)
        except HttpError as err:
            report.counts["errors"] += 1
            report.errors.append(f"{label}: {err}")
            log(f"error: {label}: {err}")
    return report


def write_github_outputs(report: Report, dry_run: bool) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as out:
            for key, value in report.counts.items():
                out.write(f"{key.replace('_', '-')}={value}\n")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = [f"## ABM to Jamf sync ({'dry run' if dry_run else 'write'})", "", "| Result | Count |", "|---|---|"]
    lines += [f"| {key.replace('_', ' ')} | {value} |" for key, value in report.counts.items()]
    if report.changes:
        verb = "Planned" if dry_run else "Applied"
        lines += ["", f"### {verb} changes", "", "| Serial | Type | Jamf ID | Fields |", "|---|---|---|---|"]
        for serial, kind, device_id, changes in report.changes[:500]:
            fields = ", ".join(f"`{k}` = {v}" for k, v in sorted(changes.items()))
            lines.append(f"| {serial} | {kind} | {device_id} | {fields} |")
        if len(report.changes) > 500:
            lines.append(f"\n{len(report.changes) - 500} more changes are in the job log.")
    if report.errors:
        lines += ["", "### Errors", ""] + [f"- {e}" for e in report.errors[:100]]
    with open(summary_path, "a", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")


def main() -> int:
    cfg = config_from_env(dict(os.environ))
    mask(cfg.jamf_client_secret)
    jamf = JamfClient(cfg.jamf_url, cfg.jamf_client_id, cfg.jamf_client_secret)
    axm = AxmClient(cfg.axm_client_id, cfg.axm_key_id, cfg.axm_private_key, cfg.axm_scope)
    mode = "dry run: no changes are written" if cfg.dry_run else "write mode"
    print(f"Sync from Apple {cfg.axm_scope.title()} Manager to {cfg.jamf_url} ({mode})", flush=True)
    try:
        report = run(cfg, jamf, axm)
    except HttpError as err:
        print(f"::error::Sync stopped: {err}", flush=True)
        return 1
    print("Result: " + ", ".join(f"{k}={v}" for k, v in report.counts.items()), flush=True)
    write_github_outputs(report, cfg.dry_run)
    if report.errors and cfg.fail_on_error:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
