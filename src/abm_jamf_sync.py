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
# Display names for the log and the step summary, in Jamf field name order.
FIELD_LABELS = {
    "purchased": "Purchased", "poNumber": "PO Number", "poDate": "PO Date", "vendor": "Vendor",
    "warrantyDate": "Warranty Expiration", "appleCareId": "AppleCare ID",
}
JAMF_LABELS = {jamf: FIELD_LABELS[logical] for logical, names in FIELD_NAMES.items() for jamf in names}
JAMF_LOGICAL = {jamf: logical for logical, names in FIELD_NAMES.items() for jamf in names}
JAMF_DATE_FIELDS = {jamf for logical in DATE_FIELDS for jamf in FIELD_NAMES[logical]}
COUNT_LABELS = {
    "jamf_devices": "Jamf devices", "matched_abm": "Found in ABM", "matched_ea": "From extension attribute",
    "no_data": "No data", "unsupported": "Unsupported", "unchanged": "Already correct",
    "changed": "Changed", "errors": "Errors",
}
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


def annotation(level: str, title: str, message: str) -> str:
    """Return a workflow command that shows the message on the run page (level: warning or error)."""
    data = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::{level} title={title}::{data}"


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


def pick_warranty_start(coverages: list[dict]) -> str | None:
    """Return the earliest start date of the coverages.

    The Limited Warranty starts on the purchase date. Other coverage starts on or after it.
    """
    starts = [to_date(c.get("startDateTime")) for c in coverages]
    starts = [s for s in starts if s]
    return min(starts) if starts else None


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
        return vendor_map.get(str(device.get("purchaseSourceId") or ""))
    return None


def purchase_source(device: dict) -> str:
    """Return where ABM got the device, as text for people."""
    source = device.get("purchaseSourceType")
    if source == "APPLE":
        return "Apple"
    if source == "RESELLER":
        return f"Reseller {device.get('purchaseSourceId') or '(unknown)'}"
    if source == "MANUALLY_ADDED":
        added = to_date(device.get("addedToOrgDateTime"))
        return f"Apple Configurator, added {added}" if added else "Apple Configurator"
    return str(source or "(unknown)")


def desired_from_abm(device: dict, coverages: list[dict], vendor_map: dict[str, str]) -> dict[str, Any]:
    """Return the logical field values that ABM supplies for a device. Leave out empty values."""
    # For a device added with Apple Configurator, orderDateTime is the date it was added, which can be
    # years after the purchase. The warranty start date is closer to the purchase date.
    if device.get("purchaseSourceType") == "MANUALLY_ADDED":
        po_date = pick_warranty_start(coverages)
    else:
        po_date = to_date(device.get("orderDateTime"))
    values = {
        "purchased": True if device.get("purchaseSourceType") in ("APPLE", "RESELLER") else None,
        "poNumber": device.get("orderNumber") or None,
        "poDate": po_date,
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
    # Serial, kind, Jamf ID, new values, and the Jamf values before the change.
    changes: list[tuple[str, str, str, dict, dict]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    no_data: list[str] = field(default_factory=list)
    # Where the data for each serial number came from, for example "Apple" or "Reseller 101C20E0".
    sources: dict[str, str] = field(default_factory=dict)


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
            note = f"Serial {serial} is on {count} Jamf records. Every record gets the same data."
            report.notes.append(note)
            log(annotation("warning", "Duplicate serial number", note))

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
                report.sources[r["serial"]] = purchase_source(device)
                report.counts["matched_abm"] += 1
                uid = str(device.get("purchaseSourceId") or "")
                if device.get("purchaseSourceType") == "RESELLER" and uid not in cfg.vendor_map \
                        and uid not in unknown_resellers:
                    unknown_resellers.add(uid)
                    note = (f"Vendor not set: reseller {uid} is not in vendor-map "
                            f"(first seen on {r['serial']}).")
                    report.notes.append(note)
                    log(annotation("warning", "Unknown reseller", note))
                # ABM has no coverage date for some devices, for example devices added with Apple Configurator.
                if "warrantyDate" not in desired and r["kind"] == "computer" and cfg.warranty_ea_name:
                    desired.update(desired_from_ea(r["raw"], cfg.warranty_ea_name))
            elif r["kind"] == "computer" and cfg.warranty_ea_name:
                desired = desired_from_ea(r["raw"], cfg.warranty_ea_name)
                if not desired:
                    report.counts["no_data"] += 1
                    report.no_data.append(r["serial"])
                    continue
                report.sources[r["serial"]] = "Extension attribute"
                report.counts["matched_ea"] += 1
            else:
                report.counts["no_data"] += 1
                report.no_data.append(r["serial"])
                continue

            changes = plan_changes(desired, r["purchasing"], r["kind"], cfg.fields)
            if not changes:
                report.counts["unchanged"] += 1
                continue
            report.counts["changed"] += 1
            before = {name: r["purchasing"].get(name) for name in changes}
            report.changes.append((r["serial"], r["kind"], r["id"], changes, before))
            log(format_change("Plan" if cfg.dry_run else "Update", label, changes, before,
                              report.sources.get(r["serial"], "")))
            if not cfg.dry_run:
                if r["kind"] == "computer":
                    jamf.update_computer(r["id"], changes)
                else:
                    jamf.update_mobile_device(r["id"], r["patch_key"], changes)
        except HttpError as err:
            report.counts["errors"] += 1
            report.errors.append(f"{label}: {err}")
            log(annotation("error", "Update failed", f"{label}: {err}"))
    return report


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def show(jamf_name: str, value: Any) -> str:
    """Return a Jamf field value as text for people."""
    if value is None or value == "":
        return "(empty)"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if jamf_name in JAMF_DATE_FIELDS:
        return to_date(value) or str(value)
    return str(value)


def ordered(changes: dict) -> list[str]:
    """Return the changed Jamf field names in display order."""
    return [name for name in JAMF_LABELS if name in changes]


def format_change(verb: str, label: str, changes: dict, before: dict, source: str = "") -> str:
    """Return a log block that shows each changed field as before → after."""
    width = max(len(text) for text in FIELD_LABELS.values())
    lines = [f"{verb} {label}" + (f" from {source}" if source else "")]
    for name in ordered(changes):
        lines.append(f"    {JAMF_LABELS[name]:<{width}}  {show(name, before.get(name))} → {show(name, changes[name])}")
    return "\n".join(lines)


def format_counts(report: Report, dry_run: bool) -> str:
    """Return the result counts as an aligned table for the log."""
    labels = dict(COUNT_LABELS, changed="Changes planned" if dry_run else "Changed")
    width = max(len(text) for text in labels.values())
    return "\n".join(["Result"] + [f"    {labels[key]:<{width}}  {value}" for key, value in report.counts.items()])


def cell(text: str) -> str:
    """Escape text for a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def device_link(jamf_url: str, kind: str, device_id: str) -> str:
    page = "computers.html" if kind == "computer" else "mobileDevices.html"
    text = f"{kind} {device_id}"
    return f"[{text}]({jamf_url.rstrip('/')}/{page}?id={device_id}&o=r)" if jamf_url else text


def summary_markdown(report: Report, dry_run: bool, jamf_url: str = "") -> str:
    """Return the step summary: the mode, the counts, the changes, and the notes."""
    lines = ["## ABM to Jamf purchasing sync", ""]
    if dry_run:
        lines += ["> [!NOTE]", "> **Dry run.** Nothing was written to Jamf Pro. These are the planned changes."]
    else:
        lines += ["> [!IMPORTANT]", "> **Write mode.** The changes below were written to Jamf Pro."]

    labels = dict(COUNT_LABELS, changed="Changes planned" if dry_run else "Changed")
    lines += ["", "| " + " | ".join(labels[key] for key in report.counts) + " |",
              "|" + "---:|" * len(report.counts),
              "| " + " | ".join(str(value) for value in report.counts.values()) + " |"]

    if report.changes:
        # One column for each logical field. Computers and mobile devices can use different Jamf names.
        columns = [logical for logical in FIELD_NAMES
                   if any(JAMF_LOGICAL[name] == logical for c in report.changes for name in c[3])]
        title = "Planned changes" if dry_run else "Changes written"
        lines += ["", f"### {title} ({len(report.changes)})", "",
                  "| Serial | Jamf device | Source | "
                  + " | ".join(FIELD_LABELS[logical] for logical in columns) + " |",
                  "|---|---|---|" + "---|" * len(columns)]
        for serial, kind, device_id, changes, before in report.changes[:500]:
            names = {JAMF_LOGICAL[name]: name for name in changes}
            values = []
            for logical in columns:
                name = names.get(logical)
                if name is None:
                    values.append("")
                elif before.get(name) in (None, ""):
                    values.append(f"**{cell(show(name, changes[name]))}**")
                else:
                    values.append(f"{cell(show(name, before[name]))} → **{cell(show(name, changes[name]))}**")
            source = cell(report.sources.get(serial, ""))
            lines.append(f"| `{serial}` | {device_link(jamf_url, kind, device_id)} | {source} | "
                         + " | ".join(values) + " |")
        if len(report.changes) > 500:
            lines += ["", f"{len(report.changes) - 500} more changes are in the job log."]
        lines += ["", "Bold is the new value. A blank cell is a field that does not change. "
                  "For a device added with Apple Configurator, PO Date is the warranty start date."]

    if report.errors:
        lines += ["", "### Errors", "", "> [!CAUTION]"] + [f"> - {cell(e)}" for e in report.errors[:100]]
    if report.notes:
        lines += ["", "### Notes", "", "> [!WARNING]"] + [f"> - {cell(n)}" for n in report.notes]
    if report.no_data:
        lines += ["", f"<details><summary>No data from ABM or the extension attribute "
                  f"({len(report.no_data)})</summary>", ""]
        lines += [f"- `{serial}`" for serial in report.no_data[:500]]
        lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


def write_github_outputs(report: Report, dry_run: bool, jamf_url: str = "") -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as out:
            for key, value in report.counts.items():
                out.write(f"{key.replace('_', '-')}={value}\n")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as out:
            out.write(summary_markdown(report, dry_run, jamf_url))


def main() -> int:
    cfg = config_from_env(dict(os.environ))
    mask(cfg.jamf_client_secret)
    jamf = JamfClient(cfg.jamf_url, cfg.jamf_client_id, cfg.jamf_client_secret)
    axm = AxmClient(cfg.axm_client_id, cfg.axm_key_id, cfg.axm_private_key, cfg.axm_scope)
    mode = "Dry run (no changes are written)" if cfg.dry_run else "Write"
    print("\n".join([
        "ABM to Jamf purchasing sync",
        f"    Source  Apple {cfg.axm_scope.title()} Manager",
        f"    Target  {cfg.jamf_url}",
        f"    Mode    {mode}",
        "",
    ]), flush=True)
    try:
        report = run(cfg, jamf, axm, log=lambda line: print(line, flush=True))
    except HttpError as err:
        print(annotation("error", "Sync stopped", str(err)), flush=True)
        return 1
    print("\n" + format_counts(report, cfg.dry_run), flush=True)
    write_github_outputs(report, cfg.dry_run, cfg.jamf_url)
    if report.errors and cfg.fail_on_error:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
