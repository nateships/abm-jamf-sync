import copy
import json
import sys
import urllib.parse
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import abm_jamf_sync as sync  # noqa: E402

JAMF = "https://example.jamfcloud.com"
ABM = "https://api-business.apple.com"

# Coverage example from the Apple Business API documentation.
DOC_COVERAGE = [
    {"isCanceled": False, "description": "Limited Warranty", "agreementNumber": None,
     "startDateTime": "2025-02-02T00:00:00Z", "endDateTime": "2026-02-02T00:00:00Z", "status": "ACTIVE"},
    {"isCanceled": False, "description": "AppleCare+", "agreementNumber": "0000000001",
     "startDateTime": "2025-04-17T00:00:00Z", "endDateTime": "2026-04-17T00:00:00Z", "status": "ACTIVE"},
    {"isCanceled": False, "description": "AppleCare+ for Business", "agreementNumber": None,
     "startDateTime": "2025-04-17T00:00:00Z", "endDateTime": None, "status": "ACTIVE"},
]


def make_key():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return key, pem


# --------------------------------------------------------------------------
# Pure functions
# --------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("2026-04-17T00:00:00Z", "2026-04-17"),
    ("2026-04-17T23:30:00-05:00", "2026-04-18"),
    ("2026-04-17", "2026-04-17"),
    ("2029-05-23 23:59:59", "2029-05-23"),
    ("", None),
    (None, None),
    ("not a date", None),
])
def test_to_date(value, expected):
    assert sync.to_date(value) == expected


def test_pick_warranty_end_uses_latest_non_null_end():
    assert sync.pick_warranty_end(DOC_COVERAGE) == "2026-04-17"


def test_pick_warranty_end_ignores_canceled():
    coverages = copy.deepcopy(DOC_COVERAGE)
    coverages[1]["isCanceled"] = True
    assert sync.pick_warranty_end(coverages) == "2026-02-02"


def test_pick_agreement():
    assert sync.pick_agreement(DOC_COVERAGE) == "0000000001"
    assert sync.pick_agreement(DOC_COVERAGE[:1]) is None


def test_vendor_name():
    vendor_map = {"-2085650007946880": "Example Reseller"}
    assert sync.vendor_name({"purchaseSourceType": "APPLE"}, vendor_map) == "Apple"
    assert sync.vendor_name({"purchaseSourceType": "RESELLER", "purchaseSourceUid": "-2085650007946880"},
                            vendor_map) == "Example Reseller"
    assert sync.vendor_name({"purchaseSourceType": "RESELLER", "purchaseSourceUid": "999"}, vendor_map) is None
    assert sync.vendor_name({"purchaseSourceType": "MANUALLY_ADDED"}, vendor_map) is None


def test_desired_from_abm_leaves_out_empty_values():
    device = {"purchaseSourceType": "MANUALLY_ADDED", "orderNumber": None, "orderDateTime": None}
    assert sync.desired_from_abm(device, [], {}) == {}


def test_plan_changes_never_clears_a_field():
    purchasing = {"poNumber": "PO-1", "vendor": "Someone", "warrantyDate": "2027-01-01"}
    assert sync.plan_changes({}, purchasing, "computer", list(sync.FIELD_NAMES)) == {}


def test_plan_changes_only_touches_managed_fields():
    desired = {"poNumber": "123", "warrantyDate": "2026-04-17"}
    assert sync.plan_changes(desired, {}, "computer", ["warrantyDate"]) == {"warrantyDate": "2026-04-17"}


def test_plan_changes_mobile_uses_date_time_and_compares_dates_only():
    desired = {"warrantyDate": "2026-04-17", "poDate": "2011-08-15"}
    changes = sync.plan_changes(desired, {}, "mobile", ["warrantyDate", "poDate"])
    assert changes == {"warrantyExpiresDate": "2026-04-17T12:00:00Z", "poDate": "2011-08-15T12:00:00Z"}
    stored = {"warrantyExpiresDate": "2026-04-17T12:00:00.000Z", "poDate": "2011-08-15T12:00:00Z"}
    assert sync.plan_changes(desired, stored, "mobile", ["warrantyDate", "poDate"]) == {}


def test_desired_from_ea():
    computer = {"extensionAttributes": [{"name": "AppleCare Expiration", "values": ["2029-05-23 23:59:59"]}]}
    assert sync.desired_from_ea(computer, "AppleCare Expiration") == {"warrantyDate": "2029-05-23"}
    assert sync.desired_from_ea(computer, "Other") == {}
    empty = {"extensionAttributes": [{"name": "AppleCare Expiration", "values": [""]}]}
    assert sync.desired_from_ea(empty, "AppleCare Expiration") == {}


def test_desired_from_ea_finds_attribute_in_any_section():
    computer = {"extensionAttributes": [],
                "purchasing": {"extensionAttributes": [{"name": "AppleCare Expiration", "values": ["2029-05-23"]}]}}
    assert sync.desired_from_ea(computer, "AppleCare Expiration") == {"warrantyDate": "2029-05-23"}


def base_env(**extra):
    env = {"JAMF_URL": JAMF, "JAMF_CLIENT_ID": "id", "JAMF_CLIENT_SECRET": "secret",
           "AXM_CLIENT_ID": "BUSINESSAPI.x", "AXM_KEY_ID": "kid", "AXM_PRIVATE_KEY": "pem"}
    env.update(extra)
    return env


def test_config_defaults():
    cfg = sync.config_from_env(base_env())
    assert cfg.dry_run is True
    assert cfg.fields == ["poNumber", "poDate", "vendor", "warrantyDate", "appleCareId"]
    assert cfg.device_types == ["computers"]


@pytest.mark.parametrize("extra", [
    {"FIELDS": "warrantyDate,price"},
    {"DEVICE_TYPES": "computers,tv"},
    {"AXM_SCOPE": "enterprise"},
    {"VENDOR_MAP": "[1]"},
    {"VENDOR_MAP": "{bad"},
    {"JAMF_URL": ""},
])
def test_config_rejects_bad_input(extra):
    with pytest.raises(SystemExit):
        sync.config_from_env(base_env(**extra))


def test_config_parses_lists_and_flags():
    cfg = sync.config_from_env(base_env(DRY_RUN="false", SERIALS="abc123\n def456 ", FIELDS="warrantyDate"))
    assert cfg.dry_run is False
    assert cfg.serials == {"ABC123", "DEF456"}
    assert cfg.fields == ["warrantyDate"]


# --------------------------------------------------------------------------
# Full run against fake Jamf and ABM servers
# --------------------------------------------------------------------------


class FakeServers:
    def __init__(self, public_key):
        self.public_key = public_key
        self.calls = []
        self.patches = []
        self.computers = [
            {"id": "1", "hardware": {"serialNumber": "C02ABM00001"},
             "purchasing": {"purchasePrice": "1999", "leaseDate": None}, "extensionAttributes": []},
            {"id": "2", "hardware": {"serialNumber": "c02abm00002 "}, "purchasing": {}, "extensionAttributes": []},
            {"id": "3", "hardware": {"serialNumber": "C02NOTABM03"}, "purchasing": {},
             "extensionAttributes": [{"name": "AppleCare Expiration", "values": ["2029-05-23 23:59:59"]}]},
            {"id": "4", "hardware": {"serialNumber": "C02NOTABM04"}, "purchasing": {}, "extensionAttributes": []},
        ]
        self.mobiles = [
            {"mobileDeviceId": "10", "deviceType": "iOS", "hardware": {"serialNumber": "IPADABM0010"},
             "purchasing": {"purchasePrice": "799"}},
            {"mobileDeviceId": "11", "deviceType": "watchOS", "hardware": {"serialNumber": "WATCHABM011"},
             "purchasing": {}},
        ]
        self.abm = {
            "C02ABM00001": {"orderNumber": "1234567890", "orderDateTime": "2025-01-15T07:00:00Z",
                            "purchaseSourceType": "APPLE", "purchaseSourceUid": "1"},
            "C02ABM00002": {"orderNumber": "2234567890", "orderDateTime": "2025-02-15T07:00:00Z",
                            "purchaseSourceType": "RESELLER", "purchaseSourceUid": "-2085650007946880"},
            "IPADABM0010": {"orderNumber": "3234567890", "orderDateTime": "2025-03-15T07:00:00Z",
                            "purchaseSourceType": "APPLE", "purchaseSourceUid": "1"},
            "WATCHABM011": {"orderNumber": "4234567890", "orderDateTime": "2025-03-15T07:00:00Z",
                            "purchaseSourceType": "APPLE", "purchaseSourceUid": "1"},
        }
        self.coverage = {"C02ABM00001": DOC_COVERAGE, "IPADABM0010": DOC_COVERAGE[:1]}
        self.jamf_tokens = 0
        self.fail_next_jamf_auth = False
        self.rate_limit_next_abm = False

    def __call__(self, method, url, headers, body):
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        self.calls.append((method, url))
        auth = (headers or {}).get("Authorization", "")

        if url.startswith(JAMF):
            if path == "/api/oauth/token":
                self.jamf_tokens += 1
                return 200, {}, json.dumps({"access_token": f"jamf-{self.jamf_tokens}", "expires_in": 60}).encode()
            if self.fail_next_jamf_auth:
                self.fail_next_jamf_auth = False
                return 401, {}, b""
            assert auth.startswith("Bearer jamf-")
            if method == "GET" and path == "/api/v4/computers-inventory":
                assert "HARDWARE" in query["section"] and "PURCHASING" in query["section"]
                return 200, {}, self.page(self.computers, query)
            if method == "GET" and path == "/api/v2/mobile-devices/detail":
                return 200, {}, self.page(self.mobiles, query)
            if method == "PATCH" and path.startswith("/api/v4/computers-inventory-detail/"):
                payload = json.loads(body)
                self.patches.append(("computer", path.rsplit("/", 1)[1], payload))
                record = next(c for c in self.computers if c["id"] == path.rsplit("/", 1)[1])
                record["purchasing"].update(payload["purchasing"])
                return 200, {}, b"{}"
            if method == "PATCH" and path.startswith("/api/v2/mobile-devices/"):
                payload = json.loads(body)
                self.patches.append(("mobile", path.rsplit("/", 1)[1], payload))
                record = next(m for m in self.mobiles if m["mobileDeviceId"] == path.rsplit("/", 1)[1])
                record["purchasing"].update(payload["ios"]["purchasing"])
                return 200, {}, b"{}"

        if url.startswith("https://account.apple.com/auth/oauth2/token"):
            assert query["grant_type"] == ["client_credentials"]
            assert query["scope"] == ["business.api"]
            assert query["client_assertion_type"] == ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
            assertion = query["client_assertion"][0]
            assert jwt.get_unverified_header(assertion)["kid"] == "key-id"
            claims = jwt.decode(assertion, self.public_key, algorithms=["ES256"],
                                audience="https://account.apple.com/auth/oauth2/v2/token")
            assert claims["sub"] == claims["iss"] == "BUSINESSAPI.test"
            assert claims["exp"] - claims["iat"] <= 86400 * 180
            return 200, {}, json.dumps({"access_token": "abm-token", "expires_in": 3600}).encode()

        if url.startswith(ABM):
            assert auth == "Bearer abm-token"
            if self.rate_limit_next_abm:
                self.rate_limit_next_abm = False
                return 429, {"Retry-After": "7"}, b""
            if path == "/v1/orgDevices":
                serials = sorted(self.abm)
                start = int(query.get("cursor", ["0"])[0])
                chunk = serials[start:start + 2]
                data = [{"type": "orgDevices", "id": s, "attributes": {"serialNumber": s, **self.abm[s]}}
                        for s in chunk]
                links = {"self": url}
                if start + 2 < len(serials):
                    links["next"] = f"{ABM}/v1/orgDevices?cursor={start + 2}"
                return 200, {}, json.dumps({"data": data, "links": links}).encode()
            if path.endswith("/appleCareCoverage"):
                serial = path.split("/")[3]
                if serial not in self.coverage:
                    return 404, {}, b'{"errors":[]}'
                data = [{"type": "appleCareCoverage", "id": str(i), "attributes": a}
                        for i, a in enumerate(self.coverage[serial])]
                return 200, {}, json.dumps({"data": data}).encode()

        raise AssertionError(f"unexpected request {method} {url}")

    @staticmethod
    def page(items, query):
        size = 2
        page = int(query["page"][0])
        return json.dumps({"totalCount": len(items), "results": items[page * size:(page + 1) * size]}).encode()


@pytest.fixture
def servers(monkeypatch):
    key, pem = make_key()
    fake = FakeServers(key.public_key())
    sleeps = []
    monkeypatch.setattr(sync, "send", fake)
    monkeypatch.setattr(sync, "sleep", sleeps.append)
    monkeypatch.setattr(sync.JamfClient, "PAGE_SIZE", 2)
    fake.sleeps = sleeps
    fake.pem = pem
    return fake


def make_run(fake, **overrides):
    cfg = sync.Config(
        jamf_url=JAMF + "/", jamf_client_id="id", jamf_client_secret="secret",
        axm_client_id="BUSINESSAPI.test", axm_key_id="key-id", axm_private_key=fake.pem,
        vendor_map={"-2085650007946880": "Example Reseller"},
        warranty_ea_name="AppleCare Expiration",
        device_types=["computers", "mobile"],
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    jamf = sync.JamfClient(cfg.jamf_url, cfg.jamf_client_id, cfg.jamf_client_secret)
    axm = sync.AxmClient(cfg.axm_client_id, cfg.axm_key_id, cfg.axm_private_key, cfg.axm_scope)
    logs = []
    return sync.run(cfg, jamf, axm, log=logs.append), logs


def test_dry_run_plans_but_does_not_write(servers):
    report, _ = make_run(servers)
    assert servers.patches == []
    assert report.counts == {"jamf_devices": 6, "matched_abm": 3, "matched_ea": 1, "no_data": 1,
                             "unsupported": 1, "unchanged": 0, "changed": 4, "errors": 0}
    planned = {(kind, device_id): changes for _, kind, device_id, changes in report.changes}
    assert planned[("computer", "1")] == {"poNumber": "1234567890", "poDate": "2025-01-15", "vendor": "Apple",
                                          "warrantyDate": "2026-04-17", "appleCareId": "0000000001"}
    assert planned[("computer", "2")] == {"poNumber": "2234567890", "poDate": "2025-02-15",
                                          "vendor": "Example Reseller"}
    assert planned[("computer", "3")] == {"warrantyDate": "2029-05-23"}
    assert planned[("mobile", "10")] == {"poNumber": "3234567890", "poDate": "2025-03-15T12:00:00Z",
                                         "vendor": "Apple", "warrantyExpiresDate": "2026-02-02T12:00:00Z"}


def test_write_sends_patches_and_second_run_is_idempotent(servers):
    report, _ = make_run(servers, dry_run=False)
    assert report.counts["changed"] == 4
    assert {(kind, device_id) for kind, device_id, _ in servers.patches} == {
        ("computer", "1"), ("computer", "2"), ("computer", "3"), ("mobile", "10")}
    mobile_body = next(p for kind, _, p in servers.patches if kind == "mobile")
    assert set(mobile_body) == {"ios"}
    # Fields that the sync does not manage stay as they were.
    assert servers.computers[0]["purchasing"]["purchasePrice"] == "1999"
    assert servers.mobiles[0]["purchasing"]["purchasePrice"] == "799"

    servers.patches.clear()
    report, _ = make_run(servers, dry_run=False)
    assert servers.patches == []
    assert report.counts["changed"] == 0
    assert report.counts["unchanged"] == 4


def test_coverage_is_only_fetched_for_devices_in_jamf(servers):
    make_run(servers, device_types=["computers"])
    coverage_calls = [u for _, u in servers.calls if u.endswith("/appleCareCoverage")]
    assert sorted(coverage_calls) == [f"{ABM}/v1/orgDevices/C02ABM00001/appleCareCoverage",
                                      f"{ABM}/v1/orgDevices/C02ABM00002/appleCareCoverage"]


def test_serials_filter(servers):
    report, _ = make_run(servers, serials={"C02ABM00002"})
    assert report.counts["jamf_devices"] == 1
    assert [device_id for _, _, device_id, _ in report.changes] == ["2"]


def test_jamf_401_refreshes_token_once(servers):
    servers.fail_next_jamf_auth = True
    report, _ = make_run(servers)
    assert report.counts["errors"] == 0
    assert servers.jamf_tokens == 2


def test_abm_429_obeys_retry_after(servers):
    servers.rate_limit_next_abm = True
    report, _ = make_run(servers)
    assert report.counts["errors"] == 0
    assert servers.sleeps == [7.0]


def test_duplicate_serials_are_logged(servers):
    servers.computers.append({"id": "5", "hardware": {"serialNumber": "C02ABM00001"}, "purchasing": {},
                              "extensionAttributes": []})
    report, logs = make_run(servers)
    assert any("C02ABM00001 is on 2 Jamf records" in line for line in logs)
    assert ("computer", "5") in {(kind, device_id) for _, kind, device_id, _ in report.changes}


def test_patch_error_is_counted_and_run_continues(servers, monkeypatch):
    original = servers.__call__

    def failing(method, url, headers, body):
        if method == "PATCH" and url.endswith("/computers-inventory-detail/1"):
            return 400, {}, b'{"httpStatus":400,"errors":[{"code":"INVALID_FIELD"}]}'
        return original(method, url, headers, body)

    monkeypatch.setattr(sync, "send", failing)
    report, _ = make_run(servers, dry_run=False)
    assert report.counts["errors"] == 1
    assert report.counts["changed"] == 4
    assert "computer 1 (C02ABM00001)" in report.errors[0]


def test_github_outputs(servers, tmp_path, monkeypatch):
    out, summary = tmp_path / "out", tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    report, _ = make_run(servers)
    sync.write_github_outputs(report, dry_run=True)
    assert "changed=4" in out.read_text()
    assert "jamf-devices=6" in out.read_text()
    assert "Planned changes" in summary.read_text()


def test_ea_fills_warranty_for_abm_device_without_coverage(servers):
    servers.computers[1]["purchasing"]["extensionAttributes"] = [
        {"name": "AppleCare Expiration", "values": ["2028-01-31 10:00:00"]}]
    report, _ = make_run(servers, device_types=["computers"])
    planned = {device_id: changes for _, _, device_id, changes in report.changes}
    assert planned["2"]["warrantyDate"] == "2028-01-31"
    assert planned["2"]["poNumber"] == "2234567890"


def test_ea_does_not_replace_abm_coverage(servers):
    servers.computers[0]["extensionAttributes"] = [{"name": "AppleCare Expiration", "values": ["2030-01-01"]}]
    report, _ = make_run(servers, device_types=["computers"])
    planned = {device_id: changes for _, _, device_id, changes in report.changes}
    assert planned["1"]["warrantyDate"] == "2026-04-17"


def test_unknown_reseller_is_logged_once(servers):
    servers.abm["C02ABM00001"].update(purchaseSourceType="RESELLER", purchaseSourceUid="777")
    servers.abm["IPADABM0010"].update(purchaseSourceType="RESELLER", purchaseSourceUid="777")
    report, logs = make_run(servers)
    notes = [line for line in logs if "reseller 777 is not in vendor-map" in line]
    assert len(notes) == 1
    planned = {device_id: changes for _, _, device_id, changes in report.changes}
    assert "vendor" not in planned["1"]


def test_network_error_is_retried(servers, monkeypatch):
    original = servers.__call__
    failed = []

    def flaky(method, url, headers, body):
        if url.endswith("/appleCareCoverage") and not failed:
            failed.append(url)
            return 599, {}, b"network down"
        return original(method, url, headers, body)

    monkeypatch.setattr(sync, "send", flaky)
    report, _ = make_run(servers)
    assert failed
    assert report.counts["errors"] == 0
    assert servers.sleeps == [1]


def test_http_request_maps_network_errors_to_599(monkeypatch):
    def boom(*args, **kwargs):
        raise sync.urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(sync.urllib.request, "urlopen", boom)
    status, _, body = sync.http_request("GET", "https://example.invalid/")
    assert status == 599
    assert b"name resolution failed" in body
