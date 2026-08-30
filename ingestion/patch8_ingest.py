"""Bounded Patch8 P4 ingestion primitives.

This module deliberately uses only the Python standard library. It implements
the P4 source core: source-policy sealing, bounded HTTP JSON retrieval,
restartable NVD normalization, and complete KEV snapshot reconciliation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "docs" / "licensing" / "source-policy.json"
CONTRACT_PATH = ROOT / "contracts" / "data-content-v1.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPECTED_POLICY_SHA256 = "7d102f731dc81cb55a4845375f7be2249a36a2ea4f55d63a0f36d99419bac926"
EXPECTED_CONTRACT_SHA256 = "fa29dcb956c0fb01e55b4926b3762685c4d1784aeedb91a6a82ccab216b37f19"
CVE_RE = re.compile(r"^CVE-(1999|2\d{3})-[1-9]\d{3,}$")
CWE_RE = re.compile(r"^CWE-[1-9]\d*$")
HEX_40_RE = re.compile(r"^[0-9a-f]{40}$")


class IngestionError(RuntimeError):
    """Base class for expected fail-closed ingestion failures."""


class ContractTransitionRequired(IngestionError):
    """Raised where the reviewed P3 contract cannot represent an upstream value."""


class SchemaDrift(IngestionError):
    """Raised when a source response does not satisfy its reviewed shape."""


class BudgetExceeded(IngestionError):
    """Raised before a source can exceed an explicit request, byte, or page budget."""


class Throttled(IngestionError):
    """Raised when source throttling cannot be handled within the configured bound."""


class WatermarkError(IngestionError):
    """Raised for a non-contiguous or insufficiently overlapping delta window."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def digest(value: Any) -> str:
    return sha256(canonical_json(value)).hexdigest()


def parse_instant(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise SchemaDrift(f"{field} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SchemaDrift(f"{field} is not a valid ISO 8601 instant") from error
    if parsed.tzinfo is None:
        raise SchemaDrift(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def parse_nvd_instant(value: Any, field: str) -> datetime:
    """Parse NVD's documented UTC timestamps, which are emitted without an offset."""
    if not isinstance(value, str):
        raise SchemaDrift(f"{field} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SchemaDrift(f"{field} is not a valid ISO 8601 instant") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def instant_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("instant must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def require_keys(value: Any, *, field: str, required: set[str], allowed: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SchemaDrift(f"{field} must be an object")
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing:
        raise SchemaDrift(f"{field} is missing required fields: {', '.join(missing)}")
    if unknown:
        raise SchemaDrift(f"{field} contains unreviewed fields: {', '.join(unknown)}")
    return value


def require_text(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise SchemaDrift(f"{field} must be a non-empty string")
    return value


def require_cve(value: Any, field: str = "cveID") -> str:
    text = require_text(value, field)
    if not CVE_RE.fullmatch(text):
        raise SchemaDrift(f"{field} is not a valid CVE identifier")
    return text


@dataclass(frozen=True)
class PolicyGate:
    policy: Mapping[str, Any]
    contract: Mapping[str, Any]

    @classmethod
    def load(cls) -> "PolicyGate":
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        if digest(policy) != EXPECTED_POLICY_SHA256 or digest(contract) != EXPECTED_CONTRACT_SHA256:
            raise ContractTransitionRequired("P3 policy/content changed without a reviewed P4 baseline")
        if policy.get("policy_version") != "3.0.0" or contract.get("contract_version") != 3:
            raise ContractTransitionRequired("P4 supports only reviewed contract 3 and policy 3.0.0")
        return cls(policy=policy, contract=contract)

    def source(self, source_id: str) -> Mapping[str, Any]:
        matches = [item for item in self.policy["sources"] if item.get("id") == source_id]
        if len(matches) != 1:
            raise IngestionError(f"source {source_id} is not uniquely registered")
        source = matches[0]
        if source.get("decision") != "allow" or source.get("enabled") is not True:
            raise IngestionError(f"source {source_id} is not enabled")
        if self.policy["use_mode"] not in source.get("allowed_use_modes", []):
            raise IngestionError(f"source {source_id} does not allow {self.policy['use_mode']}")
        if source.get("raw_publication") is not False:
            raise IngestionError(f"source {source_id} does not prohibit raw publication")
        return source

    def authorize(self, source_id: str, fields: Iterable[str]) -> Mapping[str, Any]:
        source = self.source(source_id)
        patterns = source.get("allowed_fields", [])
        for field in fields:
            if not any(field == pattern or (pattern.endswith(".*") and field.startswith(pattern[:-1])) for pattern in patterns):
                raise IngestionError(f"{source_id} field {field} is not allowed by policy")
        return source



@dataclass(frozen=True)
class FetchLimits:
    max_requests: int = 100_000
    max_bytes: int = 2_000_000_000
    max_pages: int = 10_000
    timeout_seconds: float = 45.0
    minimum_interval_seconds: float = 6.0
    max_throttle_responses: int = 2
    max_retry_after_seconds: float = 60.0

    def __post_init__(self) -> None:
        if min(self.max_requests, self.max_bytes, self.max_pages) < 1:
            raise ValueError("request, byte, and page limits must be positive")
        if min(self.timeout_seconds, self.minimum_interval_seconds, self.max_retry_after_seconds) < 0:
            raise ValueError("time limits cannot be negative")


@dataclass(frozen=True)
class JsonResponse:
    body: bytes
    headers: Mapping[str, str]
    status: int = 200

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SchemaDrift("source returned malformed JSON") from error


class JsonTransport(Protocol):
    def get(
        self,
        url: str,
        headers: Mapping[str, str],
        *,
        timeout_seconds: float,
    ) -> JsonResponse: ...


class UrllibTransport:
    def get(
        self,
        url: str,
        headers: Mapping[str, str],
        *,
        timeout_seconds: float,
    ) -> JsonResponse:
        request = Request(url, headers=dict(headers), method="GET")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - exact URLs are gated
                return JsonResponse(
                    body=response.read(),
                    headers={key.lower(): value for key, value in response.headers.items()},
                    status=response.status,
                )
        except HTTPError as error:
            body = error.read()
            return JsonResponse(
                body=body,
                headers={key.lower(): value for key, value in error.headers.items()},
                status=error.code,
            )
        except URLError as error:
            raise IngestionError(f"source request failed: {error.reason}") from error


class BoundedJsonClient:
    def __init__(
        self,
        transport: JsonTransport,
        limits: FetchLimits,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.transport = transport
        self.limits = limits
        self.sleep = sleep
        self.monotonic = monotonic
        self.requests = 0
        self.bytes = 0
        self.throttles = 0
        self._last_request_at: float | None = None

    def get(self, url: str, *, expected_url: str, headers: Mapping[str, str] | None = None) -> JsonResponse:
        parsed = urlparse(url)
        expected = urlparse(expected_url)
        if parsed.scheme != "https" or (parsed.scheme, parsed.netloc, parsed.path) != (
            expected.scheme,
            expected.netloc,
            expected.path,
        ):
            raise IngestionError("request URL is outside the reviewed HTTPS source")
        while True:
            if self.requests >= self.limits.max_requests:
                raise BudgetExceeded("request budget exhausted")
            now = self.monotonic()
            if self._last_request_at is not None:
                delay = self.limits.minimum_interval_seconds - (now - self._last_request_at)
                if delay > 0:
                    self.sleep(delay)
            response = self.transport.get(
                url,
                headers or {},
                timeout_seconds=self.limits.timeout_seconds,
            )
            self._last_request_at = self.monotonic()
            self.requests += 1
            self.bytes += len(response.body)
            if self.bytes > self.limits.max_bytes:
                raise BudgetExceeded("response-byte budget exceeded")
            if response.status in {429, 503}:
                self.throttles += 1
                retry_after_text = response.headers.get("retry-after", "0")
                try:
                    retry_after = float(retry_after_text)
                except ValueError as error:
                    raise Throttled("source returned an invalid Retry-After header") from error
                if (
                    self.throttles > self.limits.max_throttle_responses
                    or retry_after < 0
                    or retry_after > self.limits.max_retry_after_seconds
                ):
                    raise Throttled("source throttling exceeded the configured retry bound")
                self.sleep(retry_after)
                continue
            if response.status != 200:
                raise IngestionError(f"source returned HTTP {response.status}")
            return response


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def load_checkpoint(path: Path) -> Mapping[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise IngestionError("checkpoint is unreadable or corrupt") from error
    return require_keys(
        value,
        field="checkpoint",
        required={"checkpoint_version", "operation_id", "next_start_index", "page_hashes", "complete"},
        allowed={
            "checkpoint_version",
            "operation_id",
            "next_start_index",
            "page_hashes",
            "complete",
            "total_results",
            "last_ordering_key",
            "response_bytes",
        },
    )


@dataclass(frozen=True)
class NvdOperation:
    mode: str
    results_per_page: int
    window_start: datetime | None = None
    window_end: datetime | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"full", "modified"}:
            raise ValueError("NVD mode must be full or modified")
        if not 1 <= self.results_per_page <= 2_000:
            raise ValueError("NVD results_per_page must be between 1 and 2000")
        if self.mode == "full" and (self.window_start is not None or self.window_end is not None):
            raise ValueError("full import cannot carry a modified window")
        if self.mode == "modified":
            if self.window_start is None or self.window_end is None:
                raise ValueError("modified import requires both window bounds")
            if self.window_end <= self.window_start:
                raise WatermarkError("modified window must end after it starts")
            if self.window_end - self.window_start > timedelta(days=120):
                raise WatermarkError("NVD modified windows cannot exceed 120 days")

    @property
    def operation_id(self) -> str:
        return digest(
            {
                "mode": self.mode,
                "results_per_page": self.results_per_page,
                "window_start": instant_text(self.window_start) if self.window_start else None,
                "window_end": instant_text(self.window_end) if self.window_end else None,
            }
        )

    def url(self, start_index: int) -> str:
        params: dict[str, str | int] = {
            "resultsPerPage": self.results_per_page,
            "startIndex": start_index,
        }
        if self.mode == "modified":
            assert self.window_start is not None and self.window_end is not None
            params["lastModStartDate"] = instant_text(self.window_start)
            params["lastModEndDate"] = instant_text(self.window_end)
        return f"{NVD_URL}?{urlencode(params)}"


def next_delta_operation(
    last_successful_watermark: datetime,
    window_end: datetime,
    *,
    overlap: timedelta = timedelta(hours=2),
    results_per_page: int = 2_000,
) -> NvdOperation:
    if overlap <= timedelta(0) or overlap > timedelta(days=1):
        raise WatermarkError("NVD overlap must be positive and no more than one day")
    if window_end <= last_successful_watermark:
        raise WatermarkError("delta end must advance the contiguous watermark")
    return NvdOperation(
        mode="modified",
        results_per_page=results_per_page,
        window_start=last_successful_watermark - overlap,
        window_end=window_end,
    )


def assert_contiguous_window(
    operation: NvdOperation,
    last_successful_watermark: datetime,
    *,
    overlap: timedelta = timedelta(hours=2),
) -> None:
    if operation.mode != "modified" or operation.window_start != last_successful_watermark - overlap:
        raise WatermarkError("delta window does not provide the exact reviewed overlap")
    if operation.window_end is None or operation.window_end <= last_successful_watermark:
        raise WatermarkError("delta window does not advance the contiguous watermark")


def validate_nvd_page(value: Any, *, expected_start: int, requested_page_size: int) -> Mapping[str, Any]:
    page = require_keys(
        value,
        field="NVD page",
        required={"resultsPerPage", "startIndex", "totalResults", "format", "version", "timestamp", "vulnerabilities"},
        allowed={"resultsPerPage", "startIndex", "totalResults", "format", "version", "timestamp", "vulnerabilities"},
    )
    if page["format"] != "NVD_CVE" or page["version"] != "2.0":
        raise SchemaDrift("NVD format/version changed")
    parse_nvd_instant(page["timestamp"], "NVD timestamp")
    for field in ("resultsPerPage", "startIndex", "totalResults"):
        if not isinstance(page[field], int) or isinstance(page[field], bool) or page[field] < 0:
            raise SchemaDrift(f"NVD {field} must be a non-negative integer")
    if page["startIndex"] != expected_start:
        raise SchemaDrift("NVD startIndex does not match the requested page")
    vulnerabilities = page["vulnerabilities"]
    if page["resultsPerPage"] == 0:
        if page["totalResults"] != 0 or vulnerabilities != []:
            raise SchemaDrift("NVD zero resultsPerPage is valid only for an empty result set")
    elif page["resultsPerPage"] > requested_page_size:
        raise SchemaDrift("NVD resultsPerPage is outside the requested bound")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > page["resultsPerPage"]:
        raise SchemaDrift("NVD vulnerabilities page is not a bounded array")
    if expected_start < page["totalResults"] and not vulnerabilities:
        raise SchemaDrift("NVD returned an empty page before totalResults")
    previous: datetime | None = None
    for index, wrapper in enumerate(vulnerabilities):
        item = require_keys(wrapper, field=f"NVD vulnerabilities[{index}]", required={"cve"}, allowed={"cve"})
        cve = item["cve"]
        if not isinstance(cve, dict):
            raise SchemaDrift(f"NVD vulnerabilities[{index}].cve must be an object")
        cve_id = require_cve(cve.get("id"), f"NVD vulnerabilities[{index}].cve.id")
        published = parse_nvd_instant(cve.get("published"), f"NVD {cve_id}.published")
        if previous is not None and published < previous:
            raise SchemaDrift("NVD page is not ordered by publish date")
        previous = published
    return page


class NvdPager:
    def __init__(self, client: BoundedJsonClient) -> None:
        self.client = client

    def run(
        self,
        operation: NvdOperation,
        checkpoint_path: Path,
        accept_page: Callable[[list[Mapping[str, Any]], int], None],
    ) -> Mapping[str, Any]:
        checkpoint = load_checkpoint(checkpoint_path)
        if checkpoint is not None and checkpoint["operation_id"] != operation.operation_id:
            raise IngestionError("checkpoint belongs to a different NVD operation")
        if checkpoint is not None and checkpoint["complete"] is True:
            return checkpoint
        start_index = int(checkpoint["next_start_index"]) if checkpoint else 0
        page_hashes = list(checkpoint["page_hashes"]) if checkpoint else []
        total_results = checkpoint.get("total_results") if checkpoint else None
        last_ordering_key = checkpoint.get("last_ordering_key") if checkpoint else None
        page_count = len(page_hashes)
        response_bytes = int(checkpoint.get("response_bytes", 0)) if checkpoint else 0
        while total_results is None or start_index < total_results:
            if page_count >= self.client.limits.max_pages:
                raise BudgetExceeded("NVD page budget exhausted")
            if response_bytes >= self.client.limits.max_bytes:
                raise BudgetExceeded("NVD operation response-byte budget exhausted")
            response = self.client.get(operation.url(start_index), expected_url=NVD_URL)
            if response_bytes + len(response.body) > self.client.limits.max_bytes:
                raise BudgetExceeded("NVD operation response-byte budget exceeded")
            page = validate_nvd_page(
                response.json(), expected_start=start_index, requested_page_size=operation.results_per_page
            )
            if total_results is not None and page["totalResults"] != total_results:
                raise SchemaDrift("NVD totalResults changed during one paginated operation")
            total_results = page["totalResults"]
            vulnerabilities = page["vulnerabilities"]
            first_cve = vulnerabilities[0]["cve"] if vulnerabilities else None
            first_key = [first_cve["published"], first_cve["id"]] if first_cve else None
            if last_ordering_key is not None and first_key is not None:
                previous_published = parse_nvd_instant(last_ordering_key[0], "checkpoint ordering")
                first_published = parse_nvd_instant(first_key[0], "NVD page ordering")
                if first_published < previous_published:
                    raise SchemaDrift("NVD ordering regressed across page boundaries")
            accept_page(vulnerabilities, start_index)
            next_start = start_index + len(vulnerabilities)
            page_hashes.append(sha256(response.body).hexdigest())
            response_bytes += len(response.body)
            complete = next_start >= total_results
            checkpoint = {
                "checkpoint_version": 1,
                "operation_id": operation.operation_id,
                "next_start_index": next_start,
                "total_results": total_results,
                "page_hashes": page_hashes,
                "complete": complete,
                "response_bytes": response_bytes,
            }
            if vulnerabilities:
                final_cve = vulnerabilities[-1]["cve"]
                checkpoint["last_ordering_key"] = [final_cve["published"], final_cve["id"]]
                last_ordering_key = checkpoint["last_ordering_key"]
            atomic_write_json(checkpoint_path, checkpoint)
            start_index = next_start
            page_count += 1
        assert checkpoint is not None
        return checkpoint


CVSS_KINDS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
CVSS_VERSION_ORDER = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
NVD_TABLES = (
    "cve_metadata_observations",
    "cvss_observations",
    "weakness_observations",
    "references",
    "configuration_node_observations",
    "affected_software",
)


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise SchemaDrift(f"{field} must be a boolean")
    return value


def _number(value: Any, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise SchemaDrift(f"{field} must be numeric")
    numeric = float(value)
    if not 0 <= numeric <= 10:
        raise SchemaDrift(f"{field} must be between zero and ten")
    return numeric


def _list(value: Any, field: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SchemaDrift(f"{field} must be an array")
    return value


def _stable_id(table: str, values: Mapping[str, Any]) -> str:
    return digest({"table": table, "values": values})


def _nvd_provenance(
    *,
    gate: PolicyGate,
    record_path: str,
    accepted_input: Mapping[str, Any],
    field_rules: list[str],
    published_at: str | None,
    modified_at: str | None,
    author: str | None = "NIST/NVD",
) -> dict[str, Any]:
    source = gate.authorize("patch8_nvd", field_rules)
    input_bytes = canonical_json(accepted_input)
    input_sha = sha256(input_bytes).hexdigest()
    provenance_values = {
        "source_id": "patch8_nvd",
        "source_record_path": record_path,
        "source_record_sha256": input_sha,
        "source_field_rules": sorted(field_rules),
        "author_or_provider": author,
        "transformation_kind": "normalized",
    }
    provenance_id = digest(provenance_values)
    return {
        "provenance_id": provenance_id,
        "source_id": "patch8_nvd",
        "source_display_name": source["display_name"],
        "source_policy_decision": "allow",
        "endpoint_or_repository": source["source_locator"],
        "source_record_path": record_path,
        "source_record_sha256": input_sha,
        "source_record_bytes": len(input_bytes),
        "source_published_at": published_at,
        "source_modified_at": modified_at,
        "parser_name": "patch8_ingest.nvd",
        "parser_version": "1",
        "transformation_version": "1",
        "table_schema_version": 1,
        "rights_policy_schema_version": gate.policy["schema_version"],
        "rights_policy_version": gate.policy["policy_version"],
        "source_field_rule": json.dumps(sorted(field_rules), separators=(",", ":")),
        "author_or_provider": author,
        "transformation_kind": "normalized",
        "modification_note": "Allowed structured fields normalized; descriptions and vendor comments excluded.",
        "required_notice_ids": list(source["required_notice_ids"]),
        "schema_version": 1,
    }


def _observation(
    table: str,
    values: Mapping[str, Any],
    provenance: Mapping[str, Any],
    gate: PolicyGate,
) -> dict[str, Any]:
    observation_id = _stable_id(table, values)
    return {
        "observation_id": observation_id,
        **values,
        "is_current": True,
        "provenance_id": provenance["provenance_id"],
        "rights_policy_version": gate.policy["policy_version"],
        "schema_version": 1,
    }


def _split_cpe23(uri: str) -> tuple[str, str, str]:
    if not uri.startswith("cpe:2.3:"):
        raise SchemaDrift("NVD criteria must be a CPE 2.3 URI")
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in uri:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        raise SchemaDrift("NVD CPE URI ends with an incomplete escape")
    parts.append("".join(current))
    if len(parts) != 13 or parts[0:2] != ["cpe", "2.3"]:
        raise SchemaDrift("NVD criteria must contain the complete CPE 2.3 component set")
    return tuple(unquote(part) for part in (parts[3], parts[4], parts[5]))


def _add_row(
    bundle: dict[str, Any],
    table: str,
    values: Mapping[str, Any],
    provenance: Mapping[str, Any],
    gate: PolicyGate,
) -> dict[str, Any]:
    row = _observation(table, values, provenance, gate)
    bundle[table].append(row)
    bundle["provenance"][provenance["provenance_id"]] = provenance
    return row


def normalize_nvd_vulnerabilities(
    vulnerabilities: list[Mapping[str, Any]],
    *,
    gate: PolicyGate | None = None,
) -> Mapping[str, Any]:
    gate = gate or PolicyGate.load()
    bundle: dict[str, Any] = {
        "format": "patch8-p4-nvd-core-v1",
        "cve_metadata_observations": [],
        "cvss_observations": [],
        "weakness_observations": [],
        "references": [],
        "configuration_node_observations": [],
        "affected_software": [],
        "provenance": {},
        "selected_cvss_observation_ids": {},
        "known_cve_ids": [],
    }
    seen_cves: set[str] = set()
    for record_index, wrapper in enumerate(vulnerabilities):
        wrapped = require_keys(
            wrapper,
            field=f"NVD vulnerabilities[{record_index}]",
            required={"cve"},
            allowed={"cve"},
        )
        cve = wrapped["cve"]
        if not isinstance(cve, dict):
            raise SchemaDrift(f"NVD vulnerabilities[{record_index}].cve must be an object")
        required_cve_fields = {"id", "sourceIdentifier", "published", "lastModified", "vulnStatus"}
        missing_cve_fields = sorted(required_cve_fields - cve.keys())
        if missing_cve_fields:
            raise SchemaDrift(
                f"NVD vulnerabilities[{record_index}].cve is missing required fields: {', '.join(missing_cve_fields)}"
            )
        cve_id = require_cve(cve["id"], f"NVD vulnerabilities[{record_index}].cve.id")
        if cve_id in seen_cves:
            raise SchemaDrift(f"NVD operation contains duplicate {cve_id}")
        seen_cves.add(cve_id)
        source_identifier = require_text(cve["sourceIdentifier"], f"NVD {cve_id}.sourceIdentifier")
        record_state = require_text(cve["vulnStatus"], f"NVD {cve_id}.vulnStatus")
        published_at = instant_text(parse_nvd_instant(cve["published"], f"NVD {cve_id}.published"))
        modified_at = instant_text(parse_nvd_instant(cve["lastModified"], f"NVD {cve_id}.lastModified"))
        if parse_instant(modified_at, "NVD modified") < parse_instant(published_at, "NVD published"):
            raise SchemaDrift(f"NVD {cve_id}.lastModified precedes published")
        metadata_input = {
            "id": cve_id,
            "sourceIdentifier": source_identifier,
            "published": published_at,
            "lastModified": modified_at,
            "vulnStatus": record_state,
        }
        metadata_rules = ["cve.id", "cve.sourceIdentifier", "cve.published", "cve.lastModified", "cve.vulnStatus"]
        metadata_provenance = _nvd_provenance(
            gate=gate,
            record_path=f"cves/{cve_id}/metadata",
            accepted_input=metadata_input,
            field_rules=metadata_rules,
            published_at=published_at,
            modified_at=modified_at,
        )
        _add_row(
            bundle,
            "cve_metadata_observations",
            {
                "cve_id": cve_id,
                "source_id": "patch8_nvd",
                "record_state": record_state,
                "published_at": published_at,
                "modified_at": modified_at,
                "source_identifier": source_identifier,
                "provider_org_id": None,
                "provider_short_name": None,
            },
            metadata_provenance,
            gate,
        )

        metrics = cve.get("metrics", {})
        if not isinstance(metrics, dict):
            raise SchemaDrift(f"NVD {cve_id}.metrics must be an object")
        current_metrics: list[dict[str, Any]] = []
        for metric_kind, expected_version in CVSS_KINDS:
            for metric_index, metric in enumerate(_list(metrics.get(metric_kind), f"NVD {cve_id}.{metric_kind}")):
                if not isinstance(metric, dict):
                    raise SchemaDrift(f"NVD {cve_id}.{metric_kind}[{metric_index}] must be an object")
                metric_author = require_text(metric.get("source"), f"NVD {cve_id}.{metric_kind}[{metric_index}].source")
                if metric_author.lower() != "nvd@nist.gov":
                    continue
                metric_type = metric.get("type")
                if metric_type is not None:
                    metric_type = require_text(metric_type, f"NVD {cve_id}.{metric_kind}[{metric_index}].type")
                cvss_data = metric.get("cvssData")
                if not isinstance(cvss_data, dict):
                    raise SchemaDrift(f"NVD {cve_id}.{metric_kind}[{metric_index}].cvssData must be an object")
                version = require_text(cvss_data.get("version"), f"NVD {cve_id}.{metric_kind}[{metric_index}].version")
                if version != expected_version:
                    raise SchemaDrift(f"NVD {cve_id}.{metric_kind}[{metric_index}] version does not match its family")
                vector = require_text(cvss_data.get("vectorString"), f"NVD {cve_id}.{metric_kind}[{metric_index}].vectorString")
                base_score = _number(cvss_data.get("baseScore"), f"NVD {cve_id}.{metric_kind}[{metric_index}].baseScore")
                if version == "2.0":
                    base_severity = require_text(metric.get("baseSeverity"), f"NVD {cve_id}.{metric_kind}[{metric_index}].baseSeverity")
                    severity_rule = "cve.metrics.cvssMetricV2[].baseSeverity"
                else:
                    base_severity = require_text(cvss_data.get("baseSeverity"), f"NVD {cve_id}.{metric_kind}[{metric_index}].cvssData.baseSeverity")
                    severity_rule = "nvd.cvss.cvssData.baseSeverity"
                accepted_metric = {
                    "source": metric_author,
                    "type": metric_type,
                    "cvssData": {
                        "version": version,
                        "vectorString": vector,
                        "baseScore": base_score,
                        "baseSeverity": base_severity,
                    },
                }
                metric_rules = [
                    "cve.id",
                    "cve.lastModified",
                    "nvd.cvss.source",
                    "nvd.cvss.type",
                    "nvd.cvss.cvssData.version",
                    "nvd.cvss.cvssData.vectorString",
                    "nvd.cvss.cvssData.baseScore",
                    severity_rule,
                ]
                provenance = _nvd_provenance(
                    gate=gate,
                    record_path=f"cves/{cve_id}/metrics/{metric_kind}/{metric_index}",
                    accepted_input=accepted_metric,
                    field_rules=metric_rules,
                    published_at=None,
                    modified_at=modified_at,
                    author=metric_author,
                )
                row = _add_row(
                    bundle,
                    "cvss_observations",
                    {
                        "cve_id": cve_id,
                        "source_id": "patch8_nvd",
                        "metric_author": metric_author,
                        "metric_type": metric_type,
                        "cvss_version": version,
                        "vector": vector,
                        "base_score": base_score,
                        "base_severity": base_severity,
                        "source_modified_at": modified_at,
                    },
                    provenance,
                    gate,
                )
                current_metrics.append(row)
        if current_metrics:
            selected = min(
                current_metrics,
                key=lambda row: (
                    0 if (row["metric_type"] or "").lower() == "primary" else 1,
                    CVSS_VERSION_ORDER[row["cvss_version"]],
                    row["observation_id"],
                ),
            )
            bundle["selected_cvss_observation_ids"][cve_id] = selected["observation_id"]

        for weakness_index, weakness in enumerate(_list(cve.get("weaknesses"), f"NVD {cve_id}.weaknesses")):
            if not isinstance(weakness, dict):
                raise SchemaDrift(f"NVD {cve_id}.weaknesses[{weakness_index}] must be an object")
            for description_index, description in enumerate(
                _list(weakness.get("description"), f"NVD {cve_id}.weaknesses[{weakness_index}].description")
            ):
                if not isinstance(description, dict):
                    raise SchemaDrift(f"NVD {cve_id} weakness description must be an object")
                cwe_id = description.get("value")
                if not isinstance(cwe_id, str) or not CWE_RE.fullmatch(cwe_id):
                    continue
                accepted_weakness = {"cwe_id": cwe_id}
                provenance = _nvd_provenance(
                    gate=gate,
                    record_path=f"cves/{cve_id}/weaknesses/{weakness_index}/{description_index}",
                    accepted_input=accepted_weakness,
                    field_rules=["cve.id", "cve.lastModified", "nvd.weakness.cwe_id"],
                    published_at=None,
                    modified_at=modified_at,
                )
                _add_row(
                    bundle,
                    "weakness_observations",
                    {
                        "cve_id": cve_id,
                        "cwe_id": cwe_id,
                        "source_id": "patch8_nvd",
                        "metric_author": None,
                        "source_modified_at": modified_at,
                    },
                    provenance,
                    gate,
                )

        for reference_index, reference in enumerate(_list(cve.get("references"), f"NVD {cve_id}.references")):
            if not isinstance(reference, dict):
                raise SchemaDrift(f"NVD {cve_id}.references[{reference_index}] must be an object")
            url = require_text(reference.get("url"), f"NVD {cve_id}.references[{reference_index}].url")
            parsed_url = urlparse(url)
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
                raise SchemaDrift(f"NVD {cve_id} reference must be an absolute HTTP(S) URL")
            tags = reference.get("tags", [])
            if not isinstance(tags, list) or any(not isinstance(tag, str) or not tag for tag in tags):
                raise SchemaDrift(f"NVD {cve_id} reference tags must be strings")
            accepted_reference = {"url": url, "tags": tags}
            provenance = _nvd_provenance(
                gate=gate,
                record_path=f"cves/{cve_id}/references/{reference_index}",
                accepted_input=accepted_reference,
                field_rules=["cve.id", "cve.lastModified", "nvd.reference.url", "nvd.reference.tags"],
                published_at=None,
                modified_at=modified_at,
            )
            _add_row(
                bundle,
                "references",
                {
                    "cve_id": cve_id,
                    "source_id": "patch8_nvd",
                    "url": url,
                    "tags": list(tags),
                    "source_modified_at": modified_at,
                },
                provenance,
                gate,
            )

        for configuration_index, configuration in enumerate(
            _list(cve.get("configurations"), f"NVD {cve_id}.configurations")
        ):
            config = require_keys(
                configuration,
                field=f"NVD {cve_id}.configurations[{configuration_index}]",
                required={"nodes"},
                allowed={"nodes"},
            )
            configuration_id = digest({"cve_id": cve_id, "configuration_index": configuration_index})
            for node_index, node in enumerate(_list(config["nodes"], f"NVD {cve_id} configuration nodes")):
                normalized_node = require_keys(
                    node,
                    field=f"NVD {cve_id}.configurations[{configuration_index}].nodes[{node_index}]",
                    required={"operator", "negate", "cpeMatch"},
                    allowed={"operator", "negate", "cpeMatch"},
                )
                node_operator = require_text(normalized_node["operator"], f"NVD {cve_id} node operator")
                if node_operator not in {"AND", "OR"}:
                    raise SchemaDrift(f"NVD {cve_id} node operator is invalid")
                node_negate = _bool(normalized_node["negate"], f"NVD {cve_id} node negate")
                node_id = digest({"configuration_id": configuration_id, "node_index": node_index})
                node_input = {"operator": node_operator, "negate": node_negate}
                node_provenance = _nvd_provenance(
                    gate=gate,
                    record_path=f"cves/{cve_id}/configurations/{configuration_index}/nodes/{node_index}",
                    accepted_input=node_input,
                    field_rules=["cve.id", "cve.lastModified", "cve.configurations[].nodes[].operator", "cve.configurations[].nodes[].negate"],
                    published_at=None,
                    modified_at=modified_at,
                )
                _add_row(
                    bundle,
                    "configuration_node_observations",
                    {
                        "cve_id": cve_id,
                        "configuration_id": configuration_id,
                        "node_id": node_id,
                        "parent_node_id": None,
                        "configuration_index": configuration_index,
                        "node_index": node_index,
                        "node_kind": "node",
                        "node_depth": 0,
                        "child_order": node_index,
                        "operator": node_operator,
                        "negate": node_negate,
                        "source_modified_at": modified_at,
                    },
                    node_provenance,
                    gate,
                )
                for match_index, match in enumerate(
                    _list(normalized_node["cpeMatch"], f"NVD {cve_id} node cpeMatch")
                ):
                    normalized_match = require_keys(
                        match,
                        field=f"NVD {cve_id} cpeMatch[{match_index}]",
                        required={"vulnerable", "criteria"},
                        allowed={
                            "vulnerable",
                            "criteria",
                            "matchCriteriaId",
                            "versionStartIncluding",
                            "versionStartExcluding",
                            "versionEndIncluding",
                            "versionEndExcluding",
                        },
                    )
                    vulnerable = _bool(normalized_match["vulnerable"], f"NVD {cve_id} cpeMatch vulnerable")
                    cpe_uri = require_text(normalized_match["criteria"], f"NVD {cve_id} cpeMatch criteria")
                    vendor, product, version = _split_cpe23(cpe_uri)
                    match_criteria_id = normalized_match.get("matchCriteriaId")
                    if match_criteria_id is not None:
                        match_criteria_id = require_text(match_criteria_id, f"NVD {cve_id} matchCriteriaId")
                    bounds = {}
                    for source_name, output_name in (
                        ("versionStartIncluding", "version_start_including"),
                        ("versionStartExcluding", "version_start_excluding"),
                        ("versionEndIncluding", "version_end_including"),
                        ("versionEndExcluding", "version_end_excluding"),
                    ):
                        raw_bound = normalized_match.get(source_name)
                        bounds[output_name] = (
                            require_text(raw_bound, f"NVD {cve_id} {source_name}") if raw_bound is not None else None
                        )
                    if bounds["version_start_including"] is not None and bounds["version_start_excluding"] is not None:
                        raise SchemaDrift(f"NVD {cve_id} CPE match has conflicting start bounds")
                    if bounds["version_end_including"] is not None and bounds["version_end_excluding"] is not None:
                        raise SchemaDrift(f"NVD {cve_id} CPE match has conflicting end bounds")
                    accepted_match = {
                        "vulnerable": vulnerable,
                        "criteria": cpe_uri,
                        "matchCriteriaId": match_criteria_id,
                        **bounds,
                    }
                    match_rules = [
                        "cve.id",
                        "cve.lastModified",
                        "cve.configurations[].nodes[].cpeMatch[].vulnerable",
                        "cve.configurations[].nodes[].cpeMatch[].criteria",
                    ]
                    if match_criteria_id is not None:
                        match_rules.append("cve.configurations[].nodes[].cpeMatch[].matchCriteriaId")
                    for source_name, output_name in (
                        ("versionStartIncluding", "version_start_including"),
                        ("versionStartExcluding", "version_start_excluding"),
                        ("versionEndIncluding", "version_end_including"),
                        ("versionEndExcluding", "version_end_excluding"),
                    ):
                        if bounds[output_name] is not None:
                            match_rules.append(f"cve.configurations[].nodes[].cpeMatch[].{source_name}")
                    match_provenance = _nvd_provenance(
                        gate=gate,
                        record_path=f"cves/{cve_id}/configurations/{configuration_index}/nodes/{node_index}/cpeMatch/{match_index}",
                        accepted_input=accepted_match,
                        field_rules=match_rules,
                        published_at=None,
                        modified_at=modified_at,
                    )
                    _add_row(
                        bundle,
                        "affected_software",
                        {
                            "cve_id": cve_id,
                            "configuration_id": configuration_id,
                            "node_id": node_id,
                            "vulnerable": vulnerable,
                            "match_criteria_id": match_criteria_id,
                            "vendor": vendor,
                            "product": product,
                            "cpe_uri": cpe_uri,
                            "version": None if version in {"*", "-"} else version,
                            **bounds,
                            "source_id": "patch8_nvd",
                            "source_modified_at": modified_at,
                        },
                        match_provenance,
                        gate,
                    )
        bundle["known_cve_ids"].append(cve_id)

    contract = gate.contract
    for table in NVD_TABLES:
        expected_fields = set(contract["tables"][table])
        for row in bundle[table]:
            if set(row) != expected_fields:
                raise IngestionError(f"{table} output differs from contract 3")
        sort_keys = contract["table_keys"][table]["sort_keys"]
        bundle[table].sort(key=lambda row: tuple((row[key] is None, row[key]) for key in sort_keys))
    bundle["known_cve_ids"].sort()
    bundle["selected_cvss_observation_ids"] = dict(sorted(bundle["selected_cvss_observation_ids"].items()))
    bundle["provenance"] = sorted(
        bundle["provenance"].values(),
        key=lambda row: (row["source_id"], row["source_record_path"], row["provenance_id"]),
    )
    return bundle


def merge_nvd_state(
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any],
    *,
    mode: str,
    gate: PolicyGate | None = None,
) -> Mapping[str, Any]:
    gate = gate or PolicyGate.load()
    if mode not in {"full", "modified"}:
        raise ValueError("NVD merge mode must be full or modified")
    if mode == "full" or previous is None:
        merged = {key: list(current[key]) for key in NVD_TABLES}
        selected = dict(current["selected_cvss_observation_ids"])
    else:
        replaced = set(current["known_cve_ids"])
        merged = {
            key: [row for row in previous.get(key, []) if row["cve_id"] not in replaced] + list(current[key])
            for key in NVD_TABLES
        }
        selected = {
            cve_id: observation_id
            for cve_id, observation_id in previous.get("selected_cvss_observation_ids", {}).items()
            if cve_id not in replaced
        }
        selected.update(current["selected_cvss_observation_ids"])
    provenance_ids = {row["provenance_id"] for table in NVD_TABLES for row in merged[table]}
    provenance_by_id = {
        row["provenance_id"]: row
        for row in [*(previous or {}).get("provenance", []), *current.get("provenance", [])]
        if row["provenance_id"] in provenance_ids
    }
    for table in NVD_TABLES:
        sort_keys = gate.contract["table_keys"][table]["sort_keys"]
        merged[table].sort(key=lambda row: tuple((row[key] is None, row[key]) for key in sort_keys))
    return {
        "format": "patch8-p4-nvd-core-v1",
        **merged,
        "provenance": sorted(provenance_by_id.values(), key=lambda row: row["provenance_id"]),
        "selected_cvss_observation_ids": dict(sorted(selected.items())),
        "known_cve_ids": sorted({row["cve_id"] for row in merged["cve_metadata_observations"]}),
    }


class NvdPipeline:
    """Build and atomically activate a complete or modified NVD core state."""

    def __init__(self, client: BoundedJsonClient, *, gate: PolicyGate | None = None) -> None:
        self.client = client
        self.gate = gate or PolicyGate.load()

    def run(
        self,
        operation: NvdOperation,
        *,
        checkpoint_path: Path,
        state_path: Path,
        retrieved_at: datetime,
        builder_source_revision: str,
    ) -> Mapping[str, Any]:
        if not HEX_40_RE.fullmatch(builder_source_revision):
            raise IngestionError("builder source revision must be an immutable 40-character Git commit")
        prior: Mapping[str, Any] | None = None
        if state_path.exists():
            try:
                candidate = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise IngestionError("existing NVD state is unreadable or corrupt") from error
            if not isinstance(candidate, dict) or candidate.get("format") != "patch8-p4-nvd-core-v1":
                raise IngestionError("existing NVD state has the wrong format")
            prior = candidate
        if operation.mode == "modified":
            if prior is None or not isinstance(prior.get("source_snapshot"), dict):
                raise WatermarkError("a modified operation requires a successful prior NVD snapshot")
            watermark = parse_instant(
                prior["source_snapshot"].get("last_successful_watermark"), "prior NVD watermark"
            )
            assert_contiguous_window(operation, watermark)

        staging_path = state_path.with_name(f".{state_path.name}.{operation.operation_id}.staging")
        checkpoint = load_checkpoint(checkpoint_path)
        if checkpoint is not None and checkpoint["operation_id"] != operation.operation_id:
            raise IngestionError("checkpoint belongs to a different NVD operation")
        if checkpoint is None:
            initial = normalize_nvd_vulnerabilities([], gate=self.gate)
            if operation.mode == "modified":
                initial = merge_nvd_state(prior, initial, mode="modified", gate=self.gate)
            atomic_write_json(
                staging_path,
                {"operation_id": operation.operation_id, "accepted_cve_ids": [], "state": initial},
            )
        elif not staging_path.exists():
            raise IngestionError("NVD checkpoint exists without its normalized staging state")

        def accept_page(vulnerabilities: list[Mapping[str, Any]], start_index: int) -> None:
            try:
                staging = json.loads(staging_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise IngestionError("NVD normalized staging state is unreadable or corrupt") from error
            if staging.get("operation_id") != operation.operation_id or not isinstance(staging.get("state"), dict):
                raise IngestionError("NVD normalized staging state belongs to a different operation")
            page = normalize_nvd_vulnerabilities(vulnerabilities, gate=self.gate)
            accepted_cve_ids = staging.get("accepted_cve_ids")
            if not isinstance(accepted_cve_ids, list) or any(
                not isinstance(cve_id, str) for cve_id in accepted_cve_ids
            ):
                raise IngestionError("NVD normalized staging state has invalid accepted CVE identities")
            duplicate_cves = sorted(set(accepted_cve_ids) & set(page["known_cve_ids"]))
            if duplicate_cves:
                raise SchemaDrift(f"NVD operation repeated CVE IDs across pages: {', '.join(duplicate_cves)}")
            merged = merge_nvd_state(staging["state"], page, mode="modified", gate=self.gate)
            atomic_write_json(
                staging_path,
                {
                    "operation_id": operation.operation_id,
                    "accepted_cve_ids": sorted({*accepted_cve_ids, *page["known_cve_ids"]}),
                    "state": merged,
                },
            )

        checkpoint = NvdPager(self.client).run(operation, checkpoint_path, accept_page)
        try:
            staging = json.loads(staging_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise IngestionError("completed NVD staging state is unreadable or corrupt") from error
        if staging.get("operation_id") != operation.operation_id or not isinstance(staging.get("state"), dict):
            raise IngestionError("completed NVD staging state belongs to a different operation")
        watermark = operation.window_end if operation.mode == "modified" else retrieved_at
        assert watermark is not None
        checked_at = instant_text(retrieved_at)
        watermark_text = instant_text(watermark)
        page_hashes = checkpoint["page_hashes"]
        snapshot_evidence = {
            "source_id": "patch8_nvd",
            "endpoint_or_repository": NVD_URL,
            "immutable_revision": None,
            "source_version": "2.0",
            "catalog_version": None,
            "schema_version_seen": 2,
            "etag": None,
            "last_modified": None,
            "window_start": instant_text(operation.window_start) if operation.window_start else None,
            "window_end": instant_text(operation.window_end) if operation.window_end else None,
            "complete_input_sha256": digest(page_hashes),
            "complete_input_bytes": checkpoint["response_bytes"],
            "checked_at": checked_at,
            "source_retrieved_at": checked_at,
            "source_observed_at": watermark_text,
            "last_successful_watermark": watermark_text,
            "builder_source_revision": builder_source_revision,
            "rights_policy_version": self.gate.policy["policy_version"],
            "schema_version": 1,
        }
        snapshot = {
            "source_snapshot_id": digest(snapshot_evidence),
            **snapshot_evidence,
        }
        if set(snapshot) != set(self.gate.contract["tables"]["source_snapshots"]):
            raise IngestionError("NVD source snapshot differs from contract 3")
        activated = {**staging["state"], "source_snapshot": snapshot}
        atomic_write_json(state_path, activated)
        checkpoint_path.unlink(missing_ok=True)
        staging_path.unlink(missing_ok=True)
        return activated


KEV_ENTRY_FIELDS = {
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes",
}


def _calendar_date(value: Any, field: str) -> str:
    text = require_text(value, field)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError as error:
        raise SchemaDrift(f"{field} must be YYYY-MM-DD") from error
    if parsed.isoformat() != text:
        raise SchemaDrift(f"{field} must be a canonical date")
    return text


def normalize_kev_snapshot(
    source_bytes: bytes,
    *,
    retrieved_at: datetime,
    builder_source_revision: str,
    endpoint_or_repository: str = KEV_URL,
    gate: PolicyGate | None = None,
    response_headers: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    gate = gate or PolicyGate.load()
    if not isinstance(source_bytes, bytes) or not source_bytes:
        raise SchemaDrift("KEV input must be the complete non-empty source bytes")
    if not HEX_40_RE.fullmatch(builder_source_revision):
        raise IngestionError("builder source revision must be an immutable 40-character Git commit")
    if endpoint_or_repository == KEV_URL:
        immutable_revision = None
    else:
        immutable_revision = require_immutable_kev_repository_url(endpoint_or_repository)
    try:
        payload = json.loads(source_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SchemaDrift("KEV source returned malformed JSON") from error
    source = gate.authorize(
        "patch8_cisa_kev", ["catalogVersion", "dateReleased", "vulnerabilities.*", "normalized_history.*"]
    )
    catalogue = require_keys(
        payload,
        field="KEV catalogue",
        required={"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"},
        allowed={"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"},
    )
    catalog_version = require_text(catalogue["catalogVersion"], "KEV catalogVersion")
    if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}", catalog_version):
        raise SchemaDrift("KEV catalogVersion must be YYYY.MM.DD")
    if catalogue["title"] != "CISA Catalog of Known Exploited Vulnerabilities":
        raise SchemaDrift("KEV title changed from the reviewed catalogue identity")
    released_at = parse_instant(catalogue["dateReleased"], "KEV dateReleased")
    if not isinstance(catalogue["count"], int) or isinstance(catalogue["count"], bool) or catalogue["count"] < 0:
        raise SchemaDrift("KEV count must be a non-negative integer")
    entries = catalogue["vulnerabilities"]
    if not isinstance(entries, list) or catalogue["count"] != len(entries):
        raise SchemaDrift("KEV declared count does not match the complete snapshot")
    observations: list[dict[str, Any]] = []
    provenance: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw_entry in enumerate(entries):
        entry = require_keys(
            raw_entry,
            field=f"KEV vulnerabilities[{index}]",
            required=KEV_ENTRY_FIELDS,
            allowed=KEV_ENTRY_FIELDS,
        )
        cve_id = require_cve(entry["cveID"], f"KEV vulnerabilities[{index}].cveID")
        if cve_id in seen:
            raise SchemaDrift(f"KEV contains duplicate {cve_id}")
        seen.add(cve_id)
        cwes = entry["cwes"]
        if not isinstance(cwes, list) or any(not isinstance(item, str) or not CWE_RE.fullmatch(item) for item in cwes):
            raise SchemaDrift(f"KEV {cve_id}.cwes must contain only canonical CWE IDs")
        if len(set(cwes)) != len(cwes):
            raise SchemaDrift(f"KEV {cve_id}.cwes contains duplicates")
        row_values = {
            "cve_id": cve_id,
            "vendor_project": require_text(entry["vendorProject"], f"KEV {cve_id}.vendorProject"),
            "product": require_text(entry["product"], f"KEV {cve_id}.product"),
            "vulnerability_name": require_text(entry["vulnerabilityName"], f"KEV {cve_id}.vulnerabilityName"),
            "date_added": _calendar_date(entry["dateAdded"], f"KEV {cve_id}.dateAdded"),
            "short_description": require_text(entry["shortDescription"], f"KEV {cve_id}.shortDescription"),
            "required_action": require_text(entry["requiredAction"], f"KEV {cve_id}.requiredAction"),
            "due_date": _calendar_date(entry["dueDate"], f"KEV {cve_id}.dueDate"),
            "known_ransomware_campaign_use": require_text(
                entry["knownRansomwareCampaignUse"], f"KEV {cve_id}.knownRansomwareCampaignUse"
            ),
            "notes": require_text(entry["notes"], f"KEV {cve_id}.notes", allow_empty=True) or None,
            "cwe_ids": list(cwes),
        }
        if row_values["known_ransomware_campaign_use"] not in {"Known", "Unknown"}:
            raise SchemaDrift(f"KEV {cve_id}.knownRansomwareCampaignUse is outside the reviewed values")
        if row_values["due_date"] < row_values["date_added"]:
            raise SchemaDrift(f"KEV {cve_id}.dueDate precedes dateAdded")
        record_path = f"vulnerabilities/{cve_id}"
        record_sha = digest(entry)
        field_rules = ["vulnerabilities.*"]
        provenance_id = digest(
            {
                "source_id": "patch8_cisa_kev",
                "source_record_path": record_path,
                "source_record_sha256": record_sha,
                "source_field_rules": field_rules,
                "transformation_kind": "normalized",
            }
        )
        observation_id = digest(
            {"table": "kev_observations", "source_id": "patch8_cisa_kev", "values": row_values}
        )
        observations.append(
            {
                "observation_id": observation_id,
                **row_values,
                "is_current": True,
                "provenance_id": provenance_id,
                "rights_policy_version": gate.policy["policy_version"],
                "schema_version": 1,
            }
        )
        provenance.append(
            {
                "provenance_id": provenance_id,
                "source_id": "patch8_cisa_kev",
                "source_display_name": source["display_name"],
                "source_policy_decision": "allow",
                "endpoint_or_repository": endpoint_or_repository,
                "source_record_path": record_path,
                "source_record_sha256": record_sha,
                "source_record_bytes": len(canonical_json(entry)),
                "source_published_at": None,
                "source_modified_at": None,
                "parser_name": "patch8_ingest.kev",
                "parser_version": "1",
                "transformation_version": "1",
                "table_schema_version": 1,
                "rights_policy_schema_version": gate.policy["schema_version"],
                "rights_policy_version": gate.policy["policy_version"],
                "source_field_rule": json.dumps(field_rules, separators=(",", ":")),
                "author_or_provider": "CISA",
                "transformation_kind": "normalized",
                "modification_note": "Field names normalized; no linked content fetched.",
                "required_notice_ids": list(source["required_notice_ids"]),
                "schema_version": 1,
            }
        )
    observations.sort(key=lambda item: (item["date_added"], item["cve_id"], item["observation_id"]))
    provenance.sort(key=lambda item: (item["source_record_path"], item["provenance_id"]))
    retrieved = instant_text(retrieved_at)
    snapshot_values = {
        "source_id": "patch8_cisa_kev",
        "endpoint_or_repository": endpoint_or_repository,
        "catalog_version": catalog_version,
        "complete_input_sha256": sha256(source_bytes).hexdigest(),
        "complete_input_bytes": len(source_bytes),
        "source_retrieved_at": retrieved,
    }
    snapshot_id = digest(snapshot_values)
    headers = {key.lower(): value for key, value in (response_headers or {}).items()}
    snapshot = {
        "source_snapshot_id": snapshot_id,
        **snapshot_values,
        "immutable_revision": immutable_revision,
        "source_version": None,
        "schema_version_seen": 1,
        "etag": headers.get("etag"),
        "last_modified": headers.get("last-modified"),
        "window_start": None,
        "window_end": None,
        "checked_at": retrieved,
        "source_observed_at": instant_text(released_at),
        "last_successful_watermark": catalog_version,
        "builder_source_revision": builder_source_revision,
        "rights_policy_version": gate.policy["policy_version"],
        "schema_version": 1,
    }
    return {
        "format": "patch8-p4-kev-core-v1",
        "complete": True,
        "kev_observations": observations,
        "provenance": provenance,
        "source_snapshot": snapshot,
    }


def reconcile_kev(
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any],
    *,
    observed_at: datetime,
) -> Mapping[str, Any]:
    if current.get("complete") is not True:
        raise IngestionError("an incomplete KEV snapshot cannot establish membership or removals")
    previous_rows = {
        row["cve_id"]: row for row in (previous or {}).get("kev_observations", []) if row.get("is_current") is True
    }
    current_rows = {row["cve_id"]: row for row in current.get("kev_observations", []) if row.get("is_current") is True}
    if len(current_rows) != len(current.get("kev_observations", [])):
        raise IngestionError("current KEV observations must be unique and current")
    changes: list[dict[str, Any]] = []
    timestamp = instant_text(observed_at)
    for cve_id in sorted(previous_rows.keys() | current_rows.keys()):
        old = previous_rows.get(cve_id)
        new = current_rows.get(cve_id)
        if old is None:
            change_type = "added"
        elif new is None:
            change_type = "removed"
        elif old["observation_id"] != new["observation_id"]:
            change_type = "edited"
        else:
            continue
        changes.append(
            {
                "cve_id": cve_id,
                "change_type": change_type,
                "old_observation_id": old["observation_id"] if old else None,
                "new_observation_id": new["observation_id"] if new else None,
                "observed_at": timestamp,
            }
        )
    return {**current, "changes": changes}


def kev_membership(reconciled: Mapping[str, Any] | None, cve_id: str) -> Mapping[str, Any]:
    normalized = require_cve(cve_id)
    if reconciled is None or reconciled.get("complete") is not True:
        return {"cve_id": normalized, "kev_status": "unknown", "in_kev": None, "kev_observation_id": None}
    rows = [row for row in reconciled.get("kev_observations", []) if row.get("cve_id") == normalized]
    if len(rows) > 1:
        raise IngestionError(f"KEV membership is ambiguous for {normalized}")
    if not rows:
        return {"cve_id": normalized, "kev_status": "not_listed", "in_kev": False, "kev_observation_id": None}
    return {
        "cve_id": normalized,
        "kev_status": "listed",
        "in_kev": True,
        "kev_observation_id": rows[0]["observation_id"],
    }


def require_immutable_kev_repository_url(url: str) -> str:
    parsed = urlparse(url)
    parts = parsed.path.strip("/").split("/")
    if (
        parsed.scheme != "https"
        or parsed.netloc != "raw.githubusercontent.com"
        or len(parts) != 4
        or parts[0:2] != ["cisagov", "kev-data"]
        or not HEX_40_RE.fullmatch(parts[2])
        or parts[3] != "known_exploited_vulnerabilities.json"
        or parsed.query
        or parsed.fragment
    ):
        raise IngestionError("KEV repository input must be the official JSON at an immutable commit")
    return parts[2]


class KevPipeline:
    """Atomically activate one complete KEV reconciliation or leave prior state unchanged."""

    def __init__(self, client: BoundedJsonClient, *, gate: PolicyGate | None = None) -> None:
        self.client = client
        self.gate = gate or PolicyGate.load()

    def run(
        self,
        *,
        source_url: str,
        state_path: Path,
        retrieved_at: datetime,
        builder_source_revision: str,
    ) -> Mapping[str, Any]:
        if source_url != KEV_URL:
            require_immutable_kev_repository_url(source_url)
        previous: Mapping[str, Any] | None = None
        if state_path.exists():
            try:
                candidate = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise IngestionError("existing KEV state is unreadable or corrupt") from error
            if not isinstance(candidate, dict) or candidate.get("format") != "patch8-p4-kev-core-v1":
                raise IngestionError("existing KEV state has the wrong format")
            previous = candidate
        response = self.client.get(source_url, expected_url=source_url)
        normalized = normalize_kev_snapshot(
            response.body,
            retrieved_at=retrieved_at,
            builder_source_revision=builder_source_revision,
            endpoint_or_repository=source_url,
            gate=self.gate,
            response_headers=response.headers,
        )
        reconciled = reconcile_kev(previous, normalized, observed_at=retrieved_at)
        atomic_write_json(state_path, reconciled)
        return reconciled
