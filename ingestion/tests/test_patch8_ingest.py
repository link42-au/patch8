from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import gzip
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from ingestion.patch8_ingest import (
    BoundedJsonClient,
    BudgetExceeded,
    CVELIST_REPOSITORY,
    CVELIST_VERIFIED_COMMIT,
    CveProgramLimits,
    CveProgramPipeline,
    FetchLimits,
    FullReconciliationRequired,
    IngestionError,
    JsonResponse,
    KEV_URL,
    KevPipeline,
    NVD_URL,
    NvdOperation,
    NvdPager,
    NvdPipeline,
    PolicyGate,
    RejectedCveRecord,
    SchemaDrift,
    Throttled,
    UrllibTransport,
    WatermarkError,
    assert_contiguous_window,
    canonical_json,
    cvelist_archive_url,
    kev_membership,
    next_delta_operation,
    merge_nvd_state,
    normalize_kev_snapshot,
    normalize_cve_program_archive,
    normalize_cve_program_record,
    normalize_nvd_vulnerabilities,
    nvd_full_reconciliation_status,
    reconcile_kev,
    require_immutable_kev_repository_url,
    validate_nvd_page,
)


FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "p4-cases.json").read_text(encoding="utf-8")
)
CVELIST_FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "p4a-cases.json").read_text(encoding="utf-8")
)
NOW = datetime(2026, 8, 29, tzinfo=UTC)
BUILDER_REVISION = "1" * 40


class SequenceTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []
        self.timeouts = []
        self.max_bytes = []

    def get(self, url, headers, *, timeout_seconds, max_bytes, remaining_seconds):
        self.urls.append(url)
        self.timeouts.append(timeout_seconds)
        self.max_bytes.append(max_bytes)
        remaining_seconds()
        if not self.responses:
            raise AssertionError("unexpected request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if len(response.body) > max_bytes:
            raise BudgetExceeded("mock transport refused to acquire beyond the remaining byte budget")
        return JsonResponse(
            body=response.body,
            headers=response.headers,
            status=response.status,
            final_url=response.final_url or url,
        )


class FakeHttpResponse:
    def __init__(self, body, *, content_length=None, final_url=NVD_URL):
        self.stream = BytesIO(body)
        self.headers = {} if content_length is None else {"Content-Length": str(content_length)}
        self.final_url = final_url
        self.read_sizes = []

    def read(self, size):
        self.read_sizes.append(size)
        return self.stream.read(size)

    def geturl(self):
        return self.final_url


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def response(value, *, status=200, headers=None):
    return JsonResponse(body=canonical_json(value), status=status, headers=headers or {})


def client(transport, **overrides):
    limits = FetchLimits(
        max_requests=overrides.pop("max_requests", 20),
        max_bytes=overrides.pop("max_bytes", 1_000_000),
        max_pages=overrides.pop("max_pages", 20),
        timeout_seconds=1,
        minimum_interval_seconds=0,
        max_throttle_responses=overrides.pop("max_throttle_responses", 1),
        max_retry_after_seconds=overrides.pop("max_retry_after_seconds", 1),
        max_operation_seconds=overrides.pop("max_operation_seconds", 60),
    )
    if overrides:
        raise AssertionError(f"unused overrides: {overrides}")
    return BoundedJsonClient(transport, limits, sleep=lambda _: None, monotonic=lambda: 0)


def nvd_page(records, *, start=0, total=None, page_size=2, timestamp="2026-08-29T00:00:00.000Z"):
    return {
        "resultsPerPage": page_size,
        "startIndex": start,
        "totalResults": len(records) if total is None else total,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": timestamp,
        "vulnerabilities": deepcopy(records),
    }


def cvelist_record_path(record):
    cve_id = record["cveMetadata"]["cveId"]
    _, year, serial = cve_id.split("-")
    return f"cves/{year}/{int(serial) // 1_000}xxx/{cve_id}.json"


def archive_member(name, *, data=b"", member_type=tarfile.REGTYPE, linkname=""):
    member = tarfile.TarInfo(name)
    member.type = member_type
    member.size = len(data) if member_type in {tarfile.REGTYPE, tarfile.AREGTYPE} else 0
    member.linkname = linkname
    member.mtime = 0
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    return member, BytesIO(data) if member.type in {tarfile.REGTYPE, tarfile.AREGTYPE} else None


def cvelist_archive(
    records,
    commit,
    *,
    paths=None,
    extra_members=(),
    tar_format=tarfile.DEFAULT_FORMAT,
):
    paths = paths or [cvelist_record_path(record) for record in records]
    output = BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tar_format) as archive:
            for member, payload in extra_members:
                archive.addfile(member, payload)
            for path, record in zip(paths, records, strict=True):
                record_bytes = canonical_json(record)
                member = tarfile.TarInfo(f"cvelistV5-{commit}/{path}")
                member.size = len(record_bytes)
                member.mtime = 0
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                archive.addfile(member, BytesIO(record_bytes))
    return output.getvalue()


class PolicyTests(unittest.TestCase):
    def test_reviewed_policy_loads_and_kev_is_authorized(self):
        gate = PolicyGate.load()
        source = gate.authorize("patch8_cisa_kev", ["catalogVersion", "vulnerabilities.*"])
        self.assertEqual(source["source_locator"], "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")

    def test_unknown_field_fails_closed(self):
        with self.assertRaisesRegex(IngestionError, "not allowed"):
            PolicyGate.load().authorize("patch8_nvd", ["cve.descriptions.*"])

    def test_reviewed_transition_is_contract_3_and_policy_3(self):
        gate = PolicyGate.load()
        self.assertEqual(gate.contract["contract_version"], 3)
        self.assertEqual(gate.policy["policy_version"], "3.0.0")


class NvdPaginationTests(unittest.TestCase):
    def test_full_import_uses_bounded_ordered_pagination_and_atomic_checkpoint(self):
        transport = SequenceTransport(
            [response(FIXTURES["nvd_pages"]["0"]), response(FIXTURES["nvd_pages"]["2"])]
        )
        accepted = []
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "nvd.json"
            result = NvdPager(client(transport)).run(
                NvdOperation(mode="full", results_per_page=2),
                checkpoint,
                lambda rows, evidence: (
                    accepted.extend((evidence["start_index"], row["cve"]["id"]) for row in rows)
                    or evidence["page_sha256"]
                ),
            )
            self.assertTrue(result["complete"])
            self.assertEqual(result["next_start_index"], 3)
            self.assertEqual(len(result["page_hashes"]), 2)
            self.assertEqual(accepted, [(0, "CVE-2025-1001"), (0, "CVE-2025-1002"), (2, "CVE-2025-1003")])
            stored = json.loads(checkpoint.read_text(encoding="utf-8"))
            self.assertEqual(stored, result)
        self.assertIn("resultsPerPage=2", transport.urls[0])
        self.assertIn("startIndex=2", transport.urls[1])

    def test_restart_resumes_after_last_accepted_page_without_persisting_raw_pages(self):
        operation = NvdOperation(mode="full", results_per_page=2)
        accepted = []
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "nvd.json"
            first = SequenceTransport([response(FIXTURES["nvd_pages"]["0"]), response({}, status=500)])
            with self.assertRaisesRegex(IngestionError, "HTTP 500"):
                NvdPager(client(first)).run(
                    operation,
                    checkpoint,
                    lambda rows, evidence: (
                        accepted.extend(row["cve"]["id"] for row in rows) or evidence["page_sha256"]
                    ),
                )
            stored_text = checkpoint.read_text(encoding="utf-8")
            self.assertNotIn("vulnerabilities", stored_text)
            self.assertEqual(json.loads(stored_text)["next_start_index"], 2)
            second = SequenceTransport([response(FIXTURES["nvd_pages"]["2"])])
            result = NvdPager(client(second)).run(
                operation,
                checkpoint,
                lambda rows, evidence: (
                    accepted.extend(row["cve"]["id"] for row in rows) or evidence["page_sha256"]
                ),
            )
            self.assertTrue(result["complete"])
            self.assertIn("startIndex=2", second.urls[0])
        self.assertEqual(accepted, ["CVE-2025-1001", "CVE-2025-1002", "CVE-2025-1003"])

    def test_corrupt_or_mismatched_checkpoint_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "nvd.json"
            checkpoint.write_text("{}", encoding="utf-8")
            with self.assertRaises(SchemaDrift):
                NvdPager(client(SequenceTransport([]))).run(
                    NvdOperation(mode="full", results_per_page=2), checkpoint, lambda rows, evidence: evidence["page_sha256"]
                )

    def test_page_budget_stops_before_an_extra_request(self):
        transport = SequenceTransport([response(FIXTURES["nvd_pages"]["0"])])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(BudgetExceeded, "page budget"):
                NvdPager(client(transport, max_pages=1)).run(
                    NvdOperation(mode="full", results_per_page=2),
                    Path(directory) / "nvd.json",
                    lambda rows, evidence: evidence["page_sha256"],
                )
        self.assertEqual(len(transport.urls), 1)

    def test_request_and_byte_budgets_fail_closed(self):
        transport = SequenceTransport([response(FIXTURES["nvd_pages"]["0"])])
        bounded = client(transport, max_bytes=8)
        with self.assertRaisesRegex(BudgetExceeded, "byte"):
            bounded.get(f"{NVD_URL}?startIndex=0", expected_url=NVD_URL)
        self.assertEqual(transport.timeouts, [1])
        self.assertEqual(transport.max_bytes, [8])
        request_client = client(SequenceTransport([response({})]), max_requests=1)
        request_client.get(f"{NVD_URL}?startIndex=0", expected_url=NVD_URL)
        with self.assertRaisesRegex(BudgetExceeded, "request"):
            request_client.get(f"{NVD_URL}?startIndex=1", expected_url=NVD_URL)

    def test_transport_rejects_declared_and_streamed_excess_before_allocation(self):
        declared = FakeHttpResponse(b"unused", content_length=9)
        with self.assertRaisesRegex(BudgetExceeded, "declared response length"):
            UrllibTransport._read_bounded(declared, 8)
        self.assertEqual(declared.read_sizes, [])

        streamed = FakeHttpResponse(b"123456789")
        with self.assertRaisesRegex(BudgetExceeded, "streamed response"):
            UrllibTransport._read_bounded(streamed, 8)
        self.assertEqual(streamed.read_sizes, [9])

        exact = FakeHttpResponse(b"12345678", content_length=8)
        self.assertEqual(UrllibTransport._read_bounded(exact, 8), b"12345678")
        self.assertTrue(all(size <= 9 for size in exact.read_sizes))

        clock = FakeClock()

        class SlowChunkedResponse:
            headers = {}

            def __init__(self):
                self.read_calls = 0
                self.timeouts = []

            def settimeout(self, seconds):
                self.timeouts.append(seconds)

            def read(self, _size):
                self.read_calls += 1
                allowed = self.timeouts[-1]
                intended = 0.06
                clock.now += min(allowed, intended)
                if allowed < intended:
                    clock.now = 0.1
                    raise TimeoutError("injected socket deadline")
                return b"x"

        slow = SlowChunkedResponse()

        def remaining():
            seconds = 0.1 - clock.now
            if seconds <= 0:
                raise BudgetExceeded("operation deadline exceeded before streamed response read")
            return seconds

        with self.assertRaisesRegex(BudgetExceeded, "streamed response read"):
            UrllibTransport._read_bounded(
                slow,
                8,
                timeout_seconds=45,
                remaining_seconds=remaining,
            )
        self.assertEqual(slow.read_calls, 2)
        self.assertAlmostEqual(slow.timeouts[0], 0.1)
        self.assertAlmostEqual(slow.timeouts[1], 0.04)
        self.assertAlmostEqual(clock.now, 0.1)

    def test_redirected_final_url_is_rejected_and_exact_identity_is_recorded(self):
        redirected = response(FIXTURES["nvd_pages"]["0"])
        redirected = JsonResponse(
            body=redirected.body,
            headers=redirected.headers,
            status=redirected.status,
            final_url="https://example.invalid/rest/json/cves/2.0",
        )
        transport = SequenceTransport([redirected])
        with self.assertRaisesRegex(IngestionError, "final response URL"):
            client(transport).get(NVD_URL, expected_url=NVD_URL)

    def test_total_wall_clock_deadline_covers_response_page_application_and_retry(self):
        clock = FakeClock()

        class SlowTransport(SequenceTransport):
            def get(self, *args, **kwargs):
                result = super().get(*args, **kwargs)
                clock.now = 2
                return result

        limits = FetchLimits(
            max_requests=2,
            max_bytes=1_000_000,
            max_pages=2,
            timeout_seconds=1,
            minimum_interval_seconds=0,
            max_throttle_responses=0,
            max_retry_after_seconds=0,
            max_operation_seconds=1,
        )
        bounded = BoundedJsonClient(SlowTransport([response(FIXTURES["nvd_pages"]["0"])]), limits, sleep=lambda _: None, monotonic=clock)
        with self.assertRaisesRegex(BudgetExceeded, "deadline"):
            bounded.get(NVD_URL, expected_url=NVD_URL)

        clock = FakeClock()
        bounded = BoundedJsonClient(
            SequenceTransport([response(nvd_page([FIXTURES["nvd_records"]["rich"]], page_size=1))]),
            limits,
            sleep=lambda _: None,
            monotonic=clock,
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(BudgetExceeded, "checkpoint write"):
                NvdPager(bounded).run(
                    NvdOperation(mode="full", results_per_page=1),
                    Path(directory) / "deadline.json",
                    lambda rows, evidence: (
                        setattr(clock, "now", 2) or evidence["page_sha256"]
                    ),
                )

        clock = FakeClock()
        retry_limits = FetchLimits(
            max_requests=2,
            max_bytes=1_000,
            max_pages=1,
            timeout_seconds=1,
            minimum_interval_seconds=0,
            max_throttle_responses=1,
            max_retry_after_seconds=1,
            max_operation_seconds=0.5,
        )
        retrying = BoundedJsonClient(
            SequenceTransport([response({}, status=429, headers={"retry-after": "1"})]),
            retry_limits,
            sleep=lambda seconds: setattr(clock, "now", clock.now + seconds),
            monotonic=clock,
        )
        with self.assertRaisesRegex(BudgetExceeded, "throttle retry"):
            retrying.get(NVD_URL, expected_url=NVD_URL)

    def test_remaining_deadline_caps_transport_timeout_rate_wait_and_retry_wait(self):
        limits = FetchLimits(
            max_requests=2,
            max_bytes=1_000_000,
            max_pages=2,
            timeout_seconds=45,
            minimum_interval_seconds=2,
            max_throttle_responses=1,
            max_retry_after_seconds=2,
            max_operation_seconds=1,
        )

        clock = FakeClock()
        transport = SequenceTransport([response({})])
        bounded = BoundedJsonClient(transport, limits, sleep=lambda _: None, monotonic=clock)
        clock.now = 0.9
        bounded.get(NVD_URL, expected_url=NVD_URL)
        self.assertAlmostEqual(transport.timeouts[0], 0.1)

        expired_transport = SequenceTransport([response({})])
        expired = BoundedJsonClient(expired_transport, limits, sleep=lambda _: None, monotonic=clock)
        clock.now = 2
        with self.assertRaisesRegex(BudgetExceeded, "request"):
            expired.get(NVD_URL, expected_url=NVD_URL)
        self.assertEqual(expired_transport.urls, [])

        rate_sleeps = []
        clock = FakeClock()
        rate_transport = SequenceTransport([response({})])
        rate_limited = BoundedJsonClient(
            rate_transport,
            limits,
            sleep=lambda seconds: (rate_sleeps.append(seconds), setattr(clock, "now", clock.now + seconds)),
            monotonic=clock,
        )
        rate_limited._last_request_at = 0
        clock.now = 0.9
        with self.assertRaisesRegex(BudgetExceeded, "rate-limited request"):
            rate_limited.get(NVD_URL, expected_url=NVD_URL)
        self.assertAlmostEqual(rate_sleeps[0], 0.1)
        self.assertEqual(rate_transport.urls, [])

        retry_sleeps = []
        clock = FakeClock()
        retry_transport = SequenceTransport(
            [response({}, status=429, headers={"retry-after": "2"})]
        )
        retrying = BoundedJsonClient(
            retry_transport,
            limits,
            sleep=lambda seconds: (retry_sleeps.append(seconds), setattr(clock, "now", clock.now + seconds)),
            monotonic=clock,
        )
        clock.now = 0.9
        with self.assertRaisesRegex(BudgetExceeded, "throttle retry"):
            retrying.get(NVD_URL, expected_url=NVD_URL)
        self.assertAlmostEqual(retry_transport.timeouts[0], 0.1)
        self.assertAlmostEqual(retry_sleeps[0], 0.1)
        self.assertEqual(len(retry_transport.urls), 1)

    def test_throttling_retries_only_within_explicit_bound(self):
        transport = SequenceTransport(
            [response({}, status=429, headers={"retry-after": "0"}), response({}, status=429, headers={"retry-after": "0"})]
        )
        with self.assertRaisesRegex(Throttled, "retry bound"):
            client(transport, max_throttle_responses=1).get(
                f"{NVD_URL}?startIndex=0", expected_url=NVD_URL
            )
        self.assertEqual(len(transport.urls), 2)

    def test_unreviewed_host_is_rejected_before_transport(self):
        transport = SequenceTransport([])
        with self.assertRaisesRegex(IngestionError, "reviewed HTTPS"):
            client(transport).get("https://example.invalid/cves", expected_url=NVD_URL)
        self.assertEqual(transport.urls, [])

    def test_malformed_schema_order_and_total_drift_are_rejected(self):
        unknown = deepcopy(FIXTURES["nvd_pages"]["0"])
        unknown["newField"] = True
        with self.assertRaisesRegex(SchemaDrift, "unreviewed fields"):
            validate_nvd_page(unknown, expected_start=0, requested_page_size=2)
        reversed_page = deepcopy(FIXTURES["nvd_pages"]["0"])
        reversed_page["vulnerabilities"].reverse()
        with self.assertRaisesRegex(SchemaDrift, "not ordered"):
            validate_nvd_page(reversed_page, expected_start=0, requested_page_size=2)
        overshoot = nvd_page(
            [FIXTURES["nvd_records"]["rich"], FIXTURES["nvd_records"]["second"]],
            total=1,
            page_size=2,
        )
        with self.assertRaisesRegex(SchemaDrift, "overshoots"):
            validate_nvd_page(overshoot, expected_start=0, requested_page_size=2)
        changed_total = deepcopy(FIXTURES["nvd_pages"]["2"])
        changed_total["totalResults"] = 4
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SchemaDrift, "totalResults changed"):
                NvdPager(
                    client(SequenceTransport([response(FIXTURES["nvd_pages"]["0"]), response(changed_total)]))
                ).run(
                    NvdOperation(mode="full", results_per_page=2),
                    Path(directory) / "nvd.json",
                    lambda rows, evidence: evidence["page_sha256"],
                )

    def test_official_zero_result_shape_and_timezone_less_timestamp_are_accepted(self):
        empty = nvd_page([], page_size=0, timestamp="2026-08-30T06:29:09.687")
        page = validate_nvd_page(empty, expected_start=0, requested_page_size=2_000)
        self.assertEqual(page["totalResults"], 0)
        invalid = deepcopy(empty)
        invalid["totalResults"] = 1
        with self.assertRaisesRegex(SchemaDrift, "empty result set"):
            validate_nvd_page(invalid, expected_start=0, requested_page_size=2_000)


class NvdNormalizationTests(unittest.TestCase):
    def test_all_approved_observations_are_exact_and_selected_without_erasure(self):
        normalized = normalize_nvd_vulnerabilities([deepcopy(FIXTURES["nvd_records"]["rich"])])
        gate = PolicyGate.load()
        for table in (
            "cve_metadata_observations",
            "cvss_observations",
            "weakness_observations",
            "references",
            "configuration_node_observations",
            "affected_software",
        ):
            for row in normalized[table]:
                self.assertEqual(set(row), set(gate.contract["tables"][table]))
        self.assertEqual([row["cvss_version"] for row in normalized["cvss_observations"]], ["2.0", "3.0", "3.1", "4.0"])
        v2 = next(row for row in normalized["cvss_observations"] if row["cvss_version"] == "2.0")
        self.assertEqual(v2["base_severity"], "HIGH")
        selected = normalized["selected_cvss_observation_ids"]["CVE-2025-1001"]
        selected_row = next(row for row in normalized["cvss_observations"] if row["observation_id"] == selected)
        self.assertEqual((selected_row["cvss_version"], selected_row["metric_type"]), ("4.0", "Primary"))
        self.assertEqual(len(normalized["cvss_observations"]), 4)
        self.assertEqual(normalized["cve_metadata_observations"][0]["record_state"], "Analyzed")
        self.assertNotIn("Excluded synthetic description", json.dumps(normalized))
        self.assertNotIn("Excluded comment", json.dumps(normalized))

    def test_actual_top_level_and_empty_nodes_and_cpe_bounds_are_preserved(self):
        normalized = normalize_nvd_vulnerabilities([deepcopy(FIXTURES["nvd_records"]["rich"])])
        nodes = normalized["configuration_node_observations"]
        self.assertEqual(len(nodes), 2)
        children = sorted(nodes, key=lambda row: row["child_order"])
        self.assertEqual(
            [(row["parent_node_id"], row["operator"], row["negate"], row["child_order"]) for row in children],
            [(None, "OR", False, 0), (None, "AND", True, 1)],
        )
        self.assertTrue(all((row["node_kind"], row["node_depth"]) == ("node", 0) for row in children))
        affected = normalized["affected_software"][0]
        self.assertEqual((affected["vendor"], affected["product"], affected["version"]), ("example", "alpha", None))
        self.assertEqual((affected["version_start_including"], affected["version_end_excluding"]), ("1.0", "2.0"))
        self.assertEqual(affected["node_id"], children[0]["node_id"])

    def test_reference_tags_are_trimmed_deduplicated_and_sorted(self):
        record = deepcopy(FIXTURES["nvd_records"]["rich"])
        record["cve"]["references"][0]["tags"] = [" Vendor Advisory ", "Patch", "Patch"]
        normalized = normalize_nvd_vulnerabilities([record])
        self.assertEqual(normalized["references"][0]["tags"], ["Patch", "Vendor Advisory"])

    def test_malformed_consumed_shape_identifier_reference_and_conflicting_bounds_fail_closed(self):
        cases = []
        missing = deepcopy(FIXTURES["nvd_records"]["second"])
        del missing["cve"]["sourceIdentifier"]
        cases.append(missing)
        lower = deepcopy(FIXTURES["nvd_records"]["second"])
        lower["cve"]["id"] = "cve-2025-1002"
        cases.append(lower)
        reference = deepcopy(FIXTURES["nvd_records"]["rich"])
        reference["cve"]["references"][0]["url"] = "javascript:alert(1)"
        cases.append(reference)
        bounds = deepcopy(FIXTURES["nvd_records"]["rich"])
        bounds["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionStartExcluding"] = "1.1"
        cases.append(bounds)
        for record in cases:
            with self.subTest(cve=record["cve"]["id"]):
                with self.assertRaises(SchemaDrift):
                    normalize_nvd_vulnerabilities([record])

    def test_official_extensible_fields_and_actual_configuration_container_are_accepted(self):
        record = deepcopy(FIXTURES["nvd_records"]["second"])
        record["cve"]["affected"] = [{"future": "official extension"}]
        record["cve"]["metrics"]["ssvcV203"] = [{"source": "CISA", "ssvcData": {}}]
        record["cve"]["published"] = "2025-01-02T00:00:00.000"
        record["cve"]["lastModified"] = "2026-08-28T00:00:00.000"
        normalized = normalize_nvd_vulnerabilities([record])
        self.assertEqual(normalized["known_cve_ids"], ["CVE-2025-1002"])
        self.assertNotIn("official extension", json.dumps(normalized))
        self.assertNotIn("ssvcV203", json.dumps(normalized))
        actual = normalize_nvd_vulnerabilities([deepcopy(FIXTURES["nvd_records"]["rich"])])
        self.assertTrue(all(row["parent_node_id"] is None for row in actual["configuration_node_observations"]))

    def test_clean_build_delta_and_double_build_are_equivalent(self):
        rich = deepcopy(FIXTURES["nvd_records"]["rich"])
        updated = deepcopy(FIXTURES["nvd_records"]["rich_updated"])
        second = deepcopy(FIXTURES["nvd_records"]["second"])
        initial = merge_nvd_state(None, normalize_nvd_vulnerabilities([rich, second]), mode="full")
        delta = merge_nvd_state(initial, normalize_nvd_vulnerabilities([updated]), mode="modified")
        clean = merge_nvd_state(None, normalize_nvd_vulnerabilities([updated, second]), mode="full")
        self.assertEqual(delta, clean)
        self.assertEqual(clean, merge_nvd_state(None, normalize_nvd_vulnerabilities([updated, second]), mode="full"))

    def test_pipeline_restarts_without_raw_pages_and_activates_only_after_completion(self):
        rich = FIXTURES["nvd_records"]["rich"]
        second = FIXTURES["nvd_records"]["second"]
        operation = NvdOperation(mode="full", results_per_page=1)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "nvd-checkpoint.json"
            state = Path(directory) / "nvd-state.json"
            first_transport = SequenceTransport(
                [response(nvd_page([rich], total=2, page_size=1)), response({}, status=500)]
            )
            with self.assertRaisesRegex(IngestionError, "HTTP 500"):
                NvdPipeline(client(first_transport)).run(
                    operation,
                    checkpoint_path=checkpoint,
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                )
            self.assertFalse(state.exists())
            self.assertNotIn("vulnerabilities", checkpoint.read_text(encoding="utf-8"))
            second_transport = SequenceTransport(
                [response(nvd_page([second], start=1, total=2, page_size=1, timestamp="2026-08-29T00:00:01.000Z"))]
            )
            activated = NvdPipeline(client(second_transport)).run(
                operation,
                checkpoint_path=checkpoint,
                state_path=state,
                retrieved_at=NOW,
                builder_source_revision=BUILDER_REVISION,
            )
            self.assertEqual(activated["known_cve_ids"], ["CVE-2025-1001", "CVE-2025-1002"])
            self.assertEqual(set(activated["source_snapshot"]), set(PolicyGate.load().contract["tables"]["source_snapshots"]))
            self.assertEqual(len(activated["acquisition_evidence"]["final_urls"]), 2)
            self.assertTrue(
                all(url.startswith(NVD_URL) for url in activated["acquisition_evidence"]["final_urls"])
            )
            self.assertEqual(activated, json.loads(state.read_text(encoding="utf-8")))
            self.assertFalse(checkpoint.exists())
            self.assertEqual(list(Path(directory).glob("*.staging")), [])
            self.assertNotIn("Excluded synthetic description", state.read_text(encoding="utf-8"))

            repeat_transport = SequenceTransport(
                [
                    response(nvd_page([FIXTURES["nvd_records"]["rich_updated"]], total=2, page_size=1)),
                    response(nvd_page([second], start=1, total=2, page_size=1)),
                ]
            )
            repeated = NvdPipeline(client(repeat_transport)).run(
                operation,
                checkpoint_path=checkpoint,
                state_path=state,
                retrieved_at=NOW + timedelta(days=1),
                builder_source_revision=BUILDER_REVISION,
            )
            self.assertEqual(len(repeat_transport.urls), 2)
            self.assertNotEqual(repeated["source_snapshot"], activated["source_snapshot"])

    def test_pipeline_rejects_duplicate_cves_across_pages_before_activation(self):
        rich = FIXTURES["nvd_records"]["rich"]
        transport = SequenceTransport(
            [
                response(nvd_page([rich], total=2, page_size=1)),
                response(nvd_page([rich], start=1, total=2, page_size=1)),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "nvd-state.json"
            with self.assertRaisesRegex(SchemaDrift, "repeated CVE IDs"):
                NvdPipeline(client(transport)).run(
                    NvdOperation(mode="full", results_per_page=1),
                    checkpoint_path=Path(directory) / "nvd-checkpoint.json",
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                )
            self.assertFalse(state.exists())

    def test_page_application_recovers_exactly_from_both_atomic_crash_boundaries(self):
        rich = FIXTURES["nvd_records"]["rich"]
        second = FIXTURES["nvd_records"]["second"]
        operation = NvdOperation(mode="full", results_per_page=1)
        for crash_stage in ("after_staging_write", "after_checkpoint_write"):
            with self.subTest(crash_stage=crash_stage), tempfile.TemporaryDirectory() as directory:
                checkpoint = Path(directory) / "checkpoint.json"
                state = Path(directory) / "state.json"
                crashed = False

                def inject(stage):
                    nonlocal crashed
                    if stage == crash_stage and not crashed:
                        crashed = True
                        raise RuntimeError(f"injected {stage}")

                with self.assertRaisesRegex(RuntimeError, crash_stage):
                    NvdPipeline(
                        client(SequenceTransport([response(nvd_page([rich], total=2, page_size=1))]))
                    ).run(
                        operation,
                        checkpoint_path=checkpoint,
                        state_path=state,
                        retrieved_at=NOW,
                        builder_source_revision=BUILDER_REVISION,
                        crash_hook=inject,
                    )
                self.assertFalse(state.exists())
                restart_responses = [response(nvd_page([second], start=1, total=2, page_size=1))]
                if crash_stage == "after_staging_write":
                    restart_responses.insert(0, response(nvd_page([rich], total=2, page_size=1)))
                recovered = NvdPipeline(client(SequenceTransport(restart_responses))).run(
                    operation,
                    checkpoint_path=checkpoint,
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                )
                self.assertEqual(recovered["known_cve_ids"], ["CVE-2025-1001", "CVE-2025-1002"])

    def test_forged_complete_checkpoint_and_staging_never_activate_without_validation(self):
        rich = FIXTURES["nvd_records"]["rich"]
        operation = NvdOperation(mode="full", results_per_page=1)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            state = Path(directory) / "state.json"

            def crash_after_checkpoint(stage):
                if stage == "after_checkpoint_write":
                    raise RuntimeError("injected complete checkpoint crash")

            with self.assertRaisesRegex(RuntimeError, "complete checkpoint"):
                NvdPipeline(
                    client(SequenceTransport([response(nvd_page([rich], page_size=1))]))
                ).run(
                    operation,
                    checkpoint_path=checkpoint,
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                    crash_hook=crash_after_checkpoint,
                )
            staging_path = next(Path(directory).glob("*.staging"))
            staging = json.loads(staging_path.read_text(encoding="utf-8"))
            staging["pending_page"]["result_state"]["known_cve_ids"] = ["CVE-2025-9999"]
            forged_seal = sha256(
                canonical_json(staging["pending_page"]["result_state"])
            ).hexdigest()
            staging["pending_page"]["result_state_sha256"] = forged_seal
            staging_path.write_text(json.dumps(staging), encoding="utf-8")
            forged_checkpoint = json.loads(checkpoint.read_text(encoding="utf-8"))
            forged_checkpoint["normalized_state_sha256"] = forged_seal
            forged_checkpoint["staging_commit_sha256"] = sha256(
                canonical_json(
                    {
                        "format": "patch8-p4-nvd-staging-v2",
                        "operation_id": forged_checkpoint["operation_id"],
                        "accepted_cve_ids": sorted(
                            cve_id
                            for page in forged_checkpoint["applied_pages"]
                            for cve_id in page["cve_ids"]
                        ),
                        "committed_pages": forged_checkpoint["applied_pages"],
                        "normalized_state_sha256": forged_seal,
                    }
                )
            ).hexdigest()
            checkpoint.write_text(json.dumps(forged_checkpoint), encoding="utf-8")

            transport = SequenceTransport([])
            with self.assertRaisesRegex(SchemaDrift, "known CVE identities"):
                NvdPipeline(client(transport)).run(
                    operation,
                    checkpoint_path=checkpoint,
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                )
            self.assertEqual(transport.urls, [])
            self.assertFalse(state.exists())

    def test_pipeline_applies_exact_overlapping_modified_window_to_prior_state(self):
        rich = FIXTURES["nvd_records"]["rich"]
        updated = FIXTURES["nvd_records"]["rich_updated"]
        second = FIXTURES["nvd_records"]["second"]
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "nvd-state.json"
            full_transport = SequenceTransport([response(nvd_page([rich, second], page_size=2))])
            NvdPipeline(client(full_transport)).run(
                NvdOperation(mode="full", results_per_page=2),
                checkpoint_path=Path(directory) / "full-checkpoint.json",
                state_path=state,
                retrieved_at=NOW,
                builder_source_revision=BUILDER_REVISION,
            )
            operation = next_delta_operation(NOW, NOW + timedelta(days=1), results_per_page=2)
            delta_transport = SequenceTransport([response(nvd_page([updated], page_size=2))])
            actual = NvdPipeline(client(delta_transport)).run(
                operation,
                checkpoint_path=Path(directory) / "delta-checkpoint.json",
                state_path=state,
                retrieved_at=NOW + timedelta(days=1),
                builder_source_revision=BUILDER_REVISION,
            )
            clean = merge_nvd_state(
                None,
                normalize_nvd_vulnerabilities([deepcopy(updated), deepcopy(second)]),
                mode="full",
            )
            for key in (*clean.keys(),):
                self.assertEqual(actual[key], clean[key])
            self.assertIn("lastModStartDate=2026-08-28T22%3A00%3A00.000000Z", delta_transport.urls[0])
            self.assertNotIn("includeMatchStringChange", delta_transport.urls[0])
            self.assertEqual(actual["source_snapshot"]["last_successful_watermark"], "2026-08-30T00:00:00.000000Z")


class WatermarkTests(unittest.TestCase):
    def test_delta_uses_exact_overlap_and_current_last_modified_parameters(self):
        last = datetime(2026, 8, 28, 12, tzinfo=UTC)
        operation = next_delta_operation(last, datetime(2026, 8, 29, 12, tzinfo=UTC), results_per_page=100)
        assert_contiguous_window(operation, last)
        url = operation.url(0)
        self.assertNotIn("includeMatchStringChange", url)
        self.assertIn("lastModStartDate=2026-08-28T10%3A00%3A00.000000Z", url)
        self.assertIn("lastModEndDate=2026-08-29T12%3A00%3A00.000000Z", url)

    def test_gap_insufficient_overlap_and_non_advancing_windows_fail(self):
        last = datetime(2026, 8, 28, 12, tzinfo=UTC)
        gap = NvdOperation(
            mode="modified",
            results_per_page=100,
            window_start=last - timedelta(hours=1),
            window_end=last + timedelta(hours=1),
        )
        with self.assertRaisesRegex(WatermarkError, "exact reviewed overlap"):
            assert_contiguous_window(gap, last)
        with self.assertRaises(WatermarkError):
            next_delta_operation(last, last)
        with self.assertRaises(WatermarkError):
            NvdOperation(
                mode="modified",
                results_per_page=100,
                window_start=last - timedelta(days=121),
                window_end=last,
            )

    def test_complete_reconciliation_clock_is_durable_and_deltas_cannot_reset_it(self):
        rich = FIXTURES["nvd_records"]["rich"]
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            pipeline = NvdPipeline(
                client(SequenceTransport([response(nvd_page([rich], page_size=1))]))
            )
            full = pipeline.run(
                NvdOperation(mode="full", results_per_page=1),
                checkpoint_path=Path(directory) / "full.json",
                state_path=state,
                retrieved_at=NOW,
                builder_source_revision=BUILDER_REVISION,
            )
            self.assertEqual(
                nvd_full_reconciliation_status(full, observed_at=NOW)["status"],
                "current",
            )
            original_full = deepcopy(full["full_reconciliation"])
            delta_end = NOW + timedelta(days=1)
            delta = NvdPipeline(
                client(SequenceTransport([response(nvd_page([rich], page_size=1))]))
            ).run(
                next_delta_operation(NOW, delta_end, results_per_page=1),
                checkpoint_path=Path(directory) / "delta.json",
                state_path=state,
                retrieved_at=delta_end,
                builder_source_revision=BUILDER_REVISION,
            )
            self.assertEqual(delta["full_reconciliation"], original_full)

            overdue_transport = SequenceTransport([])
            with self.assertRaisesRegex(FullReconciliationRequired, "complete NVD reconciliation"):
                NvdPipeline(client(overdue_transport)).run(
                    next_delta_operation(delta_end, NOW + timedelta(days=8), results_per_page=1),
                    checkpoint_path=Path(directory) / "overdue.json",
                    state_path=state,
                    retrieved_at=NOW + timedelta(days=8),
                    builder_source_revision=BUILDER_REVISION,
                )
            self.assertEqual(overdue_transport.urls, [])
            self.assertEqual(
                nvd_full_reconciliation_status(delta, observed_at=NOW + timedelta(days=8))["status"],
                "stale",
            )

    def test_successful_full_resets_clock_while_failed_full_leaves_overdue_state_blocked(self):
        rich = FIXTURES["nvd_records"]["rich"]
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            checkpoint = Path(directory) / "checkpoint.json"
            first = NvdPipeline(
                client(SequenceTransport([response(nvd_page([rich], page_size=1))]))
            ).run(
                NvdOperation(mode="full", results_per_page=1),
                checkpoint_path=checkpoint,
                state_path=state,
                retrieved_at=NOW,
                builder_source_revision=BUILDER_REVISION,
            )
            refreshed_at = NOW + timedelta(days=8)
            refreshed = NvdPipeline(
                client(SequenceTransport([response(nvd_page([rich], page_size=1))]))
            ).run(
                NvdOperation(mode="full", results_per_page=1),
                checkpoint_path=checkpoint,
                state_path=state,
                retrieved_at=refreshed_at,
                builder_source_revision=BUILDER_REVISION,
            )
            self.assertNotEqual(refreshed["full_reconciliation"], first["full_reconciliation"])
            before_failure = state.read_bytes()
            with self.assertRaisesRegex(IngestionError, "HTTP 500"):
                NvdPipeline(client(SequenceTransport([response({}, status=500)]))).run(
                    NvdOperation(mode="full", results_per_page=1),
                    checkpoint_path=checkpoint,
                    state_path=state,
                    retrieved_at=refreshed_at + timedelta(days=8),
                    builder_source_revision=BUILDER_REVISION,
                )
            self.assertEqual(state.read_bytes(), before_failure)
            last_watermark = datetime.fromisoformat(
                refreshed["source_snapshot"]["last_successful_watermark"].replace("Z", "+00:00")
            )
            with self.assertRaises(FullReconciliationRequired):
                NvdPipeline(client(SequenceTransport([]))).run(
                    next_delta_operation(
                        last_watermark,
                        refreshed_at + timedelta(days=8),
                        results_per_page=1,
                    ),
                    checkpoint_path=Path(directory) / "blocked-delta.json",
                    state_path=state,
                    retrieved_at=refreshed_at + timedelta(days=8),
                    builder_source_revision=BUILDER_REVISION,
                )


class CveProgramTests(unittest.TestCase):
    commit = "a" * 40

    def test_record_emits_only_exact_metadata_and_english_cna_observations(self):
        record = CVELIST_FIXTURES["published"]
        source_bytes = canonical_json(record)
        record_path = cvelist_record_path(record)
        normalized = normalize_cve_program_record(source_bytes, record_path=record_path)
        self.assertEqual(normalized["cve_id"], "CVE-2026-0005")
        metadata = normalized["metadata"]
        self.assertEqual(metadata["source_id"], "patch8_cvelist_v5")
        self.assertEqual(metadata["record_state"], "PUBLISHED")
        self.assertEqual(metadata["provider_short_name"], "synthetic-cna")
        self.assertEqual(
            [row["lang"] for row in normalized["descriptions"]],
            ["en", "en-AU"],
        )
        self.assertEqual(
            normalized["selected_description_observation_id"],
            normalized["descriptions"][0]["observation_id"],
        )
        serialized = canonical_json(normalized)
        self.assertNotIn(b"Excluded media", serialized)
        self.assertNotIn(b"Excluded vendor", serialized)
        self.assertNotIn(b"Excluded ADP", serialized)
        self.assertNotIn(b"Description synthetique", serialized)
        for provenance in normalized["provenance"]:
            self.assertEqual(provenance["endpoint_or_repository"], CVELIST_REPOSITORY)
            self.assertEqual(provenance["source_record_path"], record_path)
            self.assertEqual(provenance["source_record_sha256"], sha256(source_bytes).hexdigest())
            self.assertEqual(provenance["source_record_bytes"], len(source_bytes))
            self.assertEqual(provenance["required_notice_ids"], ["notice.cve_program"])
            self.assertNotIn("cve.descriptions", provenance["source_field_rule"])

    def test_record_rejects_wrong_source_shape_schema_path_state_and_provider_lineage(self):
        published = CVELIST_FIXTURES["published"]
        cases = []
        wrong_version = deepcopy(published)
        wrong_version["dataVersion"] = "6.0"
        cases.append((wrong_version, cvelist_record_path(wrong_version), SchemaDrift))
        missing_provider = deepcopy(published)
        del missing_provider["containers"]["cna"]["providerMetadata"]
        cases.append((missing_provider, cvelist_record_path(missing_provider), SchemaDrift))
        provider_drift = deepcopy(published)
        provider_drift["containers"]["cna"]["providerMetadata"]["orgId"] = "other-provider"
        cases.append((provider_drift, cvelist_record_path(provider_drift), SchemaDrift))
        cases.append((published, "cves/2026/9xxx/CVE-2026-0005.json", SchemaDrift))
        cases.append((CVELIST_FIXTURES["rejected"], cvelist_record_path(CVELIST_FIXTURES["rejected"]), RejectedCveRecord))
        cases.append((FIXTURES["nvd_records"]["rich"], "cves/2026/1xxx/CVE-2026-1001.json", SchemaDrift))
        for record, path, error in cases:
            with self.subTest(path=path, error=error):
                with self.assertRaises(error):
                    normalize_cve_program_record(canonical_json(record), record_path=path)
        with self.assertRaises(SchemaDrift):
            normalize_cve_program_record(b"", record_path="cves/2026/1xxx/CVE-2026-1001.json")
        with self.assertRaisesRegex(IngestionError, "not allowed"):
            PolicyGate.load().authorize("patch8_cvelist_v5", ["cveMetadata.dateReserved"])

    def test_archive_is_bounded_safe_deterministic_and_excludes_rejected_records(self):
        records = [
            CVELIST_FIXTURES["second"],
            CVELIST_FIXTURES["rejected"],
            CVELIST_FIXTURES["published"],
        ]
        archive_bytes = cvelist_archive(records, self.commit)
        first = normalize_cve_program_archive(archive_bytes, commit=self.commit)
        second = normalize_cve_program_archive(archive_bytes, commit=self.commit)
        self.assertEqual(first, second)
        self.assertEqual(first["known_cve_ids"], ["CVE-2026-0005", "CVE-2026-1002"])
        self.assertEqual(len(first["cve_metadata_observations"]), 2)
        self.assertEqual(len(first["descriptions"]), 3)
        selected = first["selected_description_observation_ids"]["CVE-2026-0005"]
        self.assertEqual(
            next(row for row in first["descriptions"] if row["observation_id"] == selected)["lang"],
            "en",
        )
        self.assertNotIn("CVE-2026-1003", canonical_json(first).decode())
        with self.assertRaisesRegex(BudgetExceeded, "record-count"):
            normalize_cve_program_archive(
                archive_bytes,
                commit=self.commit,
                limits=CveProgramLimits(max_records=1),
            )
        with self.assertRaisesRegex(BudgetExceeded, "record-size"):
            normalize_cve_program_archive(
                archive_bytes,
                commit=self.commit,
                limits=CveProgramLimits(max_record_bytes=10),
            )
        with self.assertRaisesRegex(BudgetExceeded, "expanded-byte"):
            normalize_cve_program_archive(
                archive_bytes,
                commit=self.commit,
                limits=CveProgramLimits(max_expanded_bytes=10),
            )
        unsafe = cvelist_archive(
            [CVELIST_FIXTURES["published"]],
            self.commit,
            paths=["cves/2026/1xxx/../../escape.json"],
        )
        with self.assertRaisesRegex(SchemaDrift, "unsafe"):
            normalize_cve_program_archive(unsafe, commit=self.commit)
        commit_drift = cvelist_archive([CVELIST_FIXTURES["published"]], "b" * 40)
        with self.assertRaisesRegex(SchemaDrift, "unexpected path"):
            normalize_cve_program_archive(commit_drift, commit=self.commit)

        clock = FakeClock()

        def consume_deadline(_stage):
            clock.now += 0.6
            if clock.now > 1:
                raise BudgetExceeded("CVE Program operation deadline exceeded")

        with self.assertRaisesRegex(BudgetExceeded, "deadline"):
            normalize_cve_program_archive(
                archive_bytes,
                commit=self.commit,
                check_deadline=consume_deadline,
            )

    def test_archive_counts_ignored_regular_bytes_before_path_filtering(self):
        prefix = f"cvelistV5-{self.commit}/"
        archive_bytes = cvelist_archive(
            [CVELIST_FIXTURES["published"]],
            self.commit,
            extra_members=[
                archive_member(prefix + "docs/ignored.bin", data=b"x" * 1_000_000)
            ],
        )
        with self.assertRaisesRegex(BudgetExceeded, "expanded-byte"):
            normalize_cve_program_archive(
                archive_bytes,
                commit=self.commit,
                limits=CveProgramLimits(max_expanded_bytes=999_999),
            )

    def test_archive_counts_ignored_directories_before_path_filtering(self):
        prefix = f"cvelistV5-{self.commit}/"
        ignored_directories = [
            archive_member(prefix + f"docs/{index}", member_type=tarfile.DIRTYPE)
            for index in range(2_000)
        ]
        archive_bytes = cvelist_archive(
            [CVELIST_FIXTURES["published"]],
            self.commit,
            extra_members=ignored_directories,
        )
        with self.assertRaisesRegex(BudgetExceeded, "archive-member"):
            normalize_cve_program_archive(
                archive_bytes,
                commit=self.commit,
                limits=CveProgramLimits(max_members=1_999),
            )

    def test_archive_rejects_unsafe_links_and_sibling_member_types_anywhere(self):
        prefix = f"cvelistV5-{self.commit}/"
        unsafe_link = archive_member(
            prefix + "docs/link",
            member_type=tarfile.SYMTYPE,
            linkname="../../outside",
        )
        with self.assertRaisesRegex(SchemaDrift, "unsafe link target"):
            normalize_cve_program_archive(
                cvelist_archive(
                    [CVELIST_FIXTURES["published"]],
                    self.commit,
                    extra_members=[unsafe_link],
                ),
                commit=self.commit,
            )
        sibling_types = [
            (tarfile.LNKTYPE, prefix + "docs/target"),
            (tarfile.CHRTYPE, ""),
            (tarfile.BLKTYPE, ""),
            (tarfile.FIFOTYPE, ""),
            (tarfile.CONTTYPE, ""),
            (tarfile.GNUTYPE_SPARSE, ""),
        ]
        for member_type, linkname in sibling_types:
            with self.subTest(member_type=member_type):
                unsafe_member = archive_member(
                    prefix + "docs/unsafe",
                    member_type=member_type,
                    linkname=linkname,
                )
                with self.assertRaisesRegex(SchemaDrift, "unsupported"):
                    normalize_cve_program_archive(
                        cvelist_archive(
                            [CVELIST_FIXTURES["published"]],
                            self.commit,
                            extra_members=[unsafe_member],
                        ),
                        commit=self.commit,
                    )
        pax_sparse, sparse_payload = archive_member(
            prefix + "docs/sparse.bin",
            data=b"x",
        )
        pax_sparse.pax_headers = {
            "GNU.sparse.map": "0,1",
            "GNU.sparse.size": "1000000",
        }
        with self.assertRaisesRegex(SchemaDrift, "unsupported sparse"):
            normalize_cve_program_archive(
                cvelist_archive(
                    [CVELIST_FIXTURES["published"]],
                    self.commit,
                    extra_members=[(pax_sparse, sparse_payload)],
                    tar_format=tarfile.PAX_FORMAT,
                ),
                commit=self.commit,
            )

    def test_archive_allows_safe_ordinary_metadata_and_rejects_backslash_paths(self):
        prefix = f"cvelistV5-{self.commit}/"
        record_only = normalize_cve_program_archive(
            cvelist_archive([CVELIST_FIXTURES["published"]], self.commit),
            commit=self.commit,
        )
        safe_archive = cvelist_archive(
            [CVELIST_FIXTURES["published"]],
            self.commit,
            extra_members=[
                archive_member(prefix.rstrip("/"), member_type=tarfile.DIRTYPE),
                archive_member(prefix + "docs", member_type=tarfile.DIRTYPE),
                archive_member(
                    prefix + "docs/README.md",
                    data=b"metadata\n",
                    member_type=tarfile.AREGTYPE,
                ),
            ],
        )
        self.assertEqual(
            normalize_cve_program_archive(safe_archive, commit=self.commit),
            record_only,
        )
        backslash_archive = cvelist_archive(
            [CVELIST_FIXTURES["published"]],
            self.commit,
            extra_members=[archive_member(prefix + "docs\\escape", data=b"x")],
        )
        with self.assertRaisesRegex(SchemaDrift, "unsafe member path"):
            normalize_cve_program_archive(backslash_archive, commit=self.commit)

    def test_pipeline_records_exact_commit_and_is_repeat_build_deterministic(self):
        self.assertEqual(CVELIST_VERIFIED_COMMIT, "10c6b415a7a12a0c0fab006359939fcd34e2c78f")
        records = [CVELIST_FIXTURES["published"], CVELIST_FIXTURES["second"]]
        archive_bytes = cvelist_archive(records, self.commit)
        url = cvelist_archive_url(self.commit)
        response_value = JsonResponse(
            body=archive_bytes,
            headers={"etag": '"synthetic"', "last-modified": "Sat, 29 Aug 2026 00:00:00 GMT"},
            final_url=url,
        )
        with tempfile.TemporaryDirectory() as directory:
            first_path = Path(directory) / "first.json"
            second_path = Path(directory) / "second.json"
            first = CveProgramPipeline(client(SequenceTransport([response_value]))).run(
                commit=self.commit,
                state_path=first_path,
                retrieved_at=NOW,
                builder_source_revision=BUILDER_REVISION,
            )
            second = CveProgramPipeline(client(SequenceTransport([response_value]))).run(
                commit=self.commit,
                state_path=second_path,
                retrieved_at=NOW,
                builder_source_revision=BUILDER_REVISION,
            )
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            self.assertEqual(first, second)
            self.assertEqual(first["source_snapshot"]["immutable_revision"], self.commit)
            self.assertEqual(first["source_snapshot"]["last_successful_watermark"], self.commit)
            self.assertEqual(first["source_snapshot"]["complete_input_sha256"], sha256(archive_bytes).hexdigest())
            self.assertEqual(first["acquisition_evidence"]["archive_url"], url)
            self.assertEqual(first["acquisition_evidence"]["final_url"], url)

    def test_pipeline_rejects_commit_origin_redirect_byte_time_and_forged_restart_state(self):
        archive_bytes = cvelist_archive([CVELIST_FIXTURES["published"]], self.commit)
        url = cvelist_archive_url(self.commit)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            with self.assertRaisesRegex(IngestionError, "archive URL"):
                CveProgramPipeline(client(SequenceTransport([]))).run(
                    commit=self.commit,
                    archive_url=cvelist_archive_url("b" * 40),
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                )
            redirected = JsonResponse(
                body=archive_bytes,
                headers={},
                final_url="https://example.invalid/cvelist.tar.gz",
            )
            with self.assertRaisesRegex(IngestionError, "final response URL"):
                CveProgramPipeline(client(SequenceTransport([redirected]))).run(
                    commit=self.commit,
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                )
            with self.assertRaisesRegex(BudgetExceeded, "byte"):
                CveProgramPipeline(
                    client(SequenceTransport([JsonResponse(body=archive_bytes, headers={})]), max_bytes=10)
                ).run(
                    commit=self.commit,
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                )

            crashed = CveProgramPipeline(
                client(SequenceTransport([JsonResponse(body=archive_bytes, headers={}, final_url=url)]))
            )
            with self.assertRaisesRegex(RuntimeError, "staging"):
                crashed.run(
                    commit=self.commit,
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                    crash_hook=lambda stage: (_ for _ in ()).throw(RuntimeError(stage)),
                )
            self.assertFalse(state.exists())
            staging_path = next(Path(directory).glob("*.staging"))
            forged = json.loads(staging_path.read_text(encoding="utf-8"))
            forged["normalized"]["known_cve_ids"] = ["CVE-2026-9999"]
            forged_values = {key: value for key, value in forged.items() if key != "staging_sha256"}
            forged["normalized_sha256"] = sha256(canonical_json(forged["normalized"])).hexdigest()
            forged_values["normalized_sha256"] = forged["normalized_sha256"]
            forged["staging_sha256"] = sha256(canonical_json(forged_values)).hexdigest()
            staging_path.write_text(json.dumps(forged), encoding="utf-8")
            with self.assertRaisesRegex(SchemaDrift, "restart state"):
                CveProgramPipeline(
                    client(SequenceTransport([JsonResponse(body=archive_bytes, headers={}, final_url=url)]))
                ).run(
                    commit=self.commit,
                    state_path=state,
                    retrieved_at=NOW,
                    builder_source_revision=BUILDER_REVISION,
                )
            self.assertFalse(state.exists())


class KevTests(unittest.TestCase):
    def normalize(self, name):
        return normalize_kev_snapshot(
            canonical_json(deepcopy(FIXTURES[name])),
            retrieved_at=NOW,
            builder_source_revision=BUILDER_REVISION,
        )

    def test_complete_snapshot_is_deterministic_and_has_field_provenance(self):
        first = self.normalize("kev_initial")
        second = self.normalize("kev_initial")
        self.assertEqual(first, second)
        self.assertTrue(first["complete"])
        self.assertEqual(len(first["kev_observations"]), 2)
        self.assertEqual(len(first["provenance"]), 2)
        self.assertEqual(
            first["source_snapshot"]["complete_input_sha256"],
            sha256(canonical_json(FIXTURES["kev_initial"])).hexdigest(),
        )
        self.assertEqual(first["provenance"][0]["required_notice_ids"], ["notice.cisa_kev"])
        self.assertNotIn("title", first["kev_observations"][0])
        contract = PolicyGate.load().contract
        self.assertEqual(set(first["kev_observations"][0]), set(contract["tables"]["kev_observations"]))
        self.assertEqual(set(first["provenance"][0]), set(contract["tables"]["provenance"]))
        self.assertEqual(set(first["source_snapshot"]), set(contract["tables"]["source_snapshots"]))

    def test_cwes_are_validated_deduplicated_numerically_sorted_and_rows_are_newest_first(self):
        payload = deepcopy(FIXTURES["kev_initial"])
        payload["vulnerabilities"][0]["cwes"] = ["CWE-79", "CWE-10", "CWE-79"]
        normalized = normalize_kev_snapshot(
            canonical_json(payload),
            retrieved_at=NOW,
            builder_source_revision=BUILDER_REVISION,
        )
        by_cve = {row["cve_id"]: row for row in normalized["kev_observations"]}
        self.assertEqual(by_cve["CVE-2025-1001"]["cwe_ids"], ["CWE-10", "CWE-79"])
        dates = [row["date_added"] for row in normalized["kev_observations"]]
        self.assertEqual(dates, sorted(dates, reverse=True))

    def test_pipeline_activates_complete_snapshot_and_failed_refresh_preserves_state(self):
        initial_bytes = canonical_json(FIXTURES["kev_initial"])
        malformed = deepcopy(FIXTURES["kev_updated"])
        malformed["count"] = 99
        transport = SequenceTransport([JsonResponse(initial_bytes, {}), response(malformed)])
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "kev-state.json"
            pipeline = KevPipeline(client(transport))
            activated = pipeline.run(
                source_url=KEV_URL,
                state_path=state_path,
                retrieved_at=NOW,
                builder_source_revision=BUILDER_REVISION,
            )
            before = state_path.read_bytes()
            self.assertEqual(activated, json.loads(before))
            self.assertEqual(activated["acquisition_evidence"]["final_url"], KEV_URL)
            with self.assertRaises(SchemaDrift):
                pipeline.run(
                    source_url=KEV_URL,
                    state_path=state_path,
                    retrieved_at=NOW + timedelta(days=1),
                    builder_source_revision=BUILDER_REVISION,
                )
            self.assertEqual(state_path.read_bytes(), before)

    def test_unchanged_entry_identity_survives_catalog_release(self):
        later = deepcopy(FIXTURES["kev_initial"])
        later["catalogVersion"] = "2026.08.29"
        later["dateReleased"] = "2026-08-29T00:00:00Z"
        initial = self.normalize("kev_initial")
        updated = normalize_kev_snapshot(
            canonical_json(later),
            retrieved_at=NOW + timedelta(days=1),
            builder_source_revision=BUILDER_REVISION,
        )
        self.assertEqual(
            [(row["observation_id"], row["provenance_id"]) for row in initial["kev_observations"]],
            [(row["observation_id"], row["provenance_id"]) for row in updated["kev_observations"]],
        )
        self.assertNotEqual(initial["source_snapshot"], updated["source_snapshot"])

    def test_repository_snapshot_records_the_exact_immutable_revision_and_source_bytes(self):
        revision = "a" * 40
        url = f"https://raw.githubusercontent.com/cisagov/kev-data/{revision}/known_exploited_vulnerabilities.json"
        source_bytes = canonical_json(FIXTURES["kev_initial"])
        normalized = normalize_kev_snapshot(
            source_bytes,
            retrieved_at=NOW,
            builder_source_revision=BUILDER_REVISION,
            endpoint_or_repository=url,
        )
        self.assertEqual(normalized["source_snapshot"]["immutable_revision"], revision)
        self.assertEqual(normalized["source_snapshot"]["complete_input_bytes"], len(source_bytes))
        self.assertEqual(normalized["source_snapshot"]["endpoint_or_repository"], url)

    def test_add_edit_remove_and_unknown_membership_semantics(self):
        initial = reconcile_kev(None, self.normalize("kev_initial"), observed_at=NOW)
        updated = reconcile_kev(initial, self.normalize("kev_updated"), observed_at=NOW + timedelta(days=1))
        self.assertEqual(
            [(item["cve_id"], item["change_type"]) for item in updated["changes"]],
            [("CVE-2025-1001", "removed"), ("CVE-2025-1002", "edited"), ("CVE-2025-1003", "added")],
        )
        self.assertEqual(kev_membership(None, "CVE-2025-1001")["kev_status"], "unknown")
        self.assertEqual(kev_membership(updated, "CVE-2025-1001")["kev_status"], "not_listed")
        self.assertEqual(kev_membership(updated, "CVE-2025-1003")["kev_status"], "listed")

    def test_clean_snapshot_and_reconciled_delta_have_identical_current_rows(self):
        initial = reconcile_kev(None, self.normalize("kev_initial"), observed_at=NOW)
        delta = reconcile_kev(initial, self.normalize("kev_updated"), observed_at=NOW + timedelta(days=1))
        clean = reconcile_kev(None, self.normalize("kev_updated"), observed_at=NOW + timedelta(days=1))
        self.assertEqual(delta["kev_observations"], clean["kev_observations"])
        self.assertEqual(delta["provenance"], clean["provenance"])
        self.assertEqual(delta["source_snapshot"], clean["source_snapshot"])

    def test_malformed_count_duplicate_unknown_field_and_cwe_are_rejected(self):
        count = deepcopy(FIXTURES["kev_initial"])
        count["count"] = 3
        duplicate = deepcopy(FIXTURES["kev_initial"])
        duplicate["vulnerabilities"][1]["cveID"] = "CVE-2025-1001"
        unknown = deepcopy(FIXTURES["kev_initial"])
        unknown["vulnerabilities"][0]["cvss"] = 10
        cwe = deepcopy(FIXTURES["kev_initial"])
        cwe["vulnerabilities"][0]["cwes"] = ["NVD-CWE-noinfo"]
        for payload in (count, duplicate, unknown, cwe):
            with self.subTest(payload=payload):
                with self.assertRaises(SchemaDrift):
                    normalize_kev_snapshot(
                        canonical_json(payload),
                        retrieved_at=NOW,
                        builder_source_revision=BUILDER_REVISION,
                    )

    def test_incomplete_snapshot_cannot_remove_or_claim_not_listed(self):
        incomplete = {"complete": False, "kev_observations": []}
        with self.assertRaisesRegex(IngestionError, "incomplete"):
            reconcile_kev(self.normalize("kev_initial"), incomplete, observed_at=NOW)
        self.assertEqual(kev_membership(incomplete, "CVE-2025-1001")["kev_status"], "unknown")

    def test_only_official_immutable_kev_repository_urls_are_accepted(self):
        revision = "a" * 40
        self.assertEqual(
            require_immutable_kev_repository_url(
                f"https://raw.githubusercontent.com/cisagov/kev-data/{revision}/known_exploited_vulnerabilities.json"
            ),
            revision,
        )
        for url in (
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
            f"https://raw.githubusercontent.com/other/kev-data/{revision}/known_exploited_vulnerabilities.json",
            "http://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ):
            with self.subTest(url=url):
                with self.assertRaises(IngestionError):
                    require_immutable_kev_repository_url(url)


if __name__ == "__main__":
    unittest.main()
