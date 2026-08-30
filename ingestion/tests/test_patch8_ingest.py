from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from ingestion.patch8_ingest import (
    BoundedJsonClient,
    BudgetExceeded,
    FetchLimits,
    IngestionError,
    JsonResponse,
    KEV_URL,
    KevPipeline,
    NVD_URL,
    NvdOperation,
    NvdPager,
    NvdPipeline,
    PolicyGate,
    SchemaDrift,
    Throttled,
    WatermarkError,
    assert_contiguous_window,
    canonical_json,
    kev_membership,
    next_delta_operation,
    merge_nvd_state,
    normalize_kev_snapshot,
    normalize_nvd_vulnerabilities,
    reconcile_kev,
    require_immutable_kev_repository_url,
    validate_nvd_page,
)


FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "p4-cases.json").read_text(encoding="utf-8")
)
NOW = datetime(2026, 8, 29, tzinfo=UTC)
BUILDER_REVISION = "1" * 40


class SequenceTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []
        self.timeouts = []

    def get(self, url, headers, *, timeout_seconds):
        self.urls.append(url)
        self.timeouts.append(timeout_seconds)
        if not self.responses:
            raise AssertionError("unexpected request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


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
                lambda rows, start: accepted.extend((start, row["cve"]["id"]) for row in rows),
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
                    lambda rows, start: accepted.extend(row["cve"]["id"] for row in rows),
                )
            stored_text = checkpoint.read_text(encoding="utf-8")
            self.assertNotIn("vulnerabilities", stored_text)
            self.assertEqual(json.loads(stored_text)["next_start_index"], 2)
            second = SequenceTransport([response(FIXTURES["nvd_pages"]["2"])])
            result = NvdPager(client(second)).run(
                operation,
                checkpoint,
                lambda rows, start: accepted.extend(row["cve"]["id"] for row in rows),
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
                    NvdOperation(mode="full", results_per_page=2), checkpoint, lambda rows, start: None
                )

    def test_page_budget_stops_before_an_extra_request(self):
        transport = SequenceTransport([response(FIXTURES["nvd_pages"]["0"])])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(BudgetExceeded, "page budget"):
                NvdPager(client(transport, max_pages=1)).run(
                    NvdOperation(mode="full", results_per_page=2),
                    Path(directory) / "nvd.json",
                    lambda rows, start: None,
                )
        self.assertEqual(len(transport.urls), 1)

    def test_request_and_byte_budgets_fail_closed(self):
        transport = SequenceTransport([response(FIXTURES["nvd_pages"]["0"])])
        bounded = client(transport, max_bytes=8)
        with self.assertRaisesRegex(BudgetExceeded, "byte"):
            bounded.get(f"{NVD_URL}?startIndex=0", expected_url=NVD_URL)
        self.assertEqual(transport.timeouts, [1])
        request_client = client(SequenceTransport([response({})]), max_requests=1)
        request_client.get(f"{NVD_URL}?startIndex=0", expected_url=NVD_URL)
        with self.assertRaisesRegex(BudgetExceeded, "request"):
            request_client.get(f"{NVD_URL}?startIndex=1", expected_url=NVD_URL)

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
        changed_total = deepcopy(FIXTURES["nvd_pages"]["2"])
        changed_total["totalResults"] = 4
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SchemaDrift, "totalResults changed"):
                NvdPager(
                    client(SequenceTransport([response(FIXTURES["nvd_pages"]["0"]), response(changed_total)]))
                ).run(
                    NvdOperation(mode="full", results_per_page=2),
                    Path(directory) / "nvd.json",
                    lambda rows, start: None,
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
