# Patch8 v1 data-content contract

Status: **authoritative source-complete design; implementation and publication not started**

Approved: 2026-08-29

This document defines the data that a Patch8 v1 release may contain and the legacy capabilities that data may power.
It is normative for P3 and later work. If an implementation, fixture, manifest, route, or older document disagrees with
this contract, this contract wins unless a later approved feature explicitly replaces it.

This is a content and routing contract, not an ingestion implementation, a published dataset claim, or legal advice.
The restored legacy interface remains the visual and interaction authority. Data work may populate its existing states;
it may not redesign, rename, remove, or fabricate a capability.

## Release boundary

A complete v1 launch contains all of the following:

1. CVE identity and description lineage from the CVE Program `cvelistV5` repository;
2. NVD analysis, CVSS observations, CWE associations, references, and CPE applicability;
3. the current CISA Known Exploited Vulnerabilities catalogue and normalized KEV history;
4. CVE-linked package and ecosystem coverage from the public GitHub Advisory Database repository;
5. CISA-authored ADP observations from CISA Vulnrichment; and
6. the versioned MITRE CWE catalogue used to explain associated CWE identifiers.

The implementation is staged so policy-ready NVD and KEV core data can be proved first. That intermediate milestone is
not a v1 launch and must not make package, CWE, description-lineage, or full-route claims. Every release manifest declares
the exact completed capabilities; a missing stage is `unavailable`, never an empty or successful result.

| Stage | Required sources | Capability unlocked |
|---|---|---|
| A: core proof | NVD and CISA KEV | CVE-keyed NVD facts, CVSS, CPE, NVD CWE identifiers, references, and KEV context; descriptions remain null. |
| B: CVE lineage | Stage A plus registered `cvelistV5` | Canonical CVE state/dates and lineaged English CVE descriptions. |
| C: package coverage | Stage B plus GitHub Advisory Database | Package/ecosystem routes for advisories with valid CVE aliases. |
| D: complete v1 | Stage C plus CISA Vulnrichment and MITRE CWE | CISA ADP SSVC/CVSS/CWE observations and full CWE detail. This is the minimum source set for a v1 launch. |

The following sources and content are outside v1:

- FIRST EPSS: no dataset, history, durable cache, bulk query, bulk export, or score column. Its separately contemplated
  one-CVE direct-display mode remains machine-disabled pending policy v2 and is not part of this data contract.
- Microsoft MSRC: blocked pending explicit redistribution rights. An independently sourced Microsoft URL does not
  authorize MSRC-derived rows or Patch Tuesday membership.
- OSV: disabled until a fail-closed home-database licence registry is approved. GitHub Advisory Database records are
  consumed directly, never via OSV.
- ENISA EUVD: excluded for now even though a narrow future mapping might be possible; no EUVD request, row, or manifest
  source claim appears in v1.
- AppThreat: excluded; no adapter, range reader, row, source claim, or fallback.
- Cisco PSIRT: excluded; no credential, request, advisory row, or manifest source claim.
- raw source mirrors, complete API/repository records, raw archives, API envelopes, linked page bodies, attachments,
  vendor comments, logos, credentials, request headers, and unproven third-party text.

No omitted source may be used as a silent fallback. Adding one is a new rights-policy and architecture feature.

## Mandatory policy gate

Every emitted value passes both keys of the existing source-rights gate:

1. the exact `source_id` is enabled for `public_dataset_republication`; and
2. the exact upstream field path is allowed for that source and use mode.

Unknown sources, modes, fields, authorship, lineage, or licences fail closed. The emitted row records the policy version
and authorizing rule. A transformation cannot broaden the source grant, and an aggregate or history row cannot contain a
value that would be blocked in a current source row.

`patch8_cvelist_v5` does not yet exist in [`licensing/source-policy.json`](licensing/source-policy.json). Before the
builder fetches `CVEProject/cvelistV5` or emits any CVE Program-derived field, P3 must add and test an explicit enabled
public-dataset rule backed by the CVE Program Terms of Use. At minimum that rule must separately allow:

- `dataVersion`;
- `cveMetadata.cveId`, `state`, `datePublished`, `dateUpdated`, `assignerOrgId`, and `assignerShortName`;
- `containers.cna.providerMetadata.orgId`, `shortName`, and `dateUpdated`; and
- `containers.cna.descriptions[].lang` and `.value`.

The rule must require the CVE/MITRE notice, an immutable repository commit, record path and blob/input SHA-256, and field
lineage. Until it exists, descriptions are null and the UI reports description data unavailable. The builder must not
copy a description from NVD and later claim that it was verified against CVE content.

## Canonical identity

Patch8 canonicalizes identity, not upstream opinions.

| Entity | Canonical key and rule |
|---|---|
| Vulnerability | Uppercase `CVE-YYYY-NNNN...` matching `^CVE-[0-9]{4}-[0-9]{4,}$`. The natural CVE ID is the key; random UUIDs are not published. |
| GHSA advisory | `GHSA-xxxx-xxxx-xxxx` with uppercase `GHSA` prefix and lowercase suffix matching `^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`. A GHSA is an advisory identity and never a CVE. |
| CWE | Uppercase `CWE-N`, where `N` is the canonical positive integer identifier. |
| Package | `(ecosystem, package_name)` exactly as normalized from the GitHub advisory, with `package_url` retained when supplied. Ecosystem case normalization is versioned and the original value is retained. |
| Software | `(vendor, product)` parsed from a valid CPE 2.3 URI. The CPE URI and explicit version bounds remain the authoritative observation; display labels are normalized projections. |
| Source observation | Deterministic `observation_id = sha256(source_id, source_record_id, exact_field_path_or_group, author_or_container, normalized_value)`. Repository/catalogue revisions are deliberately excluded so unchanged observations keep stable IDs. |
| Provenance | Deterministic `provenance_id` over stable record/field evidence defined below; release-specific source revision and fetch evidence live in `source_snapshots`. |

Only CVEs appear in the legacy vulnerability list and `/vulnerabilities/[id]` route. A GitHub advisory with valid CVE
aliases records each advisory-to-CVE alias relationship explicitly; one alias is never selected arbitrarily. Package and
range observations remain keyed to their GHSA advisory and affected/range indices, not copied to every CVE alias. The
legacy CVE-package read model includes an advisory only when it has exactly one valid CVE alias, which is the only v1
case where Patch8 can project the advisory's package assertion to one CVE without inventing a package×CVE cross-product.
Multi-CVE advisories remain advisory-associated observations with partial coverage and do not produce per-CVE package
claims. GHSA-only advisories are outside v1 read models, are not relabelled into `cve_id`, and yield no fake vulnerability
route. For each included CVE-linked advisory, the GHSA ID remains the source record key, attribution link, and provenance
identity.

## Source field contracts

The lists below are exhaustive for v1. A source policy may permit more than this product contract; that does not make the
extra field part of v1.

### CVE Program `cvelistV5`

- Source: public `CVEProject/cvelistV5` repository at an immutable 40-character Git commit.
- Accepted: the policy-gated fields listed under **Mandatory policy gate**.
- Use: CVE identity/state, CVE Program dates, and the English CNA description with its CNA provider lineage.
- Not accepted in v1 from this source: ADP containers, supporting-media bodies, credits, arbitrary extensions, linked
  bodies, or any field absent from the new machine rule. A later allow-list may add CNA affected/metric/reference fields
  without weakening the two-key gate.
- Description selection: prefer the first valid English CNA description in source order; preserve every accepted English
  description observation, its language, provider, and record hash. Do not translate, combine, or silently truncate it.

### NVD API 2.0 and NVD change history

- Accepted identity/dates: `cve.id`, `cve.published`, `cve.lastModified`, and `cve.sourceIdentifier`.
- Accepted CVSS: NIST/NVD-authored metric `source`, `type`, `cvssData.version`, `vectorString`, `baseScore`, and
  `baseSeverity`. All accepted v4.0, v3.1, v3.0, and v2 observations are retained; CNA/vendor metrics require separately
  proven CVE lineage and are otherwise rejected.
- Accepted weakness data: normalized `CWE-N` identifiers from NVD weakness descriptions; `NVD-CWE-noinfo`,
  `NVD-CWE-Other`, prose, and unparseable identifiers are not CWE associations.
- Accepted applicability: vulnerable CPE 2.3 URI, match-criteria identifier when covered by policy, and the explicit
  configuration/node identity, `operator`, `negate`, `vulnerable`, match-criteria identifier, and all four explicit
  start/end including/excluding version bounds. P3 must add any of those exact structural paths missing from the current
  NVD machine allow-list before output. Patch8 preserves the Boolean configuration tree; a CPE observation is labelled
  “listed in NVD applicability” and is not presented as vendor confirmation.
- Accepted references: HTTPS URL and NVD tags. The linked title, body, file, vendor comment, and attachment are not read
  or published.
- Accepted history: NVD change time/type and old/new values only for otherwise allowed fields; denied text produces a
  hash-only change event.
- Not accepted: NVD descriptions without exact `cvelistV5` lineage, vendor comments, raw response pages, unknown metric
  authors, or fields outside `patch8_nvd.allowed_fields`.

### CISA Known Exploited Vulnerabilities

- Source: official CISA feed or `cisagov/kev-data` at a pinned commit, with catalogue SHA-256, `catalogVersion`, and
  `dateReleased` validated against declared and actual row counts.
- Accepted per entry: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`,
  `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, and valid `cwes[]` when supplied.
- Use: current KEV membership and a distinct CISA KEV panel. KEV prose never overwrites the CVE Program description,
  and KEV product names never create NVD CPE version assertions.
- History: adds, edits, removals, catalogue-version changes, and Patch8 observations. A current full snapshot is
  authoritative: a removed CVE becomes `kev_status=not_listed`/`in_kev=false` and emits a removal event rather than
  remaining sticky. Without a complete reconciliation it becomes `unknown`/null instead.
- Not accepted: inferred scores, inferred affected versions, linked vendor content, or a raw JSON/CSV mirror.

### GitHub Advisory Database

- Source: public `github/advisory-database` repository at an immutable commit. The legacy authenticated GraphQL feed is
  not the bulk source and no GitHub token is required for v1 ingestion.
- Accepted advisory fields: `id`, syntactically valid CVE values from `aliases[]`, `published`, `modified`, `withdrawn`, `summary`, `details`, `severity`,
  `references[].url/type`, and `credits[]`.
- Accepted package fields: `affected[].package.ecosystem`, `.name`, `.purl`; `affected[].ranges[].type`, `.repo`, and
  the complete ordered `events[]` sequence with exactly one of `introduced`, `fixed`, `last_affected`, or `limit` per
  event; explicit `affected[].versions[]`; and approved
  GitHub `database_specific` values only when named in the field-policy implementation.
- Use: advisory-associated package/ecosystem identity and ranges, retaining `affected_index`, `range_index`, and ordered
  `event_index`. Only a single-CVE-alias advisory enters the per-CVE legacy package read model. Summary/details and
  GitHub qualitative severity remain GHSA observations; they do not overwrite the CVE description or selected CVSS.
- A withdrawn advisory remains in source history with `withdrawn_at`, but it is excluded from current package results
  unless another current allowed source independently supports the relationship.
- Not accepted: GHSA-to-CVE substitution, unreviewed custom fields, linked bodies, attachments, or a raw OSV mirror.

### CISA Vulnrichment

- Source: public `cisagov/vulnrichment` repository at an immutable commit.
- Accepted identity/provider: `cveMetadata.cveId` and the CISA-ADP `providerMetadata` object.
- Accepted CISA ADP observations: `metrics` containing SSVC decision points, CISA-authored CVSS, and KEV reference
  metadata; `problemTypes` containing valid CWE identifiers; and `references[].url`.
- Use: source-specific SSVC, CVSS, CWE, and reference observations. The canonical KEV catalogue, not an ADP KEV marker,
  controls `in_kev`.
- CISA may remove an enrichment after a CNA supplies data. A later pinned commit with the CISA observation absent closes
  the current observation and records a removal; Patch8 must not preserve a stale value as current.
- Not accepted: any `containers.cna` field, descriptions, affected data, historical CPE enrichment, linked bodies, or a
  complete CVE record.

### MITRE CWE

- Source: exact versioned XML ZIP from the official CWE archive, with version, URL, published date, byte size, and
  SHA-256.
- Accepted: CWE ID, name, entry type, abstraction, status, description, extended description, relationships, applicable
  platforms/languages/technologies, common consequences, detection methods, potential mitigations, notes, external
  reference metadata/URLs, and content-history fields allowed by `patch8_mitre_cwe`.
- Use: explain a CWE identifier already asserted by an allowed vulnerability source. CWE platform metadata does not
  create affected-product or package relationships.
- Not accepted: invented CWE scores/rankings, logos, linked document bodies, or a raw archive mirror.

## Observations and deterministic presentation

Patch8 never performs last-writer-wins merging. Source observations remain independently queryable and immutable within
a release. The denormalized legacy read model contains selected display values plus the exact `observation_id` used.

| Field | Selection rule |
|---|---|
| CVE state and dates | Current `cvelistV5` metadata; until Stage B, fall back to clearly provenanced NVD published/modified observations and keep state `unknown`. |
| Description | Current English CNA description from registered `cvelistV5` only. No NVD, KEV, GHSA, or Vulnrichment fallback. |
| CVSS and severity | Retain every allowed v1 metric. Select NVD `Primary` NIST metrics first, then CISA-ADP metrics. Within a tier prefer v4.0, then v3.1, v3.0, v2.0, then newest upstream timestamp and lexical observation ID. Severity is the selected metric's base severity, not a separately merged opinion. CVE Program metrics are outside the v1 `cvelistV5` rule and GitHub qualitative severity is not converted to CVSS. |
| CWE list | Stable union of current source-specific CWE observations, sorted numerically and displayed with source badges; no “best” CWE is invented. |
| References | Deduplicate identical normalized HTTPS URLs only in the presentation projection. Preserve every source observation and tag set. Unsafe schemes are rejected. |
| Affected software | NVD CPE observations only in v1. Preserve URI and bounds. Do not enumerate all versions between bounds or collapse several ranges. |
| Affected packages | GitHub advisory observations only in v1, and only through explicit CVE aliases. Preserve ecosystem, package, range type/events, versions, and GHSA ID. |
| KEV | Current CISA KEV full snapshot only. `not_listed` is emitted only after a complete successful catalogue reconciliation; otherwise status is `unknown`. Even `not_listed` means only “not in that catalogue”, never “not exploited”. |
| SSVC | Latest current CISA-ADP SSVC observation. Keep decision timestamp and source; do not turn SSVC into a numeric score. |

Conflicts are data, not errors to hide. When two allowed observations disagree, both remain in their observation table,
the presentation rule above selects one predictable legacy value, and `selection_reason` identifies the rule/tier. A
source change never rewrites another source's observation. Values are never averaged, maximized across authors, or
multiplied together.

Patch8 publishes no composite risk score. CVSS severity, KEV membership, SSVC decision points, publication age, and
future policy-approved signals answer different questions. Existing “top” lists use an explicit lexicographic order:
current SSVC exploitation (`active`, `poc`, `none`, unavailable), KEV status (`listed`, `not_listed`, `unknown`), selected CVSS base score,
published time, then CVE ID. That order is presentation metadata, not a probability, severity, or risk score.

## Field provenance

Every source observation and every selected field pointer resolves to exactly one stable `provenance` row containing:

- `provenance_id`, `source_id`, source display name, and source policy decision;
- exact endpoint or repository URL and upstream record path/identifier;
- SHA-256 and byte size of the smallest exact source record/blob/object that contains the value;
- upstream published and modified timestamps when supplied;
- parser name/version, transformation version, and table schema version;
- rights-policy schema/version and exact authorizing field rule;
- authorship/provider identity where relevant (CNA, NVD metric source, CISA-ADP, GitHub, MITRE);
- transformation kind (`copied`, `normalized`, `selected`, `aggregated`, or `hash_only`) and a modification/truncation
  note when applicable; and
- required notice IDs used to generate the dataset card and application attribution.

One provenance row may authorize several output rows only when their input object, field rule, authorship, and
transformation tuple are identical. A selected display field points to its underlying observation. A count, union,
status, normalized label, flattened range, or other derived value points to a `derivation` row listing every input
observation and the versioned deterministic rule; neither may point only to a build or a generic source.

Release-specific evidence is separate so a new repository commit or catalogue version does not churn every unchanged
row. Each active source has a `source_snapshot` row containing the immutable Git commit, source/catalogue/schema version,
ETag/Last-Modified or API window bounds, complete-object hash/bytes, retrieval/check times, and contiguous watermark. The
release manifest binds its observation files and stable provenance set to those exact snapshots. For a monolithic input
such as KEV, provenance hashes the canonical individual entry while the source snapshot hashes and validates the complete
catalogue. For Git sources, provenance carries record path/blob hash while the snapshot carries the commit. A record with
unchanged value, author, path, and blob/object hash therefore keeps identical observation/provenance rows across releases;
only the small snapshot/status/release metadata changes.

## Time, freshness, and availability

All instants are UTC Parquet `TIMESTAMP_MICROS` values and all calendar-only values are ISO `DATE`. Source timestamps are
never replaced with fetch time. The contract distinguishes:

- `source_published_at` / `source_modified_at`: supplied by upstream;
- `source_retrieved_at`: bytes successfully obtained;
- `source_observed_at`: bytes validated and normalized;
- `dataset_built_at`: candidate release completed;
- `manifest_activated_at`: manifest-last publication completed; and
- `stale_at`: first instant at which the declared freshness threshold is exceeded; and
- `last_successful_watermark`: highest contiguous upstream window/commit/version safely incorporated.

| Source | Intended check/build cadence | `current` threshold | Stale rule |
|---|---|---|---|
| NVD | bounded modified-window poll; never more than one automated cycle per two hours | successful contiguous watermark no more than 30 hours old | older than 30 hours, overlap/reconciliation incomplete, or a gap exists |
| `cvelistV5` | daily pinned-commit check | checked commit no more than 30 hours old | older than 30 hours or commit/schema validation failed |
| CISA KEV | daily full-snapshot check | checked catalogue no more than 30 hours old | older than 30 hours or declared/actual count or integrity fails |
| GitHub Advisory Database | daily pinned-commit check | checked commit no more than 30 hours old | older than 30 hours or repository/schema validation failed |
| CISA Vulnrichment | daily pinned-commit check | checked commit no more than 30 hours old | older than 30 hours or commit/schema validation failed |
| MITRE CWE | daily version check; fetch only on change | successful version check no more than 8 days old | no successful check for 8 days or the advertised archive/version fails validation |

`unavailable` means there is no verified observation for the active release/capability. `unsupported` means v1 does not
provide that capability. `partial` means the declared source/identity coverage is narrower than the route's theoretical
domain. `stale` means the last verified observation is shown with its source-modified, checked, built, published, age,
and watermark timestamps. `blocked` and `excluded` are policy states, not feed failures. An HTTP error, missing artifact,
corrupt Parquet file, stale source, or disabled source must never be converted to zero rows, zero scores, `not_listed`,
“not affected”, or “no vulnerabilities found”.

A candidate may activate only when all sources required by its declared stage meet the threshold. Complete v1 activation
requires every v1 source above. The browser may use the previous-good immutable release when current activation fails;
it must display that release's age and never mix files or source statuses from two revisions.

## History and retention

- Current tables contain only the state at the active release watermark. Upstream removals and withdrawals disappear
  from current projections only after a full-snapshot or deterministic reconciliation proves the removal.
- `change_events` records additions, allowed-value changes, withdrawals/removals, and selection changes. Denied values
  are represented only by hashes and field paths.
- The active dataset retains normalized v1 change events for 24 months in stable source/year partitions. Current
  withdrawal/removal tombstones remain for as long as the affected identity is present, even when older than 24 months.
- Hugging Face commit history is useful immutable evidence but is best effort and is not the contractual history API or
  retention mechanism. The logical current tree is replaced in bounded paths and never accumulates a file per day.
  Each manifest records current repository revision count and retained-byte estimates plus P6-established hard maxima.
  Publication runs only when inputs changed, removes failed candidate paths, and stops before either maximum is crossed.
  Crossing a limit requires a separately approved, read-back-verified compaction or repository-generation migration;
  the publisher may not silently grow history or rewrite an active/previous-good revision.
- Private raw build inputs follow the shorter source-specific policy: NVD no more than two verified releases/90 days;
  KEV, GitHub Advisory Database, Vulnrichment, and CWE no more than 7 days; `cvelistV5` must receive an explicit limit in
  its new source rule, no greater than two verified releases/90 days. Credentials and sensitive request metadata have
  zero retention.
- After raw expiry, Patch8 retains only allowed normalized rows, input hashes/bytes, immutable upstream locator,
  retrieval metadata, parser identity, and release evidence.

## Parquet v1 contract

### Common physical rules

- Production table schema version is `1`; the synthetic P2 manifest/table version `0` remains fixture-only evidence.
- Strings are UTF-8; booleans are Parquet `BOOLEAN`; counts are non-negative `INT64`; scores are `DOUBLE`; hashes are
  lowercase 64-character hex; instants/dates use the types above.
- Every source-derived row contains `observation_id` and `provenance_id`; every selected value in a read model contains
  its selected observation pointer, and every derived/flattened value contains `derivation_id`. `rights_policy_version`
  and `schema_version` are never nullable.
- Rows use deterministic sort keys and deterministic IDs. Null means unavailable/not supplied, never zero or false.
- A null software/package version means “upstream did not specify a version”; it never means every version. Wildcards,
  defaults, and open range ends remain explicit source observations.
- Scalar columns use their named Parquet primitive types. Set-like lists are canonicalized as noted below; source-order
  lists preserve source order. Structured source content uses typed `LIST<STRUCT<...>>` or normalized child tables, never
  an opaque JSON string/blob.
- Paths are safe relative paths under `data/v1/`. One logical partition has one bounded current file unless P2's final
  size budget requires deterministic `part-NNNN` splits recorded in the manifest.
- `cve_year` is the four digits in the CVE ID. `cve_bucket` is the first two digits of the numeric suffix, padded right
  with zero as in P2. `vendor_bucket` and `package_bucket` are the first two hex characters of SHA-256 over the normalized
  route key. `cwe_bucket` is the first two digits of the zero-padded numeric CWE ID.

### Content and observation tables

| Table | Columns (`?` = nullable) | Partition and sort |
|---|---|---|
| `vulnerabilities` | `cve_id`, `cve_year`, `cve_bucket`, `record_state`, `published_at?`, `published_observation_id?`, `modified_at?`, `modified_observation_id?`, `description?`, `description_observation_id?`, `severity?`, `cvss_score?`, `cvss_vector?`, `cvss_version?`, `cvss_observation_id?`, `kev_status`, `in_kev?`, `kev_observation_id?`, `kev_date_added?`, `kev_due_date?`, `kev_ransomware_use?`, `ssvc_exploitation?`, `ssvc_automatable?`, `ssvc_technical_impact?`, `ssvc_observation_id?`, `package_count?`, `package_count_derivation_id?`, `software_count?`, `software_count_derivation_id?`, `source_count`, `source_count_derivation_id`, `last_observed_at`, `selection_derivation_id`, `rights_policy_version`, `schema_version` | `vulnerabilities/year=YYYY/bucket=NN/`; sort `cve_id` |
| `descriptions` | `observation_id`, `cve_id`, `lang`, `description`, `provider_org_id`, `provider_short_name?`, `source_published_at?`, `source_modified_at?`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | CVE year/bucket; sort `cve_id, lang, observation_id` |
| `cvss_observations` | `observation_id`, `cve_id`, `source_id`, `metric_author`, `metric_type?`, `cvss_version`, `vector`, `base_score`, `base_severity`, `source_modified_at?`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | CVE year/bucket; sort `cve_id, cvss_version, source_id, observation_id` |
| `weakness_observations` | `observation_id`, `cve_id`, `cwe_id`, `source_id`, `metric_author?`, `source_modified_at?`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | CVE year/bucket; sort `cve_id, cwe_id, source_id` |
| `references` | `observation_id`, `cve_id`, `source_id`, `url`, `tags`, `source_modified_at?`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | CVE year/bucket; sort `cve_id, url, source_id` |
| `affected_software` | `observation_id`, `cve_id`, `configuration_id`, `node_id`, `parent_node_id?`, `operator`, `negate`, `vulnerable`, `match_criteria_id?`, `vendor`, `product`, `cpe_uri`, `version?`, `version_start_including?`, `version_start_excluding?`, `version_end_including?`, `version_end_excluding?`, `source_id`, `source_modified_at?`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | CVE year/bucket; sort `cve_id, configuration_id, node_id, cpe_uri, observation_id` |
| `ghsa_advisories` | `observation_id`, `ghsa_id`, `published_at?`, `modified_at?`, `withdrawn_at?`, `summary?`, `details?`, `qualitative_severity?`, `references`, `credits`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | `ghsa/bucket=HH/`; sort `ghsa_id` |
| `ghsa_cve_aliases` | `observation_id`, `ghsa_id`, `alias_index`, `cve_id`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | `ghsa/bucket=HH/`; sort `ghsa_id, alias_index, cve_id` |
| `ghsa_affected_packages` | `observation_id`, `ghsa_id`, `affected_index`, `ecosystem`, `ecosystem_original`, `package_name`, `package_url?`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | `ghsa/bucket=HH/`; sort `ghsa_id, affected_index` |
| `ghsa_package_ranges` | `observation_id`, `ghsa_id`, `affected_index`, `range_index`, `range_type`, `range_repo?`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | `ghsa/bucket=HH/`; sort `ghsa_id, affected_index, range_index` |
| `ghsa_range_events` | `observation_id`, `ghsa_id`, `affected_index`, `range_index`, `event_index`, `event_type`, `event_value`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | `ghsa/bucket=HH/`; sort `ghsa_id, affected_index, range_index, event_index` |
| `ghsa_explicit_versions` | `observation_id`, `ghsa_id`, `affected_index`, `version_index`, `version`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | `ghsa/bucket=HH/`; sort `ghsa_id, affected_index, version_index` |
| `kev_observations` | `observation_id`, `cve_id`, `catalog_version`, `catalog_released_at`, `vendor_project`, `product`, `vulnerability_name`, `date_added`, `short_description`, `required_action`, `due_date`, `known_ransomware_campaign_use`, `notes?`, `cwe_ids`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | `kev/current/`; sort `date_added DESC, cve_id` |
| `ssvc_observations` | `observation_id`, `cve_id`, `exploitation`, `automatable`, `technical_impact`, `decision_at?`, `provider_org_id`, `provider_short_name`, `source_modified_at?`, `is_current`, `provenance_id`, `rights_policy_version`, `schema_version` | CVE year/bucket; sort `cve_id, source_modified_at, observation_id` |
| `cwe_catalog` | `observation_id`, `cwe_id`, `name`, `entry_type`, `abstraction?`, `status`, `description`, `extended_description?`, `relationships`, `applicable_platforms`, `consequences`, `detection_methods`, `mitigations`, `notes`, `external_references`, `content_history`, `cwe_version`, `provenance_id`, `rights_policy_version`, `schema_version` | `cwe/bucket=NN/`; sort numeric `cwe_id` |
| `provenance` | provenance tuple defined above plus `required_notice_ids` | `provenance/source=SOURCE/`; sort `source_record_id, provenance_id` |
| `source_snapshots` | `source_snapshot_id`, `source_id`, `endpoint_or_repository`, `immutable_revision?`, `source_version?`, `catalog_version?`, `schema_version_seen?`, `etag?`, `last_modified?`, `window_start?`, `window_end?`, `complete_input_sha256`, `complete_input_bytes`, `checked_at`, `source_retrieved_at`, `source_observed_at`, `last_successful_watermark`, `builder_source_revision`, `rights_policy_version`, `schema_version` | one bounded `snapshots/source-snapshots.parquet`; sort `source_id` |
| `derivations` | `derivation_id`, `rule_id`, `rule_version`, `output_table`, `output_key`, `output_field`, `input_observation_ids`, `schema_version` | `derivations/table=TABLE/`; sort `output_key, output_field, derivation_id` |
| `change_events` | `event_id`, `source_id`, `entity_type`, `entity_id`, `field_path`, `change_type`, `old_observation_id?`, `new_observation_id?`, `old_value_hash?`, `new_value_hash?`, `source_event_at?`, `observed_at`, `provenance_id`, `rights_policy_version`, `schema_version` | `history/source=SOURCE/year=YYYY/`; sort `observed_at, entity_id, field_path, event_id` |
| `source_status` | `source_id`, `source_snapshot_id?`, `capability_stage`, `state`, `checked_at`, `source_modified_at?`, `last_success_at?`, `last_successful_watermark?`, `source_version?`, `immutable_revision?`, `dataset_built_at`, `manifest_activated_at?`, `stale_at`, `error_class?`, `rights_policy_version`, `schema_version` | one bounded `status/source-status.parquet`; sort `source_id` |
| `capability_status` | `capability_id`, `state`, `coverage_basis`, `coverage_numerator?`, `coverage_denominator?`, `coverage_as_at?`, `source_ids`, `dataset_built_at`, `manifest_activated_at?`, `stale_at?`, `derivation_id`, `schema_version` | one bounded `status/capability-status.parquet`; sort `capability_id` |

### Query-routed read models

These are deterministic projections of allowed content rows, not new source claims. Each row retains observation pointers
and is validated by the same field gate.

| Read model | Columns | Partition and legacy use |
|---|---|---|
| `vulnerability_recent` | selected `vulnerabilities` summary columns plus `published_year`, `published_month`, `derivation_id` | `read/recent/year=YYYY/month=MM/`; dashboard, empty-query list, date filters, pagination |
| `vulnerability_search_terms` | `term`, `term_kind`, `cve_id`, `rank_class`, `selected_observation_id?`, `derivation_id`, `schema_version` | `read/search/bucket=HH/`, where `HH=sha256(term)[0:2]`; exact normalized terms for CVE, allowed description tokens, vendor/product, and CVE-linked package names |
| `software_product_vulnerabilities` | selected vulnerability summary plus every `affected_software` field, observation ID, and `derivation_id` | `read/software/vendor=HH/`; software/vendor/product routes and autocomplete |
| `package_vulnerabilities` | selected vulnerability summary plus `ghsa_id`, `affected_index`, package fields, ordered typed range/event/explicit-version lists, every input observation ID, `association_kind=single_cve_alias`, and `derivation_id` | `read/packages/ecosystem=E/package=HH/`; package/ecosystem routes; excludes GHSA-only and multi-CVE advisory projections |
| `kev_current` | selected vulnerability summary plus KEV observation fields, observation ID, and `derivation_id` | one bounded `read/kev/current.parquet`; dashboard and KEV filter |
| `cwe_by_vulnerability` | `cve_id`, `cwe_id`, weakness observation ID, CWE catalogue observation ID, display fields, and `derivation_id` | CVE year/bucket; vulnerability detail CWE join |

P2's `vulnerabilities`, `affected_software`, and `kev` fixture tables are not production schemas. Compared with P2,
production v1 removes the random `id`, makes description/CVSS/KEV-state nullable where coverage is unknown, removes synthetic `source_id`, adds field-level
observation pointers and full provenance, removes every EPSS field, retains multiple CVSS/source observations, separates
GHSA packages from NVD CPE software, adds CVE/GHSA/CWE identity rules, adds source status/history, and introduces routed
search/recent/product/package/CWE read models. P2's measured request/byte/memory maxima remain release ceilings until an
approved P2 result replaces them; P3 must not loosen those budgets silently.

### Complex Parquet column types and ordering

| Column | Exact logical type | Ordering rule |
|---|---|---|
| `references.tags` | `LIST<UTF8>` | trim, deduplicate, lexical sort |
| `ghsa_advisories.references` | `LIST<STRUCT<url:UTF8, type:UTF8?>>` | normalized HTTPS URLs, exact duplicates removed, source order retained |
| `ghsa_advisories.credits` | `LIST<STRUCT<name:UTF8, contact:LIST<UTF8>, type:LIST<UTF8>>>` | outer, contact, and type arrays retain source order after exact duplicate removal |
| `kev_observations.cwe_ids` | `LIST<UTF8>` | valid CWE IDs, deduplicate, numeric sort |
| `cwe_catalog.relationships` | `LIST<STRUCT<nature:UTF8, target_cwe_id:UTF8, view_id:UTF8?, ordinal:INT32?>>` | source order |
| `cwe_catalog.applicable_platforms` | `LIST<STRUCT<kind:UTF8, class:UTF8?, name:UTF8, prevalence:UTF8?>>` | source order |
| `cwe_catalog.consequences` | `LIST<STRUCT<scope:LIST<UTF8>, impact:LIST<UTF8>, likelihood:UTF8?, note:UTF8?>>` | source order at every level |
| `cwe_catalog.detection_methods` | `LIST<STRUCT<method_id:UTF8?, method:UTF8, description:UTF8?, effectiveness:UTF8?>>` | source order |
| `cwe_catalog.mitigations` | `LIST<STRUCT<phase:LIST<UTF8>, description:UTF8, effectiveness:UTF8?>>` | source order |
| `cwe_catalog.notes` | `LIST<STRUCT<type:UTF8, note:UTF8>>` | source order |
| `cwe_catalog.external_references` | `LIST<STRUCT<reference_id:UTF8?, url:UTF8?, title:UTF8?, authors:LIST<UTF8>>>` | source order |
| `cwe_catalog.content_history` | `LIST<STRUCT<event_type:UTF8, event_date:DATE?, version:UTF8?, details:UTF8?>>` | source order, with deterministic source-index tie-break |
| `provenance.required_notice_ids`, `derivations.input_observation_ids`, `capability_status.source_ids` | `LIST<UTF8>` | deduplicate, lexical sort |
| `package_vulnerabilities.ranges` | `LIST<STRUCT<range_index:INT32, range_type:UTF8, range_repo:UTF8?, events:LIST<STRUCT<event_index:INT32, event_type:UTF8, event_value:UTF8>>>>` | range/event index ascending; disjoint and repeated events remain distinct |
| `package_vulnerabilities.explicit_versions` | `LIST<STRUCT<version_index:INT32, version:UTF8>>` | version index ascending |

## Legacy route capability matrix

“Supported” below means supported by the complete v1 contract, not implemented today. Legacy routes, information
architecture, component placement, visual styling, brand assets, tokens, and responsive layout stay authoritative.
Exact old copy, metadata, and enabled controls are not authoritative when they make a false data claim. P9/P10 may make
the smallest semantic-only text/meta change or disable an existing filter/card control needed to say `unavailable`,
`unsupported`, `partial`, or `stale` honestly; they may not redesign, remove the route, or reflow the layout. These changes
require legacy visual-regression and accessibility evidence in every locked viewport/theme.

| Legacy route/panel | v1 state | Contractual behavior |
|---|---|---|
| `/` statistics | Supported with limitations | Total CVEs, selected CVSS severity counts, current KEV count, package count, source freshness, and coverage state. Unknown coverage is unavailable/null, not zero. `high_epss` is unavailable/null. |
| `/` recent KEV / critical CVEs | Supported | Current KEV and selected-CVSS projections with provenance and release freshness. |
| `/` High EPSS | **Unavailable** | No request, dataset field, ranking, count, or fake empty success. Show the existing unavailable state. |
| `/` Patch Tuesday | **Unavailable** | No inferred report from `vendor=microsoft` plus publication month. The existing unavailable state remains. |
| `/search` exact CVE, text, severity, KEV, date, vendor/product | Supported | Routed indexes and selected values; text index contains only allowed values. |
| `/search` ecosystem/package | Supported with declared partial coverage at complete v1 | Per-CVE package results include only single-CVE-alias GitHub advisories; multi-CVE advisories remain advisory-associated and GHSA-only advisories are outside v1 read models. Coverage counts/state remain visible to data consumers. |
| `/search` EPSS filter/sort/export columns | **Unavailable** | `epss_gt` cannot be evaluated and must not be interpreted as zero/no matches. Export emits an explicit unavailable/null field only if exact legacy shape requires it. |
| `/vulnerabilities/[id]` | Supported for CVE IDs | CVE description, all source observations, NVD CPE, CVE-linked GHSA packages, KEV, CISA ADP, CWE detail, references, provenance, and freshness. GHSA IDs are not accepted as CVE route IDs. |
| vulnerability EPSS pills/percentile | **Unavailable** | Null/unavailable; no durable or direct EPSS request under this contract. |
| threat-context panel | **Unavailable** | Threat10/AppThreat/linked report bodies are outside v1. |
| `/packages` and package detail | Supported with declared partial coverage at complete v1 | GitHub Advisory Database only; GHSA identity remains visible. Only single-CVE-alias advisory package observations become per-CVE vulnerability rows; no alias cross-product is shown. |
| `/software`, vendor, product, versions | Supported | NVD CPE applicability and bounds, labelled as NVD observations; versions are observed bounds, not an enumerated affected-version claim. |
| product intelligence | Supported with limitations | Counts, selected CVSS severities, current KEV, and SSVC fields. EPSS averages/maxima are unavailable. “Top” uses the explicit non-score ordering above. |
| `/reports/patch-tuesday` and month detail | **Unavailable in v1** | MSRC is blocked and NVD publication month is not Patch Tuesday membership. No monthly rows, narrative, or runtime AI call. |
| `/feeds` | Supported as release-source status | Build/manifest source checks and freshness replace server feed-run claims. Disabled/excluded sources are labelled accordingly. |
| watchlist routes | Data-supported later | Local watchlist matching may use v1 software/package projections under P11; no account, shared state, or server write. |
| admin/backfill/auth routes | Absent | No static substitute, credential, Worker, D1, or runtime write. |
| CSV/JSON export | Data-supported later | Export only the pinned queried projection, provenance IDs, and honest null/unavailable fields; never raw source records or blocked values. |

The unavailable Patch Tuesday decision is deliberate. NVD CPE vendor `microsoft` plus CVE publication month is not an
authoritative Microsoft security-update release. That legacy approximation and the legacy runtime-AI narrative are not
carried into the static product. Re-enabling the report requires an approved source that establishes bulletin membership,
rights, dates, products, and revisions; MSRC remains blocked today.

## Acceptance tests

P3 and the later ingestion/release features must turn this contract into executable fixtures. At minimum:

### Policy and source scope

- reject an unregistered `patch8_cvelist_v5` fetch/output and accept it only after the exact machine rule and notices pass;
- reject every unknown source/field/use mode and every EPSS, OSV, ENISA, MSRC, AppThreat, or Cisco row/manifest claim;
- reject raw payloads, linked bodies, vendor comments, CNA leakage from Vulnrichment, unsafe URLs, and missing lineage;
- snapshot required NVD, CVE/MITRE, CISA, GitHub CC BY 4.0, and MITRE CWE notices; and
- prove every emitted field resolves through an enabled source rule and a field rule.

### Identity, conflicts, and lineage

- normalize valid CVE/CWE/GHSA IDs and reject malformed IDs;
- prove a GHSA-only advisory never enters `cve_id`, while one/many CVE aliases create explicit relationships and retain
  GHSA identity/provenance;
- prove only exactly-one-CVE-alias advisories project packages to a per-CVE legacy row, while multi-CVE advisories remain
  advisory-associated and never create a package×CVE cross-product;
- preserve repeated and disjoint package ranges plus every source-ordered range event through content and read models;
- prove KEV prose and GHSA text cannot overwrite the CVE Program description;
- retain conflicting typed NVD/CISA-ADP CVSS observations, select v4.0 before v3.1 within the same precedence tier, and
  prove CVE Program/GitHub qualitative severity cannot enter the v1 CVSS selector;
- prove source arrival order does not change selected values or bytes;
- prove an unrelated repository/catalogue change leaves every unchanged observation/provenance row and ID byte-stable,
  while source snapshot/release evidence advances to the new immutable revision;
- remove current KEV/SSVC/package observations only after authoritative snapshot/reconciliation evidence and retain the
  change event; and
- prove denied old/new text creates hash-only history.

### Schema and routing

- validate every declared column/type/nullability, natural key, observation/provenance foreign key, schema fingerprint,
  deterministic sort, row count, min/max bound, partition coordinate, checksum, and safe path;
- prove every selected field has an observation pointer and every aggregate/normalized/flattened field has a complete
  deterministic derivation row;
- prove exact CVE, recent list, text search, KEV, software/vendor/product, package/ecosystem, CWE detail, pagination, empty,
  stale, corrupt-current, and previous-good queries select only manifest-declared bounded files;
- prove duplicate read-model rows resolve to the same source observation and cannot bypass rights checks;
- prove no file-per-day accumulation and clean-build/delta byte equivalence for identical pinned inputs; and
- enforce the final P2 request, transferred-byte, latency, and browser-memory ceilings in Chromium, Firefox, desktop
  Safari, and representative mobile Safari before publication.

### Freshness, history, and failure truthfulness

- exercise every current/stale/unavailable/blocked/excluded source state and boundary timestamp;
- exercise supported/partial/unsupported/unavailable/stale capability coverage and prove zero is returned only for a
  successfully evaluated supported coverage domain;
- reject a candidate with a source gap, non-contiguous NVD watermark, mutable/unpinned Git source, schema drift, count
  mismatch, checksum mismatch, or mixed revision;
- verify the 24-month active history window, long-lived current tombstones, and source-specific raw expiry;
- enforce manifest-declared Hugging Face revision-count and retained-byte ceilings and fail closed before growth exceeds
  either bound;
- prove a missing/failed source cannot become zero results, false `in_kev`, “not affected”, or “no vulnerabilities”; and
- verify manifest-last activation and previous-good rollback never mix tables, indexes, statuses, or provenance across
  revisions.

### Legacy semantics

- replay the complete legacy query corpus against fixtures without route, layout, asset, token, component-placement, or
  responsive changes; snapshot-test only the minimal approved semantic copy/meta/disabled-control changes;
- assert EPSS fields/filters/cards are unavailable and no FIRST network/storage/export path exists;
- assert Patch Tuesday list/detail/narrative are unavailable and no NVD-month approximation or runtime AI call exists;
- assert package and CWE routes become supported by complete v1 rather than silently remaining deferred; and
- assert all ordering is the documented lexicographic presentation rule and no composite risk-score column, formula,
  label, filter, or export is present.

## Change control and remaining gates

P3 must implement a Patch8-specific source/field/manifest schema from this document and replace the historical shared
contract evidence. P4, P4a, P5, and P5a implement the bounded source phases; P6 produces the complete local v1 Parquet candidate.
Publication and UI population remain later features and retain their existing live-verification gates.

Any change to a source, accepted field, canonical key, precedence rule, freshness threshold, retention period, table,
partition, or legacy capability state requires a versioned contract change, source-policy evidence where applicable,
fixtures, migration/reader compatibility, and explicit plan approval. Silent contract drift fails the build.
