# Patch8 licence and redistribution register

Date: 2026-08-29

Scope: Patch8 v1 public-dataset source and field policy

Status: source-complete P3 engineering publication policy; not legal advice

## Decision rule

Patch8 may display a bounded upstream response directly in the browser or publish normalized source-derived data. Those are different uses and require separate decisions. A right to call an API, view a page, or display a value for one requested CVE does not by itself establish a right to build, host, export, or republish a public database. Conversely, a source may permit redistribution while Patch8 still chooses not to publish raw copies because they are unnecessary.

The register uses four decisions:

| Decision | Machine meaning |
|---|---|
| **ALLOW** | The source may be enabled, but only the expressly allowed fields and required notices may be published. Unknown fields remain denied. |
| **CONDITIONAL** | The source is disabled by default. It may be enabled only after the recorded condition is represented in the machine-readable source/field policy and tested. |
| **BLOCK** | Do not ingest or publish source-derived data until the named rights blocker is resolved in writing or source-specific terms change. |
| **EXCLUDE** | The source is outside the first Patch8 release. Do not register credentials, fetch it, or add it to manifests. Reconsider only through a later approved feature. |

This register does not rely on fair use or an assumption that a database has no protectable rights. Identifiers, dates, numeric scores, product names, package coordinates, version bounds, and URLs are generally factual, but contract terms, foreign copyright, database rights, trademarks, and rights in the selection or arrangement can still matter. The applicable source grant and provenance must therefore travel with every published field.

### Public dataset mode is closed

P3's machine policy has one named use mode: `public_dataset_republication`. Every allowed source explicitly names that
mode; every blocked or excluded source has no allowed modes or fields. Unknown source, field, mode, authorship, or lineage
fails closed. FIRST EPSS is not fetched, cached, republished, or exposed by this contract. OSV, EUVD, MSRC, and Cisco are
also absent from v1 output.

### United States government and embedded third-party material

Works created by United States government employees as part of their duties are generally not protected by US copyright. That does not convert third-party text embedded in a government record into a government work. It also does not waive foreign copyright, database rights, trademarks, or contract terms.

Patch8 consequently distinguishes:

- NIST- or CISA-authored data and analysis;
- CVE Record content governed independently by the CVE Program Terms of Use;
- vendor, CNA, researcher, or other third-party content merely carried in an NVD, CISA, ENISA, Microsoft, or Cisco response; and
- Patch8-generated normalization, joins, observations, and provenance.

Government origin alone is never the rule used to publish a third-party description, advisory body, vendor comment, exploit text, or external document.

## Register summary

| Source | Decision | Default ingestion state | Public dataset core |
|---|---|---:|---|
| CVE Program `cvelistV5` | **ALLOW** | enabled | Canonical CVE identity/state/dates and English CNA descriptions with immutable commit, record path, hash, provider lineage, and CVE/MITRE notice |
| NVD API 2.0 | **ALLOW** | enabled | NIST analysis and structured facts; CVE-derived text only with verified CVE lineage and CVE notice |
| CISA KEV | **ALLOW** | enabled | Complete normalized KEV fields under CC0; raw mirror unnecessary |
| FIRST EPSS | **BLOCK** | disabled | None. Patch8 does not build, cache, or republish EPSS. |
| CISA Vulnrichment | **ALLOW** | enabled | CISA ADP SSVC/CVSS/CWE enrichment and its history; do not use it as a second full CVE mirror |
| OSV | **EXCLUDE** | disabled | None in v1 |
| GitHub Security Advisory Database | **ALLOW** | enabled | Advisory fields under CC BY 4.0 with record-level attribution and modification notice |
| ENISA EUVD | **EXCLUDE** | disabled | None in v1 |
| Microsoft MSRC CVRF/CSAF | **BLOCK** | disabled | Link to the official MSRC source only; no MSRC-derived catalogue rows |
| MITRE CWE | **ALLOW** | enabled | CWE identifiers, names, descriptions, relationships, status, history, and reference metadata with MITRE notice |
| Cisco PSIRT | **EXCLUDE** | absent | No fields in the first release |

## Global publication and retention policy

### Normalized output

Every published row or nested field must record enough provenance to identify:

- `source_id` and, where relevant, the upstream home database or author;
- exact endpoint or repository URL;
- upstream record identifier;
- retrieval time and upstream published/modified time;
- source version, Git commit, ETag, Last-Modified value, or other watermark when available;
- SHA-256 of the exact input object or response page used;
- parser version and canonical schema version;
- licence-policy version and the field rule that authorized publication; and
- whether Patch8 normalized, combined, or otherwise changed the value.

Patch8 must not claim that an upstream organization authored a merged or normalized Patch8 record. A source observation is different from the canonical row produced from several observations.

### Raw input

- `raw_payload`, raw JSON/XML/CSV bodies, HTML, PDFs, screenshots, and complete API envelopes are **deny by default** in public Parquet, manifests, Git history, GitHub Actions artifacts, and Hugging Face objects.
- The ingestion work directory may keep raw bytes privately until two successful releases have been verified, for no more than 90 days, unless a shorter source rule below applies. It must then retain only the input hash, byte size, retrieval metadata, and upstream immutable reference.
- A source already offering versioned Git history or dated archives should be pinned by commit/date and hash. Patch8 does not create a second public raw mirror merely for convenience.
- A raw object may be published later only through a separate field-policy change that identifies the exact upstream grant, required notices, necessity, and expiry/deletion behavior. There is no generic `allow_raw=true` switch.
- Failed or blocked-source fetches must not be uploaded as build artifacts. Credentials, request headers, cookies, and API envelopes containing account or quota information are never retained.

### Patch8-generated history

Patch8 may publish factual ingestion observations and diffs it creates, such as “field X changed at source watermark Y”, provided the old and new values are each independently allowed. A change event is not a way to launder blocked text: if a description is denied, its old/new text and textual diff are denied too. A hash-only event remains permitted.

## NVD API 2.0

**Owner and source.** The National Vulnerability Database is operated by the US National Institute of Standards and Technology. Use the CVE API 2.0 at `https://services.nvd.nist.gov/rest/json/cves/2.0` and, where needed, the CVE change-history API documented by NVD. The API, rather than legacy feeds, is NVD's preferred update mechanism.

**Governing terms.** NVD API use is subject to the NVD API Terms of Use and NIST website/data policy. NIST-authored non-SRD data is generally not protected by US copyright; NIST grants broad worldwide reuse rights for foreign rights it may hold, requires acknowledgement, and asks modified works to identify the date and nature of changes. NVD separately asks applications to display: “This product uses data from the NVD API but is not endorsed or certified by the NVD.” The API terms state that modified content must not be attributed to NVD. Patch8 must therefore say that its dataset is *derived from* NVD inputs and normalized by Link42, never that NVD authored the merged record.

NVD carries CVE Program and other third-party material. CVE Record content has a separate broad reuse licence under the CVE Program Terms of Use, conditional on reproducing MITRE's copyright designation and licence. Vendor comments, linked pages, and other non-CVE third-party content are not cleared merely because NVD displays them.

| Field class | Publication decision |
|---|---|
| Identifiers | **ALLOW** CVE IDs, CPE names, CWE IDs, NVD source identifiers, and factual aliases. |
| Dates | **ALLOW** published, last-modified, NVD analysis, and change-event times. |
| Scores | **ALLOW** NIST-authored CVSS vectors/scores and their source labels. CVSS v2 `baseSeverity` is authorized only at its exact metric-level API path; it is not treated as a `cvssData` field. **CONDITIONAL** CNA/vendor scores: publish only when the value has verified CVE Record lineage or an independently allowed source. |
| Descriptions | **CONDITIONAL**. Publish only a description that is byte-for-byte traceable to an official CVE Record covered by the CVE terms, with that lineage and notice. Do not publish NVD vendor comments or unidentified third-party prose. |
| Affected products/packages/ranges | **ALLOW** NIST CPE applicability statements, exact ordered configuration roots/nodes and Boolean operators, CPE URIs, factual vendor/product names, and version bounds. Preserve `source=NIST/NVD` and do not imply vendor confirmation. CNA affected data is allowed only with verified CVE Record lineage. |
| References | **ALLOW** URL, source label, and NVD tags as structured metadata. Do not mirror the linked page, its title/body, attachments, or vendor comment. Validate URL schemes before display. |
| Raw JSON | Rights may permit some NIST/CVE content, but **do not publish** complete API pages because they mix rights holders and unnecessary envelope data. Private build cache: global maximum of two verified releases/90 days. |
| History | **ALLOW** normalized NVD change-history events for allowed values; hash-only events for denied values. Do not publish raw third-party old/new prose. |

**Attribution and notice.** Dataset card, application legal page, and generated notices must acknowledge NIST/NVD, include the exact non-endorsement notice, link the NIST data policy and NVD API terms, identify Link42 transformations, and include the CVE/MITRE notice wherever CVE Record text is present.

**Refresh, authentication, and rate constraints.** Use modified-date windows, persist the last successful response watermark, and reconcile overlap. NVD recommends no more than one automated delta cycle every two hours and a six-second delay between requests. An API key raises available capacity but is optional, belongs to one requestor, must be sent in the documented header, and must never be shared or published. Respect current response headers and fail on throttling rather than increasing concurrency.

**Unresolved blocker.** None for the allow-listed fields. The parser must prove CVE lineage before enabling CVE descriptions or non-NIST scores; until then those fields are denied.

**Official evidence, accessed 2026-08-28:**

- [NVD API Terms of Use and API-key request](https://nvd.nist.gov/developers/request-an-api-key)
- [NVD data feeds and API preference](https://nvd.nist.gov/vuln/data-feeds)
- [NVD API automation guidance](https://nvd.nist.gov/general/news/API-Key-Announcement)
- [NVD general FAQ, enrichment and product-use notice](https://nvd.nist.gov/general/FAQ-Sections/General-FAQs)
- [NIST data, copyright, acknowledgement, and modification policy](https://www.nist.gov/open/license)
- [CVE Program Terms of Use](https://www.cve.org/legal/termsofuse)

## CISA Known Exploited Vulnerabilities

**Owner and source.** CISA is the authoritative owner. Fetch the stable JSON from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`; the official `cisagov/kev-data` repository may be used for commit history and change detection.

**Governing terms.** CISA publishes the KEV data repository under CC0 1.0 and states that its repository licence is identical to the licence distributed with the CISA feed. CC0 covers copyright and related database rights held by the affirmer, but does not grant trademark or patent rights and does not clear rights held by someone else. KEV's CISA-authored catalogue fields are usable; external vendor pages remain external.

| Field class | Publication decision |
|---|---|
| Identifiers | **ALLOW** CVE IDs, catalogue version, and vulnerability names as KEV catalogue data. |
| Dates | **ALLOW** date added, due date, and catalogue release/version dates. |
| Scores | Not supplied by KEV. Do not infer or copy a score into the KEV observation. |
| Descriptions | **ALLOW** CISA's short vulnerability name/description, required action, ransomware-use value, and notes under CC0. Preserve them as CISA observations rather than canonical vendor claims. |
| Affected products/packages/ranges | **ALLOW** KEV vendor/project and product fields. KEV does not establish complete affected-version ranges; do not invent them. |
| References | **ALLOW** CVE and upstream remediation URLs as URLs only. Do not mirror linked vendor content. |
| Raw JSON/CSV | **ALLOW by licence but do not publish** because the canonical CISA files are already public and versioned. Pin URL/commit and SHA-256. Normal Git/build cache only. |
| History | **ALLOW** commit-derived adds, edits, removals, catalogue version changes, and Patch8 observations. |

**Attribution and notice.** CC0 does not require attribution, but Patch8 will state “Source: CISA Known Exploited Vulnerabilities Catalog”, link the record/catalogue and CC0 licence, preserve the CISA source timestamp, and avoid CISA logos or endorsement claims.

**Refresh, authentication, and rate constraints.** Fetch once daily and on an approved manual rebuild. No authentication is required and CISA publishes no numeric request quota for the feed. Use conditional HTTP if available, or fetch the official Git repository once and compare commits; no page scraping.

**Unresolved blocker.** None for the enumerated fields.

**Official evidence, accessed 2026-08-28:**

- [CISA KEV catalogue and JSON/CSV links](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA KEV data repository, update schedule, usage, and CC0 statement](https://github.com/cisagov/kev-data)
- [CISA KEV CC0 licence](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)

## FIRST Exploit Prediction Scoring System

**Owner and source.** EPSS is maintained by the FIRST EPSS SIG; Empirical Security generates the daily scores. Patch8's approved use is the FIRST REST API as an on-demand, per-CVE lookup from the browser. Link42 will not use the daily gzip CSV or historical repository to ingest, build, host, synchronize, or redistribute an EPSS dataset.

**Governing terms.** FIRST says scores are free to use without registration and requests attribution in products and publications. Its current Services Terms of Use are narrower than an open-data licence: they grant a revocable, limited right to view, copy, print, and distribute content only for vulnerability disclosure, incident response, or preventative cybersecurity uses, with proprietary notices preserved. Showing a current score for the CVE a Patch8 user has requested is within the approved preventative-cybersecurity product purpose. A general-purpose public download cannot technically ensure that every downstream use remains within that purpose, and no CC0, CC BY, or other standard open-data licence was found for the score files.

| Use mode | Decision | Exact boundary |
|---|---|---|
| On-demand browser display | **Approved in this register; machine-disabled pending policy v2** | One current CVE lookup initiated by the user's detail view. Display only CVE, EPSS probability, percentile, score date, and model version with attribution. Keep no application-controlled durable copy. |
| Public or shared dataset | **CONDITIONAL / BLOCKED** | Do not create or host current/history tables, derived EPSS files, a shared cache, a public API, or any downloadable EPSS dataset without separate written republication permission and tested downstream notices. |
| Raw, bulk, history, or export | **BLOCK** | Do not display/log the raw API response, fetch bulk CSV/history for Link42, provide raw/normalized bulk or history export, or rehost FIRST artifacts. |

| Field class | EPSS use decision |
|---|---|
| Identifiers | **DISPLAY ONLY** the requested CVE ID; **DENY** EPSS-derived dataset publication. |
| Dates | **DISPLAY ONLY** the current score date; a transient fetch time may appear as client state but must not become a shared observation history. |
| Scores | **DISPLAY ONLY** current EPSS probability and percentile; label them as a forecast, not severity or complete risk, and preserve model version. **DENY** dataset publication. |
| Descriptions | **DENY**. EPSS does not provide vulnerability descriptions; do not copy FIRST explanatory prose into the UI or data. |
| Affected products/packages/ranges | Not supplied; **DENY** any inferred association beyond the CVE join. |
| References | **ALLOW FOR DISPLAY** links to FIRST's EPSS definition, data page, terms, and applicable score date/source. |
| Raw CSV/API JSON | **DENY** display, logging, durable storage, export, and republication. Patch8 does not fetch the daily CSV. The browser adapter parses an allowed response in memory and discards it. |
| History | **DENY** collection, publication, or export. Do not reproduce the underlying model inputs or exploitation telemetry, which FIRST says it cannot redistribute. |

**Attribution and notice.** If the direct-display mode is enabled after the machine-policy extension, the CVE detail and product legal page must credit “Exploit Prediction Scoring System (EPSS), FIRST.org; scores generated by Empirical Security”, link the data page and FIRST terms, preserve model/date, state the preventative-cybersecurity purpose, and state that EPSS is not severity or a complete risk score. Because no EPSS dataset is published, Patch8 must not generate an EPSS dataset card or imply that Link42 owns or refreshes the score.

**Request, authentication, and retention constraints.** No authentication is required. After the version 2 gate is implemented, issue at most one bounded API lookup for the CVE whose detail view the user opened; debounce duplicate UI activity and use only transient in-memory request coalescing. Do not prefetch lists, fan out across search results, synchronize in the background, use the API for bulk work, or write EPSS values or raw responses to OPFS, IndexedDB, local storage, a service-worker cache, logs, analytics, build artifacts, Git, Hugging Face, or any Link42-controlled server. Normal user-agent transport caching must be disabled where the browser API permits. On failure, show EPSS as unavailable rather than substituting stored Link42 data.

**Unresolved blockers.** Direct display is approved only at the human-policy level. Version 1 of the machine policy cannot distinguish it from dataset publication, so `patch8_first_epss.enabled=false` remains mandatory until the closed version 2 `use_modes` schema, validator rules, per-mode caller contract, attribution tests, and no-persistence/no-export tests described above are implemented. Public dataset republication remains separately blocked pending written FIRST confirmation covering the exact normalized fields/history and a tested mechanism for communicating the downstream-use restriction. Patch8 ships without EPSS until the direct-display machine gate is complete, and without an EPSS dataset unless the republication blocker is later resolved.

**Official evidence, accessed 2026-08-28:**

- [FIRST EPSS data access and bulk-use guidance](https://www.first.org/epss/data.html)
- [FIRST EPSS FAQ, free-use and attribution statements](https://www.first.org/epss/faq)
- [FIRST Services Terms of Use](https://www.first.org/about/policies/FIRST-Services-Terms-of-Use.pdf)
- [FIRST API rate-limit documentation](https://api.first.org/)
- [FIRST EPSS API fields](https://api.first.org/epss/)
- [Official historical EPSS score repository named by FIRST](https://github.com/empiricalsec/epss_scores)

## CISA Vulnrichment

**Owner and source.** CISA publishes Vulnrichment through `https://github.com/cisagov/vulnrichment`. Patch8 should fetch the repository by Git commit and extract only CISA's ADP container and its source metadata.

**Governing terms.** The repository is under CC0 1.0. Its files are complete CVE JSON records containing a CNA container plus CISA ADP enrichment. CISA's CC0 can waive only rights CISA holds; it does not by itself clear third-party CNA text. The independently applicable CVE Program Terms permit CVE reuse with MITRE's copyright designation and licence reproduced. Patch8 nevertheless avoids using Vulnrichment as a duplicate full-CVE feed: it imports CISA ADP fields here and obtains canonical CVE descriptions/affected data through separately governed sources.

| Field class | Publication decision |
|---|---|
| Identifiers | **ALLOW** CVE ID, ADP provider metadata, and CISA observation identifiers. |
| Dates | **ALLOW** ADP update/publish timestamps and SSVC decision timestamp. |
| Scores | **ALLOW** CISA-authored SSVC decision points and CISA-provided CVSS vectors/scores; preserve author and timestamp. |
| Descriptions | **DENY from this source** by product policy. CNA descriptions may be reusable under CVE terms, but Patch8 must ingest them once from the canonical CVE/NVD lineage, not through Vulnrichment. |
| Affected products/packages/ranges | **DENY from this source** unless CISA later authors a distinct ADP affected assertion and the field rule is reviewed. Do not republish the embedded CNA container here. |
| References | **ALLOW** CISA ADP reference URLs and minimal CVE record link metadata. Do not mirror linked material. |
| Raw JSON | **ALLOW only to the extent of the applicable CC0/CVE grants, but do not publish**. Use pinned Git blobs during the build and retain commit/blob hashes. |
| History | **ALLOW** CISA ADP field changes and commit observations. For embedded CNA fields publish hashes only, since those values are intentionally not sourced here. |

**Attribution and notice.** Credit CISA Vulnrichment and link the exact repository commit and CC0. Because the upstream object is a CVE Record, also include the CVE/MITRE copyright designation and licence in dataset notices. State that Link42 extracted the CISA ADP container; do not imply CISA endorsed Patch8.

**Refresh, authentication, and rate constraints.** Perform a daily `git fetch` of the public repository and process commits after the stored SHA. No authentication is required for public Git access. If GitHub API calls are used for metadata, they inherit GitHub's rate limits; file-by-file API crawling is prohibited by Patch8 policy.

**Unresolved blocker.** None for the allow-listed CISA ADP fields. Parser tests must reject CNA-container leakage.

**Official evidence, accessed 2026-08-28:**

- [CISA Vulnrichment repository and ADP description](https://github.com/cisagov/vulnrichment)
- [CISA Vulnrichment CC0 licence](https://github.com/cisagov/vulnrichment/blob/develop/LICENSE)
- [CVE Program Terms of Use](https://www.cve.org/legal/termsofuse)

## OSV

**Owner and source.** OSV.dev is operated by Google as an aggregator of many independent “home” vulnerability databases. It publishes full OSV JSON records in `gs://osv-vulnerabilities`, ecosystem ZIP files, and `modified_id.csv` delta indexes, and offers an API at `https://api.osv.dev`.

**Governing terms.** The OSV infrastructure and schema code are Apache-2.0, but that software licence is not a blanket licence for the aggregated vulnerability records. OSV's own documentation stresses that records come from separate home databases. The official documentation provides bulk downloads and reports no current API rate limit, but no current official page was found granting one licence over the whole aggregated database. An official OSV issue asking for a data licence is closed without a visible answer. Therefore each home database's exact licence must control each imported record.

| Field class | Publication decision |
|---|---|
| Identifiers | **CONDITIONAL** OSV/home ID and aliases only when `home_database` is resolved to an approved licence entry. |
| Dates | **CONDITIONAL** published, modified, and withdrawn dates under the home database's approved terms. |
| Scores | **CONDITIONAL** only when the record identifies the score's author/source and that source is separately allowed. Never treat Apache-2.0 on OSV code as the score licence. |
| Descriptions | **CONDITIONAL** on the home database licence permitting republication and required attribution. Unknown or inherited prose is denied. |
| Affected packages/ranges | **CONDITIONAL** package coordinates and explicit upstream range events from an allowed home database. **DENY** OSV-generated full `affected.versions[]` enumeration until OSV grants reuse rights to that enrichment. |
| References | **CONDITIONAL** URL/type metadata under an allowed home database; linked content is never mirrored. |
| Raw JSON/ZIP/API response | **DENY** public republication. Unknown-licence records must not be fetched into durable shared storage. Allowed records may exist in a private build cache only through release verification, then are deleted. |
| History | **CONDITIONAL** modified/withdrawn observations for allowed fields. Deletion handling must preserve a tombstone and provenance, not stale content. |

**Attribution and notice.** Attribute the home database first, then “aggregated/normalized via OSV.dev” where applicable. Carry the home database licence, record URL, OSV record URL, and Link42 modification notice. OSV's Apache-2.0 code notice must not be presented as the data licence.

**Refresh, authentication, and rate constraints.** Prefer the GCS `modified_id.csv` delta and ecosystem files over per-record API fan-out. No authentication is required. OSV currently documents no API rate limit, but the API has response-size constraints; normal backoff and bounded concurrency still apply. Track withdrawn/deleted behavior explicitly.

**Unresolved blocker.** Build and approve a home-database licence registry before enabling OSV. It must at least cover every home database seen in the selected ecosystems and reject unknown values. Records already covered directly by GHSA should come from the GHSA repository, not OSV. Until that registry and tests exist, `osv.enabled=false`.

**Official evidence, accessed 2026-08-28:**

- [OSV introduction and aggregator model](https://google.github.io/osv.dev/)
- [OSV FAQ: bulk exports, deltas, enrichment, deletion, and rate limits](https://google.github.io/osv.dev/faq/)
- [OSV data-source list](https://github.com/google/osv.dev/blob/master/source.yaml)
- [OSV infrastructure repository and Apache-2.0 code licence](https://github.com/google/osv.dev)
- [Official OSV data-licence issue showing the unresolved question](https://github.com/google/osv.dev/issues/63)

## GitHub Security Advisory Database and API

**Owner and source.** GitHub owns and curates the GitHub Advisory Database. For bulk/history ingestion use `https://github.com/github/advisory-database` at a pinned commit. The REST and GraphQL APIs may be used for bounded lookups or reconciliation, not as the primary bulk source.

**Governing terms.** GitHub's Additional Product Terms license the Advisory Database under Creative Commons Attribution 4.0. The terms say attribution may be satisfied with a link to the database or individual advisory. The repository repeats CC BY 4.0. API access is additionally subject to GitHub's API Terms and rate limits.

| Field class | Publication decision |
|---|---|
| Identifiers | **ALLOW** GHSA IDs, CVE aliases, and other aliases. |
| Dates | **ALLOW** published, modified, withdrawn, and Git commit observation dates. |
| Scores | **ALLOW** severity labels and CVSS vectors/scores present in the licensed advisory, preserving author/source. |
| Descriptions | **ALLOW** summary and details under CC BY 4.0. Mark Link42 normalization/truncation and never silently rewrite meaning. |
| Affected packages/ranges | **ALLOW** ecosystem, package/PURL, range events, vulnerable versions, and patched versions under CC BY 4.0. |
| References | **ALLOW** URL/type and credits from the advisory. Do not mirror linked pages or attachments. |
| Raw JSON | **ALLOW by licence but do not publish** as a second advisory-database mirror. Build from a pinned Git commit; keep commit/blob hashes. |
| History | **ALLOW** Git commit-derived field changes, withdrawals, and Patch8 observations with the same attribution and modification notice. |

**Attribution and notice.** Include “GitHub Advisory Database, CC BY 4.0”, a database or per-record advisory link, the CC BY 4.0 link, and a notice that Link42 transformed the data. Preserve advisory credits where published. Do not use GitHub marks to imply endorsement.

**Refresh, authentication, and rate constraints.** Daily shallow fetch plus the last pinned commit is preferred and requires no token for the public repository. REST public data allows unauthenticated access but is normally limited to 60 requests/hour; authenticated users normally receive 5,000 requests/hour, and a repository `GITHUB_TOKEN` normally receives 1,000 requests/hour. Secondary limits and `Retry-After`/rate headers must be respected. Never share tokens to evade limits.

**Unresolved blocker.** None for repository content. API-derived fields must be reconciled to the licensed repository record or separately proven to fall within the Advisory Database licence before publication.

**Official evidence, accessed 2026-08-28:**

- [GitHub Advisory Database repository and CC BY 4.0 statement](https://github.com/github/advisory-database)
- [GitHub Additional Product Terms: Advisory Database licence and attribution](https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features#github-advisory-database)
- [GitHub global security-advisory REST API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [GitHub REST API rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [GitHub Terms of Service API terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service#h-api-terms)

## ENISA European Vulnerability Database

**Owner and source.** The European Union Agency for Cybersecurity operates EUVD. The public API base is `https://euvdservices.enisa.europa.eu`; official documentation is at `https://euvd.enisa.europa.eu/apidoc`. The API includes paginated search, individual records, a daily full CVE-to-EUVD mapping CSV, and a daily consolidated KEV dump.

**Governing terms.** ENISA's legal notice defines covered material to include data and text and authorizes reproduction of ENISA material with source acknowledgement unless stated otherwise. It separately warns that permission for material not under ENISA copyright must be obtained from the rightsholder and that third-party sources remain third-party. No field-level rights marker was found in the EUVD API response contract. ENISA's permission supports its own identifier/mapping/compilation fields, but does not automatically clear descriptions, scores, or vendor content imported from other databases.

| Field class | Publication decision |
|---|---|
| Identifiers | **ALLOW** EUVD ID and the official EUVD-to-CVE mapping. **CONDITIONAL** other aliases on identified, allowed upstream provenance. |
| Dates | **ALLOW** EUVD published/updated observations and mapping-dump date as ENISA database metadata. |
| Scores | **DENY by default**. EPSS must come from the separately governed FIRST source. CVSS may be published only when EUVD identifies an independently allowed author/source. |
| Descriptions | **DENY by default** because EUVD aggregates third-party descriptions without a per-field licence marker. An ENISA-authored description may be enabled only with an explicit authorship test or written clarification. |
| Affected products/packages/ranges | **CONDITIONAL** on an identified upstream source whose licence is already allowed. Vendor/product/version strings with no field provenance are denied. |
| References | **ALLOW** reference URL and factual source identifier. Do not copy linked titles, pages, documents, or vendor text. |
| Raw JSON/CSV | The ENISA mapping CSV is reusable with acknowledgement but **not republished** because the official dump exists. Full API records and KEV dump are **DENY** as raw mirrors because they mix third-party material. Private cache maximum: release verification plus 30 days. |
| History | **ALLOW** Patch8 observation time, EUVD published/updated time, and mapping changes. **DENY** textual old/new values unless their field source is independently allowed. |

**Attribution and notice.** State “Source: European Union Agency for Cybersecurity (ENISA), European Vulnerability Database”, link the record/API and ENISA legal notice, and identify Link42 modifications. Do not reproduce the ENISA logo or imply an official/authentic ENISA publication.

**Refresh, authentication, and rate constraints.** All documented endpoints are GET and require no authentication. Search is limited to 100 records per response; mapping and KEV dumps update daily at 07:00 UTC. ENISA publishes no numeric request-rate ceiling in the API documentation. Fetch daily with bounded serial pagination, overlap/reconciliation, conditional requests where supported, and exponential backoff.

**Unresolved blocker.** Obtain field-level provenance or written ENISA confirmation before enabling descriptions, scores, or affected products from EUVD. The API must also gain a deterministic delta/reconciliation strategy; page-number iteration alone can shift during a build. Until then only the mapping and ENISA-owned metadata fields are enabled.

**Official evidence, accessed 2026-08-28:**

- [EUVD API documentation, endpoints, limits, and update schedule](https://euvd.enisa.europa.eu/apidoc)
- [ENISA legal notice and reproduction/third-party rules](https://www.enisa.europa.eu/about-enisa/legal-notice)
- [EUVD purpose and authority](https://euvd.enisa.europa.eu/about)

## Microsoft MSRC CVRF and CSAF

**Owner and source.** Microsoft Security Response Center publishes the CVRF update catalogue through `https://api.msrc.microsoft.com/cvrf/v3.0/updates` and public CSAF metadata at `https://msrc.microsoft.com/csaf/provider-metadata.json`. CSAF is the preferred modern machine-readable channel; Microsoft says the Security Update Guide/CVRF remains available.

**Governing terms.** Microsoft intentionally publishes machine-readable documents, but machine readability is not a redistribution licence. The general Microsoft Terms of Use limit services to personal/non-commercial use unless otherwise specified and prohibit copying, distribution, publication, and derivative works without permission. The open-source MSRC API client and Swagger are MIT-licensed, but that code licence does not license API output or advisory content. No blanket open-data or redistribution grant for MSRC CVRF/CSAF content was found. The general Microsoft API Terms page enumerates covered Microsoft APIs and does not clearly identify the MSRC Security Updates API, so Patch8 must not use unrelated API terms as an implied grant.

| Field class | Publication decision |
|---|---|
| Identifiers | **BLOCK from MSRC**. CVE IDs may still be published when obtained from an allowed CVE/NVD/GHSA source. A static link to an official MSRC advisory is allowed. |
| Dates | **BLOCK** MSRC-specific release/revision dates as an ingested dataset until permission is obtained. |
| Scores | **BLOCK** Microsoft severity/CVSS assertions. |
| Descriptions | **BLOCK** titles, descriptions, FAQ, impact, mitigation, workaround, and remediation text. |
| Affected products/packages/ranges | **BLOCK** Microsoft product trees, KB/product status, and affected/fixed relationships. |
| References | **ALLOW only** a manually or independently sourced official MSRC advisory URL associated with an otherwise allowed CVE. Do not ingest MSRC reference collections. |
| Raw JSON/XML | **BLOCK** retrieval into durable ingestion storage and **deny** publication. |
| History | **BLOCK** MSRC revision history; Patch8 may record only that an official link was configured/checked. |

**Attribution and notice.** If Microsoft later grants permission, the grant must specify copyright notice, Microsoft attribution, modification marking, trademark/non-endorsement treatment, downstream terms, and whether complete CSAF/CVRF documents may be retained. Until then Patch8 only links to Microsoft.

**Refresh, authentication, and rate constraints.** The official client documentation says the CVRF API no longer requires an API key, and CSAF is publicly discoverable. No official numeric rate limit was found. Because the source is blocked, no scheduled fetch, credential, cache, or retry policy is created.

**Unresolved blocker.** Written Microsoft permission or an explicit licence in each CSAF document that permits extraction, modification, public redistribution, and downstream reuse. An explicit per-document grant could later be allow-listed; absence of a grant remains fail-closed.

**Official evidence, accessed 2026-08-28:**

- [Microsoft MSRC machine-readable CSAF announcement and provider URL](https://www.microsoft.com/en-us/msrc/blog/2024/11/toward-greater-transparency-publishing-machine-readable-csaf-files)
- [Microsoft CSAF directory](https://msrc.microsoft.com/csaf)
- [Official MSRC Security Updates API repository and Swagger](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API)
- [Microsoft general Terms of Use](https://www.microsoft.com/en-us/legal/terms-of-use)
- [Microsoft copyrighted-content permission guidance](https://www.microsoft.com/en-us/legal/intellectualproperty/copyright/permissions)

## MITRE Common Weakness Enumeration

**Owner and source.** The MITRE Corporation manages CWE. Use a versioned XML ZIP from the official CWE downloads/archive rather than scraping individual pages. Record CWE version, archive URL, published date, and SHA-256.

**Governing terms.** MITRE grants a non-exclusive, royalty-free licence to use CWE for research, development, and commercial purposes. Copies are authorized if they reproduce MITRE's copyright designation and the CWE licence. Contributor material is subject to a broad perpetual downstream licence stated in the terms. CWE names and logos remain MITRE trademarks.

| Field class | Publication decision |
|---|---|
| Identifiers | **ALLOW** CWE IDs, entry type, abstraction, status, and relationship IDs. |
| Dates | **ALLOW** release, modification, submission, and content-history dates. |
| Scores | Not a CWE field; **DENY** invented weakness scores/rankings. |
| Descriptions | **ALLOW** CWE name, description, extended description, consequences, detection/mitigation text, and notes under the CWE terms. Preserve structure and indicate any truncation/transformation. |
| Affected products/packages/ranges | Not supplied as vulnerability affected data. **ALLOW** applicable platform/language/technology metadata; do not convert it into a product vulnerability assertion. |
| References | **ALLOW** CWE external-reference metadata and URLs. The licence does not authorize mirroring linked third-party documents. |
| Raw XML/CSV | **ALLOW by licence but do not publish** as a duplicate archive. Retain the pinned archive URL/hash/version; local input may be deleted after release verification. |
| History | **ALLOW** CWE content history, version-to-version changes, deprecations, and Patch8 observations. |

**Attribution and notice.** Include MITRE's CWE copyright designation and CWE Terms of Use in the dataset notices; attribute The MITRE Corporation, link the exact CWE version, and state Link42 transformations. Use “CWE” only to identify the source/standard and do not use the logo or imply compatibility/endorsement.

**Refresh, authentication, and rate constraints.** Check the downloads page daily but fetch only when the published version changes. No authentication or numeric rate limit is documented for the release ZIP. Pin a versioned archive, not `latest`, for the build.

**Unresolved blocker.** None for the enumerated fields. The generator must stop if the XML version differs from the expected schema or if the required copyright/licence notice cannot be emitted.

**Official evidence, accessed 2026-08-28:**

- [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html)
- [CWE versioned downloads](https://cwe.mitre.org/data/downloads.html)
- [CWE release archive](https://cwe.mitre.org/data/archive/)
- [CWE FAQ on licence, downloads, and history](https://cwe.mitre.org/about/faq.html)

## Cisco PSIRT openVuln API

**Owner and source.** Cisco PSIRT operates the authenticated openVuln API at `https://apix.cisco.com/security/advisories/v2`. It returns Cisco advisory identifiers, CVEs, scores, products, summaries, and CVRF/CSAF/publication links.

**Governing terms.** Access requires a Cisco account, registered service application, client credentials, OAuth token, and acceptance of Cisco's API terms. Those terms grant a non-transferable, non-sublicensable right to call the API solely to build applications that work, communicate, or interact with Cisco products or services. They do not grant a clear right to republish the advisory-response database as a general public dataset, and they reserve all ungranted rights. Credentials must remain confidential and cannot be embedded in open source.

| Field class | Publication decision |
|---|---|
| Identifiers | **EXCLUDE** Cisco advisory/bug IDs and API-derived CVE associations in the first release. CVE IDs may come from allowed sources. |
| Dates | **EXCLUDE** Cisco first-published/last-updated/status/version fields. |
| Scores | **EXCLUDE** Cisco CVSS and severity/SIR. |
| Descriptions | **EXCLUDE** advisory title, summary, impact, workaround, and remediation text. |
| Affected products/packages/ranges | **EXCLUDE** Cisco product names and Software Checker results. |
| References | **ALLOW only** a manually or independently sourced public Cisco advisory URL attached to an otherwise allowed CVE. No API collection. |
| Raw JSON/XML/CSAF | **EXCLUDE** fetch, retention, and publication. |
| History | **EXCLUDE** API-derived advisory history. |

**Attribution and notice.** None is implemented because the source is excluded. Any later proposal must define Cisco attribution, trademark/non-endorsement language, advisory-specific distribution terms, and downstream rights.

**Refresh, authentication, and rate constraints.** No fetch in the first release. A future approved implementation would require OAuth client credentials and must respect Cisco's documented default quotas: 5 calls/second, 30 calls/minute, and 5,000 calls/day, plus `429` and `Retry-After`. The secret may exist only in a protected ingestion workflow, never in browser code, public data, logs, or artifacts.

**Unresolved blocker.** Product priority plus written or advisory-level terms permitting extraction, modification, public redistribution, and downstream reuse. A registered API application alone does not resolve redistribution. This source must be absent from the first canonical source enum and manifest, matching the F1 decision.

**Official evidence, accessed 2026-08-28:**

- [Cisco PSIRT openVuln getting started](https://developer.cisco.com/docs/psirt/getting-started/)
- [Cisco PSIRT authentication requirements](https://developer.cisco.com/docs/psirt/authentication/)
- [Cisco PSIRT pagination and rate limits](https://developer.cisco.com/docs/psirt/browsing-sorting-filterting-and-rate-limits/)
- [Cisco API Licence Terms and Conditions](https://developer.cisco.com/site/license/cisco-api-license/)
- [Cisco PSIRT API terms pointer](https://github.com/CiscoPSIRT/openVulnAPI/blob/master/LICENSE.md)

## Superseded F2 implementation sketch

The YAML and test list below are retained only as historical F2 research context. They are not normative and use old
source identifiers and broad field groups. P3 replaced them with the closed
[`source-policy.json`](source-policy.json), [`source-policy.schema.json`](../../contracts/source-policy.schema.json),
[`data-content-v1.json`](../../contracts/data-content-v1.json), and tested Patch8 manifest contract. Implementations must
use those machine files and their exact `patch8_*` source identities, repositories, allowed fields, blocked artifacts,
required notices, publication modes, immutable-revision requirements, and output derivation ledger; none may be widened
by a producer manifest. NVD configuration/node identifiers are Link42 derivations from pinned source paths, not raw NVD
fields. The complete semantic policy and data-content contract are independently sealed to their declared version pair.
Any approved material policy or contract drift must increment both versions and add a new reviewed baseline; an existing
version baseline is never changed in place. P3b's approved `2:2.0.0` transition adds only the exact NVD CVSS-v2
severity/state paths and representation needed for source-specific metadata/configuration observations; it removes KEV
release fields from per-entry rows without changing CISA's allowed source fields. No direct EPSS mode is approved.

```yaml
policy_version: 1
defaults:
  source_enabled: false
  field: deny
  public_raw_payload: deny
  unknown_home_database: deny
  unknown_rights_holder: deny
  copy_linked_content: deny

sources:
  nvd:
    enabled: true
    decision: allow
    allow:
      - cve.id
      - cve.published
      - cve.lastModified
      - cve.sourceIdentifier
      - nvd.cvss.*
      - nvd.weakness.cwe_id
      - nvd.configuration.cpe
      - nvd.configuration.version_bounds
      - nvd.reference.url
      - nvd.reference.tags
      - nvd.history.allowed_value_change
    conditional:
      cve.description: exact_official_cve_record_lineage
      cna.cvss.*: independently_allowed_source_or_cve_lineage
      cna.affected.*: exact_official_cve_record_lineage
    deny:
      - vendor_comment.*
      - raw_response

  cisa_kev:
    enabled: true
    decision: allow
    allow:
      - catalogVersion
      - dateReleased
      - vulnerabilities.*
      - normalized_history.*
    deny: [raw_response]

  first_epss:
    enabled: false
    decision: conditional
    enable_when: use_mode_policy_v2_is_validated
    planned_use_modes:
      browser_direct_display:
        enabled: true
        decision: allow
        allow: [cve, date, epss, percentile, model_version]
        retention: transient_memory_only
        require: [preventative_cybersecurity_purpose, first_empirical_security_attribution]
        deny: [raw_response, durable_cache, shared_cache, bulk_query, history, export, rehosting]
      public_dataset_republication:
        enabled: false
        decision: conditional
        enable_when: written_bulk_republication_confirmation_and_downstream_notice
        allow: []
        deny: [raw_response, raw_csv, normalized_current_table, normalized_history_table, export, rehosting, explanatory_text, model_inputs, exploitation_telemetry]

  cisa_vulnrichment:
    enabled: true
    decision: allow
    allow:
      - cveMetadata.cveId
      - containers.adp[provider=CISA-ADP].providerMetadata
      - containers.adp[provider=CISA-ADP].metrics
      - containers.adp[provider=CISA-ADP].problemTypes
      - containers.adp[provider=CISA-ADP].references.url
      - normalized_adp_history.*
    deny:
      - containers.cna.*
      - raw_record

  osv:
    enabled: false
    decision: conditional
    enable_when: home_database_license_registry_complete
    allow_if_home_database_allowed:
      - id
      - aliases
      - published
      - modified
      - withdrawn
      - summary
      - details
      - severity
      - affected.package
      - affected.ranges.events
      - references
    deny:
      - affected.versions
      - raw_record

  github_advisory_database:
    enabled: true
    decision: allow
    allow:
      - id
      - aliases
      - published
      - modified
      - withdrawn
      - summary
      - details
      - severity
      - affected.*
      - references
      - credits
      - normalized_history.*
    deny: [raw_record]

  enisa_euvd:
    enabled: true
    decision: conditional
    allow:
      - euvd_id
      - cve_euvd_mapping
      - euvd_published
      - euvd_updated
      - reference.url
      - normalized_mapping_history.*
    conditional:
      aliases: independently_allowed_source
      scores: identified_independently_allowed_source
      affected: identified_independently_allowed_source
      description: proven_enisa_authorship_or_written_permission
    deny: [raw_response, embedded_epss]

  microsoft_msrc:
    enabled: false
    decision: block
    allow: [manually_configured_official_advisory_url]
    deny: [api_response, csaf_document, cvrf_document, derived_fields, history]

  mitre_cwe:
    enabled: true
    decision: allow
    allow:
      - cwe_id
      - name
      - description
      - extended_description
      - relationships
      - status
      - applicable_platforms
      - consequences
      - detection_methods
      - mitigations
      - notes
      - external_reference_metadata
      - content_history
    deny: [linked_document_body, invented_score, raw_archive]

  cisco_psirt:
    enabled: false
    decision: exclude
    register_source: false
    register_credentials: false
    allow: [manually_configured_official_advisory_url]
    deny: [api_response, csaf_document, cvrf_document, derived_fields, history]
```

Required enforcement tests:

1. Unknown `source_id`, home database, upstream field, nested object, licence version, or rights holder fails the build.
2. A source marked disabled, blocked, or excluded cannot create canonical rows, provenance rows, raw archives, manifests, dataset-card source claims, or browser requests. This keeps EPSS fully disabled under policy version 1.
3. Raw payload keys and complete serialized upstream objects cannot enter public tables or Actions artifacts.
4. Every emitted field resolves to one exact allow/conditional rule and one notice bundle; conditions are evaluated from verified provenance, not caller-supplied booleans.
5. NVD descriptions and CNA fields fail without a matching official CVE Record lineage hash; NVD vendor comments always fail.
6. Vulnrichment CNA-container fields fail even though the surrounding repository is CC0.
7. OSV records fail for an unknown home database and `affected.versions[]` fails even for an otherwise allowed record until OSV enrichment rights are resolved.
8. EUVD descriptions, embedded EPSS, scores, and affected data fail without the required authorship/source condition.
9. MSRC and Cisco network adapters are absent from the default registry; a manually configured official URL cannot unlock any other field.
10. Required NVD, CVE/MITRE, GitHub CC BY, ENISA, and CWE notices are generated from policy metadata and snapshot-tested. A future EPSS direct-display adapter must snapshot-test its FIRST/Empirical Security attribution, model/date labels, and forecast disclaimer in the UI rather than generating an EPSS dataset notice.
11. Licence-policy version and a deterministic notice manifest are included in every dataset release manifest.
12. A terms/licence URL or recorded terms hash change disables that source until a human reviews and increments `policy_version`.
13. Policy version 2 requires every source use to name a closed `use_modes` entry. Missing and unknown modes fail closed; enabling `browser_direct_display` cannot enable `public_dataset_republication` or populate its allowed fields.
14. EPSS direct-display tests prove one-CVE request scoping, response projection, transient-memory-only handling, attribution, no background/prefetch/bulk/history path, no durable cache or logs, no export/rehosting, and an explicit unavailable state on failure.

## F1 completeness cross-check

The F1 Patch8 inventory named ten upstream candidates. All ten are covered here:

- NVD API 2.0;
- CISA KEV;
- FIRST EPSS;
- CISA Vulnrichment;
- OSV;
- GitHub Security Advisories;
- ENISA EUVD;
- Microsoft MSRC CVRF/CSAF;
- MITRE CWE; and
- Cisco PSIRT, explicitly excluded from the first release.

This register also resolves the F1 raw-archive gap: historical R2-style archiving is not carried forward. Public raw
payload publication is fail-closed, and private short-lived build retention is source-specific. P3's machine contracts
enforce this register. Later features must not add a source or field without an approved policy/contract version change.
