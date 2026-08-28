# Patch8 browser-direct API evaluation

**Status:** **source-complete** for F5 source selection and evaluation; F7/F8 browser and resilience validation remains planned.

**Evidence date:** 2026-08-28

This record evaluates the first-release Patch8 point-detail sources from a local static origin representative of GitHub Pages. It separates browser transport compatibility from the [F2 source-rights policy](../licensing/README.md): a successful cross-origin request does not enable a source or a field.

Current decision:

- **NVD API 2.0:** launch-approved for the F2 allow-listed fields.
- **CISA KEV:** launch-approved through an immutable commit in CISA's official `cisagov/kev-data` repository. The mutable `cisa.gov` JSON is not browser-direct in the observed configuration.
- **FIRST EPSS:** technically browser-compatible. The human policy approves narrow on-demand preventative-cybersecurity display, but machine policy v1 keeps it disabled until a closed policy-v2 `use_modes` contract is implemented and tested.
- **OSV:** technically browser-compatible but disabled until the F2 home-database licence registry exists and approves each record's lineage.

There is no Link42 ingestion job, runtime database, API proxy, or browser credential for these sources. F5 is complete because the source-selection outcome and its evidence are recorded; current Chrome, Firefox, and Safari correctness, cache, constrained-network, failure, throttling, and performance work belongs to F7/F8 and is not claimed complete here.

## Probe boundary

The browser observations came from repeated `fetch` GETs in an in-app browser page served by a localhost static server. Requests carried no API key, bearer token, cookie, or other source credential. The timing intervals are the observed spread across those probes, including browser and network cache effects; they are not controlled benchmarks or service-level guarantees.

| Source and exact request | Browser observation | Response identity | Observed CORS | Launch state |
|---|---|---|---|---|
| NVD: [`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094`](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094) | HTTP `200`, approximately `355-690 ms` | `totalResults: 1`; sole record ID `CVE-2024-3094` | `Access-Control-Allow-Origin: *` | **Enabled** |
| FIRST: [`https://api.first.org/data/v1/epss?cve=CVE-2024-3094`](https://api.first.org/data/v1/epss?cve=CVE-2024-3094) | HTTP `200`, approximately `1-816 ms` | `total: 1`; sole row for `CVE-2024-3094` | `Access-Control-Allow-Origin: *` | **Disabled by F2** |
| OSV: [`https://api.osv.dev/v1/vulns/CVE-2024-3094`](https://api.osv.dev/v1/vulns/CVE-2024-3094) | HTTP `200`, approximately `347-594 ms` | record ID `CVE-2024-3094` | ACAO echoed the localhost origin in the header recheck | **Disabled by F2** |
| CISA canonical: [`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Server returned HTTP `200`, but the browser cannot read this cross-origin response | Mutable official catalogue | No `Access-Control-Allow-Origin` header was observed | Not a browser-direct runtime path |
| CISA official GitHub copy: [`known_exploited_vulnerabilities.json` at `5665af1...`](https://raw.githubusercontent.com/cisagov/kev-data/5665af188f94ef09be76e53630b5fc520777fa69/known_exploited_vulnerabilities.json) | HTTP `200`, approximately `7-445 ms` | `count: 1685`, exactly `1,685` array rows; includes `CVE-2021-44228` | `Access-Control-Allow-Origin: *` | **Enabled at this pin** |

The short warm observations, particularly `1 ms` and `7 ms`, must not be treated as cold network latency. Browser request counts, transferred bytes, peak memory, and cache provenance were not captured.

## NVD API 2.0

The exact-CVE request uses the official [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) with the documented `cveId` filter. The observed response used this shape:

```text
totalResults
vulnerabilities[]
  cve.id
  cve.sourceIdentifier
  cve.published
  cve.lastModified
  cve.vulnStatus
  cve.descriptions[] { lang, value }
  cve.metrics
  cve.weaknesses[]
  cve.configurations[]
  cve.references[] { url, source, tags }
```

The Patch8 adapter may display only fields authorized in the [Patch8 licence register](../licensing/patch8.md): identifiers and dates; NIST-authored CVSS vectors, scores, and source labels; CWE values; NIST CPE applicability and explicit version bounds; and reference URL/source/tag metadata. Description or non-NIST score display remains fail-closed unless the adapter proves the required CVE Record lineage. External reference bodies are never fetched or mirrored.

The sampled `CVE-2024-3094` result had `published=2024-03-29T17:15:21.150`, `lastModified=2026-06-17T07:43:17.830`, `vulnStatus=Modified`, CVSS v3.1 base score `10.0`, `CWE-506`, and CPE matches for xz `5.6.0` and `5.6.1`. Those values demonstrate the adapter shape, not a permanent snapshot; NVD is a live mutable point source.

No NVD API key was used, and Patch8 must not ship one. The official public-client guidance requires conservative pacing; the app must debounce exact-CVE requests, cache a successful observation with its upstream timestamps, and avoid background fan-out. HTTP `403`, `429`, timeout, malformed JSON, or a service failure must render a source-unavailable/stale state rather than “no vulnerability found”. A last verified browser-cached response may be shown with its retrieval time and a stale label.

## FIRST EPSS

The official [FIRST EPSS API](https://api.first.org/epss/) returned this logical shape:

```text
status
status-code
version
access
total
offset
limit
data[] { cve, epss, percentile, date }
```

The localhost browser probe proved unauthenticated transport compatibility for one bounded lookup. A separate shell recheck on 2026-08-28 returned:

```text
cve:        CVE-2024-3094
epss:       0.859740000
percentile: 0.997130000
date:       2026-08-27
```

The date belongs to the score observation, not the browser measurement. The human [Patch8 licence policy](../licensing/patch8.md) approves a narrow preventative-cybersecurity use: one on-demand request for the CVE detail being viewed, projecting only `cve`, `epss`, `percentile`, score `date`, and `model_version`. The UI must label EPSS as a probability rather than severity and provide the attribution required by the [FIRST EPSS data guidance](https://www.first.org/epss/data.html).

FIRST remains **machine-disabled** under policy v1. That source-wide schema cannot independently allow `browser_direct_display` while prohibiting `public_dataset_republication`, so technical success, public access, and the human-policy approval do not enable the adapter. A closed policy-v2 `use_modes` schema, mode-aware validator/caller, attribution tests, and no-persistence/no-export tests must pass first. The permitted future mode must not fetch or publish a dataset, bulk data, history, or raw responses; persist scores in browser or shared storage; or offer exports or rehosting. Until then, the first release makes no FIRST request and shows no FIRST-derived score.

## OSV

The exact unauthenticated GET returned an [OSV schema](https://ossf.github.io/osv-schema/) record with the relevant top-level structure:

```text
schema_version
id
modified
published
aliases[]
summary
details
severity[]
affected[]
references[]
database_specific
```

For `CVE-2024-3094`, the probe observed `schema_version=1.9.0`, one `affected` entry, and alias `GHSA-rxwq-x6h5-x525`. This establishes that an exact CVE GET can work from the sampled browser origin; it does not establish rights to display the aggregated record.

OSV remains **disabled** by the [F2 home-database rule](../licensing/patch8.md). OSV is an aggregator, and its software/schema licence is not a blanket data licence for every home database. The first release must make no OSV request. A future adapter may be enabled only after it derives the home database, finds an explicit allow rule for that source and field, rejects unknown lineage, and carries the required attribution. There is no fallback from an enabled source to OSV while this gate is closed.

## CISA KEV

The [canonical CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) is authoritative and unauthenticated, but its observed response omitted ACAO. A static Patch8 page therefore cannot read it directly under the browser same-origin policy. This is a transport limitation, not a rights limitation and not a reason to add a Link42 proxy.

The launch path is CISA's [official `cisagov/kev-data` repository](https://github.com/cisagov/kev-data), pinned to immutable commit:

```text
5665af188f94ef09be76e53630b5fc520777fa69
```

Exact browser URL:

```text
https://raw.githubusercontent.com/cisagov/kev-data/5665af188f94ef09be76e53630b5fc520777fa69/known_exploited_vulnerabilities.json
```

The observed object was `1,618,253` bytes and had this response shape:

```text
title
catalogVersion
dateReleased
count
vulnerabilities[]
  cveID
  vendorProject
  product
  vulnerabilityName
  dateAdded
  shortDescription
  requiredAction
  dueDate
  knownRansomwareCampaignUse
  notes
  cwes[]
```

At the pin, `catalogVersion=2026.08.27`, `dateReleased=2026-08-27T17:00:36.6632Z`, declared and actual counts were both `1,685`, and exactly one row matched `CVE-2021-44228`. The adapter may expose the allow-listed CISA catalogue fields under the recorded CC0 policy and must identify CISA KEV as the source. It must not infer complete affected-version ranges or fetch linked vendor content.

The commit SHA is part of the application release lock. A release updates it only after validating the response shape, declared/actual count, required fields, representative CVEs, exact bytes, and content checksum. On fetch, parse, or integrity failure, the client keeps the last verified cached pin or reports KEV unavailable; it never activates a partial object. The previous verified application release remains the rollback. A mutable branch, mutable raw URL, or silent fallback to the non-CORS CISA URL is prohibited.

## Runtime and failure rules

All adapters must:

1. Validate and normalize an exact `CVE-YYYY-NNNN...` identifier before constructing a request; use URL APIs rather than string or HTML interpolation.
2. Make one bounded request only to an enabled source and render upstream strings as text. Allow only `https:` reference links.
3. Record source, retrieval time, upstream publication/modification date, and immutable revision where one exists.
4. Apply timeouts, bounded retries with backoff, per-source cache isolation, and explicit unavailable/stale states. A missing source response is never evidence that a CVE is safe or absent.
5. Keep responses from different sources distinct. Do not overwrite source observations with a merged, unattributed value.
6. Store no credentials and send no Link42 user information to an upstream beyond the requested CVE identifier and ordinary browser request metadata.

CORS is an availability property, not an authorization or licence grant. If an upstream changes its CORS headers, schema, terms, or availability, Patch8 fails that source closed while preserving the other independently verified panels.

## F7/F8 remaining browser and resilience work

F5 source selection is **source-complete**. The following release-readiness work is assigned to F7/F8 and does not reopen F5:

- current Chrome, Firefox, and Safari reproduce NVD and pinned-KEV correctness from the production-equivalent static origin;
- cold, warm, private-window, offline, high-latency, low-bandwidth, and interrupted-download behavior is recorded;
- browser instrumentation captures request counts, transferred bytes, latency, cache hits, parse time, and peak memory, especially for the approximately 1.6 MB KEV object;
- NVD throttling and `403`/`429` behavior, upstream `5xx`, malformed/truncated JSON, stale cache, and rollback are exercised without producing a false “not found” result;
- KEV checksum verification and atomic cache activation are demonstrated at an immutable commit; and
- automated tests prove FIRST and OSV issue no requests while their F2 policy entries remain disabled.

The F5 decision is therefore narrow: NVD exact-CVE detail and the pinned official KEV object are selected source paths. FIRST is a technically compatible, human-policy-approved narrow display candidate that remains machine-disabled pending policy v2; OSV remains a technically compatible but disabled future candidate. F7/F8 must pass the browser gates above before launch claims are made.

## Primary references

- [NVD CVE API 2.0 documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD API terms, keys, and public-use guidance](https://nvd.nist.gov/developers/request-an-api-key)
- [FIRST EPSS API field documentation](https://api.first.org/epss/)
- [FIRST EPSS data and bulk-use guidance](https://www.first.org/epss/data.html)
- [OSV API documentation](https://google.github.io/osv.dev/api/)
- [OSV schema](https://ossf.github.io/osv-schema/)
- [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA official KEV data repository and CC0 notice](https://github.com/cisagov/kev-data)
- [CISA KEV CC0 licence](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)
- [Link42 Patch8 source and field policy](../licensing/patch8.md)
- [Machine-readable Link42 source policy](../licensing/source-policy.json)
