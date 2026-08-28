# P2 immutable Hugging Face range proof

Status: **live-verified P2 feasibility canary**

Live evidence recorded 2026-08-28:

- immutable manifest revision `aa4e13c4564924c12a16720d8bebe57208dfccdd`;
- immutable data revision `dba086354122790626c7f2b1bf9746f407b9bac5`;
- exact-CVE DuckDB query: five Parquet payload GETs, all HTTP 206, totalling 176,465 of 3,617,105 bytes;
- complete exact/filter/detail/product/corrupt/previous-good proof: 12 Parquet payload GETs, all HTTP 206,
  totalling 287,285 bytes;
- no Parquet payload GET returned HTTP 200, and no browser token, cookie, or application backend request was sent.

This P2-only workflow publishes deterministic invented records to the existing public, ungated
[`link42-au/patch`](https://huggingface.co/datasets/link42-au/patch) dataset. It is a feasibility canary, not the P7
Patch8 vulnerability release. Generated output is ignored and must never be committed to the application repository.

## Publication boundary

All generated paths are below `synthetic/p2/`. The bundle includes an explicit
`synthetic/p2/DATASET_CARD_FRAGMENT.md` that identifies the rows as invented feasibility fixtures. Its CC0-1.0
statement applies only to those repository-authored synthetic rows. It does not blanket-relicense future NVD, CVE
Program, CISA KEV, Vulnrichment, EPSS, or other upstream-derived data. Future rows still require the source-rights
two-key gate, provenance, attribution, and source-specific licence review.

The representative current CVE shard is uncompressed, larger than 3 MB, and contains 4,096 rows in 64-row groups. It
is deliberately large enough for the browser proof to distinguish partial range reads from a whole-file download,
while the complete generated candidate remains modest. No bulk or third-party data is included.

## Prepare the data revision

From the Patch8 repository root:

```sh
pnpm hf:p2:prepare
```

This deterministically replaces only:

```text
.p2-hf-release/data-revision/
```

Publish that directory as the first Hugging Face commit. The credential remains outside this repository and is used
only by the publisher process:

```sh
hf upload link42-au/patch .p2-hf-release/data-revision . \
  --repo-type dataset --commit-message "Publish Patch8 P2 synthetic data"
```

Record the resulting lowercase 40-hex immutable data revision. Do not publish the manifest in this commit.

## Finalize and publish the manifest last

Bind the manifest to the immutable data revision:

```sh
PATCH8_HF_P2_DATA_REVISION=<40-hex-data-revision> pnpm hf:p2:finalize
```

This deterministically replaces only:

```text
.p2-hf-release/manifest-revision/
```

It contains one activation file at `synthetic/p2/manifest.json`; it does not copy the Parquet payloads. Publish it in
a second commit:

```sh
hf upload link42-au/patch .p2-hf-release/manifest-revision . \
  --repo-type dataset --commit-message "Activate Patch8 P2 synthetic manifest"
```

Record that second commit's lowercase 40-hex immutable manifest revision.

## Run the opt-in browser proof

```sh
PATCH8_HF_P2_REVISION=<40-hex-manifest-revision> pnpm test:e2e:hf
```

Without that environment variable the remote Playwright test is skipped, so ordinary local and hosted application
verification does not depend on mutable external state. With it set, real Chromium:

- loads `synthetic/p2/manifest.json` through an anonymous immutable URL;
- proves cross-origin browser access and an explicit 1,024-byte `Range` request returning HTTP 206;
- requires the representative exact-CVE DuckDB query to transfer less than the declared Parquet file size;
- checks bounded exact route selection, declared and observed byte budgets, detail/product queries, corrupt-current
  recovery, and immutable previous-good fallback;
- rejects authorization and cookie headers, application `/api/` calls, unexpected network origins, and mutable
  artifact URLs. Hugging Face's own same-host immutable resolve-cache redirect may appear in the request chain.

Before registration, the browser follows an anonymous HEAD from the validated immutable Hugging Face URL and accepts
only the resulting HTTPS `*.cdn.hf.co` URL. DuckDB-Wasm then uses fail-closed HTTP settings: full HTTP fallback is
disabled, HEAD metadata is required, and each payload response must remain a partial range. Signed CDN URLs are not
persisted or cached by the application.

Passing this canary closes only P2's live Hugging Face range/CORS feasibility item. It does not satisfy P7's official
source build, publisher credential, release readback, or production dataset acceptance gates.
