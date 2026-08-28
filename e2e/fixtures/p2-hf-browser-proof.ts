import { BrowserDuckDbRuntime } from "../../apps/web/src/lib/dataset/browser";
import { P2DatasetClient } from "../../apps/web/src/lib/dataset/client";
import { artifactsForCve, validateManifest } from "../../apps/web/src/lib/dataset/routing";
import type { P2Manifest, QueryResult, P2Vulnerability } from "../../apps/web/src/lib/dataset/types";

interface P2HfPublicationManifest {
  publication_manifest_version: 1;
  fixture_only: true;
  dataset_repository: "link42-au/patch";
  manifest_path: "synthetic/p2/manifest.json";
  data_revision: string;
  rights_policy_version: "p2-synthetic-1";
  range_proof: {
    artifact_path: string;
    row_count: number;
    row_group_size: number;
    row_groups: number;
    minimum_bytes: number;
  };
  current: P2Manifest;
  previous: P2Manifest;
  corrupt_artifact: { path: string; bytes: number; sha256: string };
}

interface LoadedProof {
  manifest: P2HfPublicationManifest;
  artifactUrls: Record<string, string>;
}

const IMMUTABLE_MANIFEST =
  /^https:\/\/huggingface\.co\/datasets\/link42-au\/patch\/resolve\/[0-9a-f]{40}\/synthetic\/p2\/manifest\.json$/;
const REVISION = /^[0-9a-f]{40}$/;
const SAFE_SYNTHETIC_PATH = /^synthetic\/p2\/[A-Za-z0-9._/-]+$/;
let loaded: LoadedProof | null = null;

const validatePublicationManifest = (value: P2HfPublicationManifest): void => {
  if (value.publication_manifest_version !== 1 || value.fixture_only !== true) {
    throw new Error("Unsupported P2 HF publication manifest");
  }
  if (value.dataset_repository !== "link42-au/patch" || value.manifest_path !== "synthetic/p2/manifest.json") {
    throw new Error("Unexpected P2 HF dataset identity");
  }
  if (!REVISION.test(value.data_revision)) throw new Error("P2 HF data revision is not immutable");
  if (value.rights_policy_version !== "p2-synthetic-1") throw new Error("Unexpected P2 HF rights policy");
  if (
    value.range_proof.artifact_path !== "synthetic/p2/current/vulnerabilities-2026-10.parquet" ||
    value.range_proof.row_count !== 4_096 ||
    value.range_proof.row_group_size !== 64 ||
    value.range_proof.row_groups !== 64 ||
    value.range_proof.minimum_bytes !== 3_000_000
  ) {
    throw new Error("Unexpected P2 HF range-proof shape");
  }
  validateManifest(value.current);
  validateManifest(value.previous);
  if (value.current.previous_release !== value.previous.release_id) {
    throw new Error("P2 HF previous-good release mismatch");
  }
  const paths = [
    ...value.current.artifacts.map(({ path }) => path),
    ...value.previous.artifacts.map(({ path }) => path),
    value.corrupt_artifact.path,
  ];
  if (paths.some((path) => !SAFE_SYNTHETIC_PATH.test(path) || path.includes(".."))) {
    throw new Error("Unsafe P2 HF artifact path");
  }
};

const artifactUrl = (revision: string, path: string): string =>
  `https://huggingface.co/datasets/link42-au/patch/resolve/${revision}/${path}`;

const createClient = (proof: LoadedProof, corruptCurrent = false): P2DatasetClient => {
  const urls = { ...proof.artifactUrls };
  if (corruptCurrent) {
    const current = artifactsForCve(proof.manifest.current, "vulnerabilities", "CVE-2026-102112")[0];
    if (!current) throw new Error("P2 HF current target route is absent");
    urls[current.path] = artifactUrl(proof.manifest.data_revision, proof.manifest.corrupt_artifact.path);
  }
  return new P2DatasetClient({
    current: proof.manifest.current,
    previous: proof.manifest.previous,
    artifactUrls: urls,
    runtimeFactory: () => new BrowserDuckDbRuntime(),
  });
};

declare global {
  interface Window {
    loadPatch8P2HfProof: (manifestUrl: string) => Promise<unknown>;
    runPatch8P2HfRangeQuery: () => Promise<QueryResult<P2Vulnerability | null>>;
    runPatch8P2HfQueryProof: () => Promise<unknown>;
  }
}

window.loadPatch8P2HfProof = async (manifestUrl) => {
  if (!IMMUTABLE_MANIFEST.test(manifestUrl)) throw new Error("P2 HF manifest URL must pin a 40-hex revision");
  const response = await fetch(manifestUrl, { cache: "no-store", credentials: "omit" });
  if (!response.ok) throw new Error(`P2 HF manifest request failed: ${response.status}`);
  const manifest = (await response.json()) as P2HfPublicationManifest;
  validatePublicationManifest(manifest);
  const artifactUrls = Object.fromEntries(
    [...manifest.current.artifacts, ...manifest.previous.artifacts].map(({ path }) => [
      path,
      artifactUrl(manifest.data_revision, path),
    ]),
  );
  loaded = { manifest, artifactUrls };

  const exactArtifact = artifactsForCve(manifest.current, "vulnerabilities", "CVE-2026-102112")[0];
  if (!exactArtifact || exactArtifact.bytes < 3_000_000) throw new Error("P2 HF range shard is not representative");
  const rangeResponse = await fetch(artifactUrls[exactArtifact.path], {
    cache: "no-store",
    credentials: "omit",
    headers: { Range: "bytes=0-1023" },
  });
  const rangeBytes = (await rangeResponse.arrayBuffer()).byteLength;
  return {
    dataRevision: manifest.data_revision,
    exactArtifact,
    range: {
      status: rangeResponse.status,
      bytes: rangeBytes,
      contentRange: rangeResponse.headers.get("content-range"),
      acceptRanges: rangeResponse.headers.get("accept-ranges"),
      responseType: rangeResponse.type,
    },
  };
};

window.runPatch8P2HfRangeQuery = async () => {
  if (!loaded) throw new Error("P2 HF proof is not loaded");
  const client = createClient(loaded);
  try {
    return await client.exact("CVE-2026-102112");
  } finally {
    await client.close();
  }
};

window.runPatch8P2HfQueryProof = async () => {
  if (!loaded) throw new Error("P2 HF proof is not loaded");
  const client = createClient(loaded);
  try {
    const exact = await client.exact("CVE-2026-102112");
    const filtered = await client.search({
      q: "CVE-2026-102112",
      severity: "CRITICAL",
      inKev: true,
      limit: 1,
    });
    const detail = await client.detail("CVE-2026-102112");
    const products = await client.products("Acme", 10, 0);
    const fallbackClient = createClient(loaded, true);
    try {
      const fallback = await fallbackClient.exact("CVE-2026-102112");
      return { exact, filtered, detail, products, fallback };
    } finally {
      await fallbackClient.close();
    }
  } finally {
    await client.close();
  }
};
