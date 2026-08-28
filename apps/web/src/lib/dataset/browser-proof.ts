import { createP2BrowserClient } from "./browser";

declare global {
  interface Window {
    runPatch8P2Proof: () => Promise<unknown>;
  }
}

window.runPatch8P2Proof = async () => {
  const client = createP2BrowserClient();
  try {
    const exact = await client.exact("cve-2026-1001");
    const filtered = await client.search({ severity: "CRITICAL", inKev: true, limit: 1, offset: 0 });
    const secondPage = await client.search({ vendor: "Acme", product: "Widget", limit: 1, offset: 1 });
    const detail = await client.detail("CVE-2026-1001");
    const products = await client.products("Acme", 10, 0);
    const empty = await client.exact("CVE-2026-9999");

    const fallbackClient = createP2BrowserClient({ corruptCurrent: true });
    try {
      const fallback = await fallbackClient.exact("CVE-2026-1001");
      return { exact, filtered, secondPage, detail, products, empty, fallback };
    } finally {
      await fallbackClient.close();
    }
  } finally {
    await client.close();
  }
};
