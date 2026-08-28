const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

export type SortCol = "severity" | "cvss_score" | "epss_score" | "in_kev" | "published_at";
export type SortDir = "asc" | "desc";

export interface SortableVuln {
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  in_kev: number;
  published_at: string | null;
}

export function sortVulnerabilities<T extends SortableVuln>(items: T[], col: SortCol | null, dir: SortDir): T[] {
  if (!col) return items;

  const sorted = [...items];

  sorted.sort((a, b) => {
    let aVal: number;
    let bVal: number;

    if (col === "severity") {
      aVal = SEVERITY_ORDER[a.severity ?? ""] ?? 0;
      bVal = SEVERITY_ORDER[b.severity ?? ""] ?? 0;
    } else if (col === "cvss_score") {
      aVal = a.cvss_score ?? -Infinity;
      bVal = b.cvss_score ?? -Infinity;
    } else if (col === "epss_score") {
      aVal = a.epss_score ?? -Infinity;
      bVal = b.epss_score ?? -Infinity;
    } else if (col === "in_kev") {
      aVal = a.in_kev ? 1 : 0;
      bVal = b.in_kev ? 1 : 0;
    } else {
      aVal = a.published_at ? new Date(a.published_at).getTime() : -Infinity;
      bVal = b.published_at ? new Date(b.published_at).getTime() : -Infinity;
    }

    if (aVal === -Infinity && bVal === -Infinity) return 0;
    if (aVal === -Infinity) return 1;
    if (bVal === -Infinity) return -1;

    if (aVal < bVal) return dir === "asc" ? -1 : 1;
    if (aVal > bVal) return dir === "asc" ? 1 : -1;
    return 0;
  });

  return sorted;
}
