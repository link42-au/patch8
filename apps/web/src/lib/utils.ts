/** Escape HTML entities in a string. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/** Highlight substring matches in text, returning safe HTML. */
export function highlightMatch(text: string, query: string): string {
  if (!query) return esc(text);

  const regex = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
  let result = "";
  let lastIndex = 0;
  let match: RegExpExecArray | null = regex.exec(text);

  while (match) {
    result += esc(text.slice(lastIndex, match.index));
    result += `<span class="match">${esc(match[0])}</span>`;
    lastIndex = match.index + match[0].length;
    match = regex.exec(text);
  }

  result += esc(text.slice(lastIndex));
  return result;
}

/** Convert a CPE slug (e.g. "windows_10") to a human-readable name ("Windows 10"). */
export function prettyName(slug: string): string {
  const ACRONYMS: Record<string, string> = {
    os: "OS",
    ios: "iOS",
    macos: "macOS",
    api: "API",
    sdk: "SDK",
    ssl: "SSL",
    tls: "TLS",
    ssh: "SSH",
    url: "URL",
    sql: "SQL",
    http: "HTTP",
    https: "HTTPS",
    ip: "IP",
    dns: "DNS",
    vpn: "VPN",
    usb: "USB",
    cpu: "CPU",
    gpu: "GPU",
    ram: "RAM",
    xml: "XML",
    json: "JSON",
    csv: "CSV",
    pdf: "PDF",
    iot: "IoT",
    ui: "UI",
    ide: "IDE",
    tcp: "TCP",
    udp: "UDP",
    ftp: "FTP",
    php: "PHP",
  };
  const fmt = (w: string): string => {
    const lc = w.toLowerCase();
    if (ACRONYMS[lc]) return ACRONYMS[lc];
    if (/\d/.test(w) && w.replace(/\d/g, "").length <= 3) return w.toUpperCase();
    return w.charAt(0).toUpperCase() + w.slice(1);
  };
  return slug
    .replace(/_/g, " ")
    .split(" ")
    .map((w) => (w.includes("-") ? w.split("-").map(fmt).join("-") : fmt(w)))
    .join(" ");
}
