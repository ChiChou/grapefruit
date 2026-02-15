export interface RequestInfo {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export const formats = [
  { id: "curl", label: "cURL" },
  { id: "fetch-browser", label: "fetch (Browser)" },
  { id: "fetch-node", label: "fetch (Node.js)" },
  { id: "powershell", label: "PowerShell" },
  { id: "url", label: "URL" },
] as const;

export type FormatId = (typeof formats)[number]["id"];

function escapeShell(s: string): string {
  return s.replace(/'/g, "'\\''");
}

function curl(req: RequestInfo): string {
  let cmd = `curl '${escapeShell(req.url)}'`;
  if (req.method !== "GET") cmd += ` -X ${req.method}`;
  for (const [k, v] of Object.entries(req.headers)) {
    cmd += ` \\\n  -H '${escapeShell(k)}: ${escapeShell(v)}'`;
  }
  if (req.body) cmd += ` \\\n  --data-raw '${escapeShell(req.body)}'`;
  return cmd;
}

function fetchBrowser(req: RequestInfo): string {
  const hasHeaders = Object.keys(req.headers).length > 0;
  const hasBody = !!req.body;
  const isSimple = req.method === "GET" && !hasHeaders && !hasBody;

  if (isSimple) return `fetch("${req.url}");`;

  const opts: string[] = [];
  if (req.method !== "GET") opts.push(`  method: "${req.method}",`);
  if (hasHeaders) {
    opts.push("  headers: {");
    for (const [k, v] of Object.entries(req.headers)) {
      opts.push(`    "${k}": "${v}",`);
    }
    opts.push("  },");
  }
  if (hasBody) {
    opts.push(`  body: ${JSON.stringify(req.body)},`);
  }

  return `fetch("${req.url}", {\n${opts.join("\n")}\n});`;
}

function fetchNode(req: RequestInfo): string {
  const browser = fetchBrowser(req);
  return `const response = await ${browser}\nconst data = await response.json();`;
}

function powershell(req: RequestInfo): string {
  const lines: string[] = [];
  const hasHeaders = Object.keys(req.headers).length > 0;

  if (hasHeaders) {
    lines.push("$headers = @{");
    for (const [k, v] of Object.entries(req.headers)) {
      lines.push(`    "${k}" = "${v}"`);
    }
    lines.push("}");
    lines.push("");
  }

  if (req.body) {
    lines.push(`$body = '${req.body.replace(/'/g, "''")}'`);
    lines.push("");
  }

  let cmd = "Invoke-RestMethod";
  cmd += ` -Uri "${req.url}"`;
  cmd += ` -Method ${req.method}`;
  if (hasHeaders) cmd += " -Headers $headers";
  if (req.body) cmd += " -Body $body";

  lines.push(cmd);
  return lines.join("\n");
}

export function generate(format: FormatId, req: RequestInfo): string {
  switch (format) {
    case "curl":
      return curl(req);
    case "fetch-browser":
      return fetchBrowser(req);
    case "fetch-node":
      return fetchNode(req);
    case "powershell":
      return powershell(req);
    case "url":
      return req.url;
  }
}
