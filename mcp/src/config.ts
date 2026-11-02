export interface HotwashConfig {
  url: string;
  apiKey?: string;
  timeout: number;
  // Byte ceiling for one backend response body. Defaults to 5 MiB.
  maxResponseBytes?: number;
  // Operator opt-in for state-changing tools. Defaults to false (read-only).
  allowMutations?: boolean;
  // Cortex analyzer ids hotwash_run_analyzer may launch. Operator-controlled
  // (HOTWASH_MCP_ANALYZER_ALLOWLIST); never taken from tool arguments.
  analyzerAllowlist?: string[];
}

export const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

export const DEFAULT_ANALYZER_ALLOWLIST = ["CIRCLHashlookup_1_1", "MISP_2_1"] as const;
const ANALYZER_ID = /^[A-Za-z0-9_-]{1,128}$/;

// Unset or blank selects the default pair. A set value is a comma-separated
// list of exact analyzer ids. Malformed entries are dropped, and a list with no
// valid entry leaves the tool refusing every launch (fail closed).
export function parseAnalyzerAllowlist(raw: string | undefined): string[] {
  if (raw === undefined || raw.trim() === "") return [...DEFAULT_ANALYZER_ALLOWLIST];
  return [...new Set(raw.split(",").map(entry => entry.trim()).filter(entry => ANALYZER_ID.test(entry)))];
}

const TRUTHY = new Set(["1", "true", "yes", "on"]);

export function getConfig(): HotwashConfig {
  const url = (process.env.HOTWASH_URL ?? "http://localhost:8000").replace(/\/+$/, "");
  const apiKey = process.env.HOTWASH_API_KEY;
  const timeoutSeconds = parseInt(process.env.HOTWASH_TIMEOUT ?? "30", 10);
  const timeout = (Number.isFinite(timeoutSeconds) ? timeoutSeconds : 30) * 1000;
  const maxBytes = parseInt(process.env.HOTWASH_MCP_MAX_RESPONSE_BYTES ?? "", 10);
  const maxResponseBytes = Number.isFinite(maxBytes) && maxBytes > 0 ? maxBytes : DEFAULT_MAX_RESPONSE_BYTES;
  const allowMutations = TRUTHY.has((process.env.HOTWASH_MCP_ALLOW_MUTATIONS ?? "").trim().toLowerCase());
  const analyzerAllowlist = parseAnalyzerAllowlist(process.env.HOTWASH_MCP_ANALYZER_ALLOWLIST);
  return { url, apiKey, timeout, maxResponseBytes, allowMutations, analyzerAllowlist };
}
