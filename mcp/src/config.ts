export interface HotwashConfig {
  url: string;
  apiKey?: string;
  timeout: number;
  // Byte ceiling for one backend response body. Defaults to 5 MiB.
  maxResponseBytes?: number;
  // Operator opt-in for state-changing tools. Defaults to false (read-only).
  allowMutations?: boolean;
  // Analyzer name -> Cortex worker id that hotwash_run_analyzer may launch.
  // Operator-controlled (HOTWASH_MCP_ANALYZER_ALLOWLIST); never taken from
  // tool arguments. Cortex launches by worker id, a per-deployment hash.
  analyzerAllowlist?: Readonly<Record<string, string>>;
}

export const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

// Recommended entries for the SOC triage scope. Worker ids differ per Cortex
// deployment, so there is no default mapping: an unset allowlist launches nothing.
export const RECOMMENDED_ANALYZER_NAMES = ["CIRCLHashlookup_1_1", "MISP_2_1"] as const;
const ANALYZER_TOKEN = /^[A-Za-z0-9_-]{1,128}$/;

// A comma-separated list of exact `Name=WorkerId` pairs. Unset, blank, a bare
// name, or a malformed pair is dropped. A name listed with two different worker
// ids is dropped entirely. The result can be empty, which refuses every launch.
export function parseAnalyzerAllowlist(raw: string | undefined): Record<string, string> {
  const result = new Map<string, string>();
  const conflicted = new Set<string>();
  for (const entry of (raw ?? "").split(",")) {
    const parts = entry.trim().split("=");
    if (parts.length !== 2) continue;
    const [name, worker] = parts.map(part => part.trim());
    if (!ANALYZER_TOKEN.test(name) || !ANALYZER_TOKEN.test(worker)) continue;
    const existing = result.get(name);
    if (existing !== undefined && existing !== worker) conflicted.add(name);
    else result.set(name, worker);
  }
  for (const name of conflicted) result.delete(name);
  // fromEntries defines own data properties, so names such as __proto__ stay data.
  return Object.fromEntries(result);
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
