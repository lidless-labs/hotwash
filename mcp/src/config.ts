export interface HotwashConfig {
  url: string;
  apiKey?: string;
  timeout: number;
  // Byte ceiling for one backend response body. Defaults to 5 MiB.
  maxResponseBytes?: number;
  // Operator opt-in for state-changing tools. Defaults to false (read-only).
  allowMutations?: boolean;
}

export const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

const TRUTHY = new Set(["1", "true", "yes", "on"]);

export function getConfig(): HotwashConfig {
  const url = (process.env.HOTWASH_URL ?? "http://localhost:8000").replace(/\/+$/, "");
  const apiKey = process.env.HOTWASH_API_KEY;
  const timeoutSeconds = parseInt(process.env.HOTWASH_TIMEOUT ?? "30", 10);
  const timeout = (Number.isFinite(timeoutSeconds) ? timeoutSeconds : 30) * 1000;
  const maxBytes = parseInt(process.env.HOTWASH_MCP_MAX_RESPONSE_BYTES ?? "", 10);
  const maxResponseBytes = Number.isFinite(maxBytes) && maxBytes > 0 ? maxBytes : DEFAULT_MAX_RESPONSE_BYTES;
  const allowMutations = TRUTHY.has((process.env.HOTWASH_MCP_ALLOW_MUTATIONS ?? "").trim().toLowerCase());
  return { url, apiKey, timeout, maxResponseBytes, allowMutations };
}
