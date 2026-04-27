export interface HotwashConfig {
  url: string;
  apiKey?: string;
  timeout: number;
}

export function getConfig(): HotwashConfig {
  const url = (process.env.HOTWASH_URL ?? "http://localhost:8000").replace(/\/+$/, "");
  const apiKey = process.env.HOTWASH_API_KEY;
  const timeoutSeconds = parseInt(process.env.HOTWASH_TIMEOUT ?? "30", 10);
  const timeout = (Number.isFinite(timeoutSeconds) ? timeoutSeconds : 30) * 1000;
  return { url, apiKey, timeout };
}
