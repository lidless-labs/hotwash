/**
 * Time formatting helpers shared across pages.
 */

/**
 * Parse an API timestamp. The backend emits naive ISO strings that are
 * UTC; `new Date()` would read them as local time (showing negative
 * elapsed timers and wrong "ago" labels), so append Z when no timezone
 * marker is present.
 */
export function parseApiDate(iso: string): Date {
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(iso);
  return new Date(hasZone ? iso : `${iso}Z`);
}

/**
 * Render an ISO timestamp as a short relative label (e.g. "5m ago").
 * Returns "just now" for anything younger than a minute.
 */
export function relativeTime(iso: string): string {
  const now = Date.now();
  const then = parseApiDate(iso).getTime();
  const diff = now - then;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}
