/**
 * Sanitize a link URL before it becomes an href.
 *
 * Playbook markdown is untrusted (shared/imported content) and React does NOT
 * block `javascript:` hrefs in production, so an unchecked `[x](javascript:...)`
 * link executes on click. Browsers also strip C0 control characters from URLs
 * before parsing the scheme, so control-bearing URLs must be rejected too.
 *
 * Allow only schemeless (relative/anchor) URLs and the http/https/mailto
 * schemes; collapse anything else (javascript:, vbscript:, data:, file:, ...)
 * to '#'.
 */
export function safeHref(url: string): string {
  if (/[\u0000-\u001f\u007f]/.test(url)) return '#';
  const cleaned = url.trim();
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(cleaned);
  if (!scheme) return cleaned || '#';
  const name = scheme[1].toLowerCase();
  return name === 'http' || name === 'https' || name === 'mailto' ? cleaned : '#';
}
