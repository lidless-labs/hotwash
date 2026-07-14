/**
 * Sanitize a link URL before it becomes an href.
 *
 * Playbook markdown is untrusted (shared/imported content) and React does NOT
 * block `javascript:` hrefs in production, so an unchecked `[x](javascript:...)`
 * link executes on click. Browsers also strip tab/newline/CR from a URL before
 * parsing the scheme, so `java\tscript:` must be neutralized too.
 *
 * Allow only schemeless (relative/anchor) URLs and the http/https/mailto
 * schemes; collapse anything else (javascript:, vbscript:, data:, file:, ...)
 * to '#'.
 */
export function safeHref(url: string): string {
  const cleaned = url.replace(/[\t\n\r]/g, '').trim();
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(cleaned);
  if (!scheme) return cleaned || '#';
  const name = scheme[1].toLowerCase();
  return name === 'http' || name === 'https' || name === 'mailto' ? cleaned : '#';
}
