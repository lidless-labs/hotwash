/**
 * One-shot migration of localStorage keys from the previous "playbook-forge"
 * brand to the current "hotwash" brand. Runs before React mounts so lazy
 * useState initializers see the new keys.
 */

const MIGRATIONS: ReadonlyArray<readonly [string, string]> = [
  ['variant-default-playbook-forge', 'variant-default-hotwash'],
  ['playbook-forge-tour-complete', 'hotwash-tour-complete'],
];

export function migrateLegacyStorageKeys(): void {
  try {
    for (const [oldKey, newKey] of MIGRATIONS) {
      const value = localStorage.getItem(oldKey);
      if (value !== null && localStorage.getItem(newKey) === null) {
        localStorage.setItem(newKey, value);
        localStorage.removeItem(oldKey);
      }
    }
  } catch {
    // localStorage may be unavailable (private mode, SSR); ignore
  }
}
