/**
 * Route definitions for Playbook Forge
 *
 * Hash-based routing (no react-router-dom dependency).
 * Routes:
 *   /              → Variant picker (landing page)
 *   /library       → Global playbook library
 *   /editor        → Create new playbook
 *   /editor/:id    → Edit existing playbook
 *   /import        → Import playbooks (JSON/Markdown)
 *   /shared/:token → Read-only shared playbook view
 *   /1 .. /5       → Variant app root
 *   /N/library     → Playbook library for variant N
 *   /N/playbook/:slug → View specific playbook
 *   /N/import      → Import/paste markdown
 *   /N/dashboard   → Statistics dashboard
 *   /N/docs        → In-app documentation
 */

export interface RouteMatch {
  /** Raw path from hash (e.g., '/2/library') */
  path: string;
  /** Variant number 1-5 or null for root */
  variant: number | null;
  /** Page identifier: 'picker' | 'home' | 'library' | 'playbook' | 'import' | 'editor' | 'shared' | 'dashboard' | 'docs' */
  page: string;
  /** Dynamic parameters (e.g., { slug: 'vulnerability-remediation-python' }) */
  params: Record<string, string>;
}

/**
 * Parse a hash path into a RouteMatch.
 */
export function matchRoute(hash: string): RouteMatch {
  // Normalize: strip leading '#' and trailing '/'
  const path = (hash.replace(/^#/, '') || '/').replace(/\/+$/, '') || '/';

  // Root: variant picker
  if (path === '/') {
    return { path, variant: null, page: 'picker', params: {} };
  }

  // Global library
  if (path === '/library') {
    return { path, variant: null, page: 'library', params: {} };
  }

  // Global editor
  const editorMatch = path.match(/^\/editor(?:\/(.+))?$/);
  if (editorMatch) {
    return {
      path,
      variant: null,
      page: 'editor',
      params: editorMatch[1] ? { id: editorMatch[1] } : {},
    };
  }

  // Global import
  if (path === '/import') {
    return { path, variant: null, page: 'import', params: {} };
  }

  // Shared playbook view
  const sharedMatch = path.match(/^\/shared\/(.+)$/);
  if (sharedMatch) {
    return {
      path,
      variant: null,
      page: 'shared',
      params: { token: sharedMatch[1] },
    };
  }

  // Match variant prefix: /1 .. /5
  const variantMatch = path.match(/^\/([1-5])(?:\/(.*))?$/);
  if (!variantMatch) {
    // Unknown route → fall back to picker
    return { path, variant: null, page: 'picker', params: {} };
  }

  const variant = parseInt(variantMatch[1], 10);
  const rest = variantMatch[2] || '';

  // Variant root
  if (!rest) {
    return { path, variant, page: 'home', params: {} };
  }

  // /N/library
  if (rest === 'library') {
    return { path, variant, page: 'library', params: {} };
  }

  // /N/import
  if (rest === 'import') {
    return { path, variant, page: 'import', params: {} };
  }

  // /N/dashboard
  if (rest === 'dashboard') {
    return { path, variant, page: 'dashboard', params: {} };
  }

  // /N/docs
  if (rest === 'docs') {
    return { path, variant, page: 'docs', params: {} };
  }

  // /N/playbook/:slug
  const playbookMatch = rest.match(/^playbook\/(.+)$/);
  if (playbookMatch) {
    return {
      path,
      variant,
      page: 'playbook',
      params: { slug: playbookMatch[1] },
    };
  }

  // Fallback: treat as variant home
  return { path, variant, page: 'home', params: {} };
}

/**
 * Build a hash path string.
 */
export function buildPath(variant?: number, page?: string, params?: Record<string, string>): string {
  if (!variant) return '#/';
  let p = `#/${variant}`;
  if (page && page !== 'home') {
    if (page === 'playbook' && params?.slug) {
      p += `/playbook/${params.slug}`;
    } else {
      p += `/${page}`;
    }
  }
  return p;
}
