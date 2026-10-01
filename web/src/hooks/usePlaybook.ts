/**
 * usePlaybook — Hook for loading a single playbook by slug
 *
 * Returns the PlaybookLibraryItem or undefined if not found.
 */

import { useEffect, useMemo, useState } from 'react';
import { PlaybookLibraryItem } from '../types';
import { allPlaybooks } from '../data';
import { getPlaybook } from '../api/client';
import { mapApiPlaybookToLibraryItem } from '../lib/apiPlaybookMapper';

export interface UsePlaybookResult {
  /** The playbook data, or undefined if slug doesn't match */
  playbook: PlaybookLibraryItem | undefined;
  /** Whether the slug was found */
  found: boolean;
}

export function usePlaybook(slug: string | undefined): UsePlaybookResult {
  const [playbook, setPlaybook] = useState<PlaybookLibraryItem | undefined>(undefined);
  const [found, setFound] = useState(false);

  const localMatch = useMemo(() => {
    if (!slug) return undefined;
    return allPlaybooks.find((p) => p.slug === slug);
  }, [slug]);

  useEffect(() => {
    let active = true;

    const load = async () => {
      if (!slug) {
        if (!active) return;
        setPlaybook(undefined);
        setFound(false);
        return;
      }

      if (localMatch) {
        if (!active) return;
        setPlaybook(localMatch);
        setFound(true);
        return;
      }

      try {
        const apiPlaybook = await getPlaybook(slug);
        if (!active) return;
        setPlaybook(mapApiPlaybookToLibraryItem(apiPlaybook));
        setFound(true);
      } catch {
        if (!active) return;
        setPlaybook(undefined);
        setFound(false);
      }
    };

    load();
    return () => {
      active = false;
    };
  }, [slug, localMatch]);

  return { playbook, found };
}
