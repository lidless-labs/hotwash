/**
 * usePlaybooks — Hook providing access to the full playbook library
 *
 * Returns all playbooks, category filtering, and slug lookup.
 */

import { useMemo, useCallback, useEffect, useState } from 'react';
import { PlaybookLibraryItem, PlaybookCategory } from '../types';
import { allPlaybooks } from '../data';
import { listPlaybooks, getPlaybook, ApiPlaybookSummary, ApiPlaybook } from '../api/client';
import { mapApiPlaybookToLibraryItem } from '../lib/apiPlaybookMapper';

export interface UsePlaybooksResult {
  /** All playbook library items */
  playbooks: PlaybookLibraryItem[];
  /** Filter by category */
  filterByCategory: (category: PlaybookCategory) => PlaybookLibraryItem[];
  /** Get a single playbook by slug */
  getBySlug: (slug: string) => PlaybookLibraryItem | undefined;
  /** All unique categories present in the data */
  categories: PlaybookCategory[];
  /** All unique tags across all playbooks */
  allTags: string[];
}

export function usePlaybooks(): UsePlaybooksResult {
  const [playbooks, setPlaybooks] = useState<PlaybookLibraryItem[]>(allPlaybooks);

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const summaries = await listPlaybooks();
        let fullPlaybooks: (ApiPlaybook | ApiPlaybookSummary)[] = summaries;

        const needsDetails = summaries.some(
          (pb) => !pb.content_markdown || !pb.graph_json
        );

        if (needsDetails) {
          fullPlaybooks = await Promise.all(
            summaries.map(async (pb) => {
              if (pb.content_markdown && pb.graph_json) return pb;
              try {
                return await getPlaybook(pb.id);
              } catch {
                return pb;
              }
            })
          );
        }

        if (!active) return;
        setPlaybooks(fullPlaybooks.map(mapApiPlaybookToLibraryItem));
      } catch {
        if (!active) return;
        setPlaybooks(allPlaybooks);
      }
    };

    load();
    return () => {
      active = false;
    };
  }, []);

  const categories = useMemo<PlaybookCategory[]>(() => {
    const set = new Set<PlaybookCategory>();
    playbooks.forEach((p) => set.add(p.category));
    return Array.from(set);
  }, [playbooks]);

  const allTags = useMemo<string[]>(() => {
    const set = new Set<string>();
    playbooks.forEach((p) => p.tags.forEach((t) => set.add(t)));
    return Array.from(set).sort();
  }, [playbooks]);

  const filterByCategory = useCallback(
    (category: PlaybookCategory): PlaybookLibraryItem[] => {
      return playbooks.filter((p) => p.category === category);
    },
    [playbooks]
  );

  const getBySlug = useCallback(
    (slug: string): PlaybookLibraryItem | undefined => {
      return playbooks.find((p) => p.slug === slug);
    },
    [playbooks]
  );

  return { playbooks, filterByCategory, getBySlug, categories, allTags };
}
