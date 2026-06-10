/**
 * usePlaybooks — Hook providing access to the full playbook library
 *
 * Returns all playbooks, category filtering, and slug lookup.
 */

import { useMemo, useCallback, useEffect, useState } from 'react';
import { PlaybookLibraryItem, PlaybookCategory, PlaybookMetadata, PlaybookGraph } from '../types';
import { allPlaybooks } from '../data';
import { listPlaybooks, getPlaybook, ApiPlaybookSummary, ApiPlaybook } from '../api/client';
import { parseMarkdown } from '../parsers/markdownParser';
import { parseApiDate } from '../lib/time';

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

function normalizeCategory(category?: string): PlaybookCategory {
  const value = (category || '').toLowerCase().trim();
  if (value.includes('vulnerability')) return 'vulnerability-remediation';
  if (value.includes('incident')) return 'incident-response';
  if (value.includes('threat')) return 'threat-hunting';
  if (value.includes('compliance')) return 'compliance';
  if (value.includes('siem')) return 'siem-operations';
  return 'template';
}

function formatCategoryLabel(category?: string): string {
  if (!category) return 'Playbook';
  const raw = category.replace(/_/g, '-').trim();
  const value = raw.toLowerCase();
  if (value.includes('vulnerability')) return 'Vulnerability Remediation';
  if (value.includes('incident')) return 'Incident Response';
  if (value.includes('threat')) return 'Threat Hunting';
  if (value.includes('compliance')) return 'Compliance';
  if (value.includes('siem')) return 'SIEM Operations';
  if (value.includes('template')) return 'Template';
  if (value.includes('custom')) return 'Custom';
  return raw.replace(/\\b\\w/g, (c) => c.toUpperCase());
}

function formatUpdatedDate(updatedAt?: string): string | undefined {
  if (!updatedAt) return undefined;
  const date = parseApiDate(updatedAt);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toLocaleDateString();
}

function mapApiPlaybookToLibraryItem(playbook: ApiPlaybook | ApiPlaybookSummary): PlaybookLibraryItem {
  const content = playbook.content_markdown || '';
  const parsed = content ? parseMarkdown(content) : null;
  const graph: PlaybookGraph = playbook.graph_json || parsed?.graph || { nodes: [], edges: [] };
  const parsedMeta = parsed?.metadata;

  const metadata: PlaybookMetadata = {
    title: playbook.title || parsedMeta?.title || 'Untitled Playbook',
    type: parsedMeta?.type || formatCategoryLabel(playbook.category),
    tooling: parsedMeta?.tooling || 'Hotwash',
    difficulty: parsedMeta?.difficulty,
    estimatedTime: parsedMeta?.estimatedTime,
    lastUpdated: parsedMeta?.lastUpdated || formatUpdatedDate(playbook.updated_at),
  };

  return {
    slug: playbook.id || metadata.title.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    metadata,
    category: normalizeCategory(playbook.category || parsedMeta?.type),
    markdown: content,
    graph,
    description: playbook.description || '',
    tags: playbook.tags || [],
  };
}
