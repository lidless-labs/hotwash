/**
 * usePlaybook — Hook for loading a single playbook by slug
 *
 * Returns the PlaybookLibraryItem or undefined if not found.
 */

import { useEffect, useMemo, useState } from 'react';
import { PlaybookLibraryItem, PlaybookMetadata, PlaybookGraph, PlaybookCategory } from '../types';
import { allPlaybooks } from '../data';
import { getPlaybook, ApiPlaybook } from '../api/client';
import { parseMarkdown } from '../parsers/markdownParser';
import { parseApiDate } from '../lib/time';

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

function mapApiPlaybookToLibraryItem(playbook: ApiPlaybook): PlaybookLibraryItem {
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
