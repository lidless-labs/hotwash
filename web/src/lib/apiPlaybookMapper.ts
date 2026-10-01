import type { ApiPlaybook, ApiPlaybookSummary } from '../api/client';
import type { PlaybookCategory, PlaybookGraph, PlaybookLibraryItem, PlaybookMetadata } from '../types';
import { parseMarkdown } from '../parsers/markdownParser';
import { parseApiDate } from './time';

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

export function mapApiPlaybookToLibraryItem(playbook: ApiPlaybook | ApiPlaybookSummary): PlaybookLibraryItem {
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
    slug: playbook.id != null
      ? String(playbook.id)
      : metadata.title.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    metadata,
    category: normalizeCategory(playbook.category || parsedMeta?.type),
    markdown: content,
    graph,
    description: playbook.description || '',
    tags: (playbook.tags || []).map((tag) => typeof tag === 'string' ? tag : tag.name),
  };
}
