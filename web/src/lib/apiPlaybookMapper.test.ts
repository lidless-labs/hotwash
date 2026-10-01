import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { ApiPlaybook, ApiPlaybookSummary } from '../api/client';
import { mapApiPlaybookToLibraryItem } from './apiPlaybookMapper';

const apiPlaybook: ApiPlaybook = {
  id: 42,
  title: 'API response playbook',
  description: 'Contain a suspicious endpoint',
  category: 'incident-response',
  tags: [{ id: 1, name: 'wazuh' }, { id: 2, name: 'containment' }],
  content_markdown: '# Response\n1. Investigate\n',
  graph_json: {
    nodes: [{ id: 'triage', label: 'Triage', type: 'step', metadata: { owner: 'SOC' } }],
    edges: [],
  },
  updated_at: '2026-10-01T12:00:00',
};

describe('mapApiPlaybookToLibraryItem', () => {
  it('maps real API tag objects to strings that React can render', () => {
    const item = mapApiPlaybookToLibraryItem(apiPlaybook);
    expect(item.tags).toEqual(['wazuh', 'containment']);
    expect(renderToStaticMarkup(createElement('span', null, ...item.tags)))
      .toBe('<span>wazuhcontainment</span>');
  });

  it('normalizes numeric IDs for string slug lookup and routes', () => {
    expect(mapApiPlaybookToLibraryItem(apiPlaybook).slug).toBe('42');
    expect(mapApiPlaybookToLibraryItem({ ...apiPlaybook, id: 0 }).slug).toBe('0');
  });

  it('preserves API graph, markdown, description, and parsed metadata', () => {
    const content = [
      '# Response',
      '**Type:** Threat Hunting',
      '**Tooling:** Wazuh',
      '**Difficulty:** Intermediate',
      '**Estimated Time:** 45 minutes',
      '**Last Updated:** September 30, 2026',
      '1. Investigate',
    ].join('\n');
    const item = mapApiPlaybookToLibraryItem({ ...apiPlaybook, content_markdown: content });
    expect(item.graph).toBe(apiPlaybook.graph_json);
    expect(item.graph.nodes[0].metadata).toEqual({ owner: 'SOC' });
    expect(item.markdown).toBe(content);
    expect(item.description).toBe(apiPlaybook.description);
    expect(item.category).toBe('incident-response');
    expect(item.metadata).toEqual({
      title: 'API response playbook',
      type: 'Threat Hunting',
      tooling: 'Wazuh',
      difficulty: 'Intermediate',
      estimatedTime: '45 minutes',
      lastUpdated: 'September 30, 2026',
    });
    expect(apiPlaybook.tags).toEqual([{ id: 1, name: 'wazuh' }, { id: 2, name: 'containment' }]);
  });

  it('parses markdown into a graph when the API has no graph', () => {
    const item = mapApiPlaybookToLibraryItem({ ...apiPlaybook, graph_json: undefined });
    expect(item.graph.nodes.map((node) => node.label)).toEqual(['Response', 'Investigate']);
    expect(item.graph.edges).toHaveLength(1);
    expect(item.metadata.lastUpdated).toBe(new Date('2026-10-01T12:00:00Z').toLocaleDateString());
  });

  it('maps a summary without optional fields to the existing defaults', () => {
    const summary: ApiPlaybookSummary = { id: 7, title: 'Summary' };
    expect(mapApiPlaybookToLibraryItem(summary)).toEqual({
      slug: '7',
      metadata: {
        title: 'Summary', type: 'Playbook', tooling: 'Hotwash',
        difficulty: undefined, estimatedTime: undefined, lastUpdated: undefined,
      },
      category: 'template', markdown: '', graph: { nodes: [], edges: [] },
      description: '', tags: [],
    });
  });
});
