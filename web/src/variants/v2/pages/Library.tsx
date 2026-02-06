/**
 * V2 Library — Dense Sortable Table with Status Dots & Category Filters
 *
 * SOC operator style: compact rows, status indicators, filter chips,
 * sortable columns, data-dense presentation.
 */

import React, { useState, useMemo } from 'react';
import { usePlaybooks } from '../../../hooks/usePlaybooks';
import { PlaybookCategory } from '../../../types';
import './Library.css';

interface LibraryProps {
  onNavigate: (path: string) => void;
}

const CATEGORY_LABELS: Record<PlaybookCategory, string> = {
  'vulnerability-remediation': 'Vuln Remediation',
  'incident-response': 'Incident Response',
  'threat-hunting': 'Threat Hunting',
  'compliance': 'Compliance',
  'siem-operations': 'SIEM Ops',
  'template': 'Templates',
};

const CATEGORY_COLORS: Record<PlaybookCategory, string> = {
  'vulnerability-remediation': '#EF4444',
  'incident-response': '#F59E0B',
  'threat-hunting': '#06B6D4',
  'compliance': '#22C55E',
  'siem-operations': '#8B5CF6',
  'template': '#64748B',
};

type SortKey = 'title' | 'category' | 'type' | 'nodes' | 'edges';
type SortDir = 'asc' | 'desc';

const Library: React.FC<LibraryProps> = ({ onNavigate }) => {
  const { playbooks, categories } = usePlaybooks();
  const [activeCategory, setActiveCategory] = useState<PlaybookCategory | 'all'>('all');
  const [sortKey, setSortKey] = useState<SortKey>('title');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const sortIcon = (key: SortKey) => {
    if (sortKey !== key) return ' ⇅';
    return sortDir === 'asc' ? ' ↑' : ' ↓';
  };

  const filtered = useMemo(() => {
    let items = activeCategory === 'all' ? [...playbooks] : playbooks.filter((p) => p.category === activeCategory);

    items.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'title': cmp = a.metadata.title.localeCompare(b.metadata.title); break;
        case 'category': cmp = a.category.localeCompare(b.category); break;
        case 'type': cmp = a.metadata.type.localeCompare(b.metadata.type); break;
        case 'nodes': cmp = a.graph.nodes.length - b.graph.nodes.length; break;
        case 'edges': cmp = a.graph.edges.length - b.graph.edges.length; break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return items;
  }, [playbooks, activeCategory, sortKey, sortDir]);

  return (
    <div className="v2-library">
      {/* Page Header */}
      <div className="v2-page-header">
        <h1>Playbook Library</h1>
        <span className="v2-page-subtitle">
          {filtered.length} of {playbooks.length} playbooks
        </span>
      </div>

      {/* Category Filter Chips */}
      <div className="v2-filter-row">
        <button
          className={`v2-filter-chip ${activeCategory === 'all' ? 'v2-filter-chip--active' : ''}`}
          onClick={() => setActiveCategory('all')}
        >
          <span className="v2-filter-chip-dot" style={{ background: '#E2E8F0' }} />
          All ({playbooks.length})
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            className={`v2-filter-chip ${activeCategory === cat ? 'v2-filter-chip--active' : ''}`}
            onClick={() => setActiveCategory(cat)}
          >
            <span className="v2-filter-chip-dot" style={{ background: CATEGORY_COLORS[cat] }} />
            {CATEGORY_LABELS[cat]} ({playbooks.filter((p) => p.category === cat).length})
          </button>
        ))}
      </div>

      {/* Data Table */}
      <div className="v2-table-wrapper">
        <table className="v2-library-table">
          <thead>
            <tr>
              <th className="v2-th-status">⬤</th>
              <th className="v2-th-sortable" onClick={() => handleSort('title')}>
                Playbook{sortIcon('title')}
              </th>
              <th className="v2-th-sortable" onClick={() => handleSort('category')}>
                Category{sortIcon('category')}
              </th>
              <th className="v2-th-sortable" onClick={() => handleSort('type')}>
                Type{sortIcon('type')}
              </th>
              <th className="v2-th-sortable v2-th-num" onClick={() => handleSort('nodes')}>
                Nodes{sortIcon('nodes')}
              </th>
              <th className="v2-th-sortable v2-th-num" onClick={() => handleSort('edges')}>
                Edges{sortIcon('edges')}
              </th>
              <th className="v2-th-tags">Tags</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((pb) => (
              <tr
                key={pb.slug}
                className="v2-lib-row"
                onClick={() => onNavigate(`#/2/playbook/${pb.slug}`)}
              >
                <td className="v2-td-status">
                  <span
                    className="v2-status-dot v2-status-dot--green"
                    style={{ width: 6, height: 6 }}
                  />
                </td>
                <td className="v2-td-title">
                  <div className="v2-td-title-text">{pb.metadata.title}</div>
                  <div className="v2-td-title-desc">{pb.description}</div>
                </td>
                <td>
                  <span
                    className="v2-category-badge"
                    style={{ borderColor: CATEGORY_COLORS[pb.category], color: CATEGORY_COLORS[pb.category] }}
                  >
                    {CATEGORY_LABELS[pb.category]}
                  </span>
                </td>
                <td className="v2-td-type">{pb.metadata.type}</td>
                <td className="v2-td-num">{pb.graph.nodes.length}</td>
                <td className="v2-td-num">{pb.graph.edges.length}</td>
                <td className="v2-td-tags">
                  {pb.tags.slice(0, 3).map((tag) => (
                    <span key={tag} className="v2-tag">{tag}</span>
                  ))}
                  {pb.tags.length > 3 && (
                    <span className="v2-tag v2-tag--more">+{pb.tags.length - 3}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filtered.length === 0 && (
        <div className="v2-library-empty">
          <span className="v2-status-dot v2-status-dot--amber" />
          No playbooks match the selected filter.
        </div>
      )}
    </div>
  );
};

export default Library;
