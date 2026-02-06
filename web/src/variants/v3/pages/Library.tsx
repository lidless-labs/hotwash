/**
 * V3 Library — Clean Card Grid with Category Tags & Search
 *
 * GitBook/Notion-inspired library view: search bar, category filter pills,
 * clean card grid showing playbook title, description, metadata, and tags.
 */

import React, { useState, useMemo } from 'react';
import { usePlaybooks } from '../../../hooks/usePlaybooks';
import { PlaybookCategory } from '../../../types';
import './Library.css';

interface LibraryProps {
  onNavigate: (path: string) => void;
}

const CATEGORY_LABELS: Record<PlaybookCategory, string> = {
  'vulnerability-remediation': 'Vulnerability Remediation',
  'incident-response': 'Incident Response',
  'threat-hunting': 'Threat Hunting',
  'compliance': 'Compliance',
  'siem-operations': 'SIEM Operations',
  'template': 'Templates',
};

const Library: React.FC<LibraryProps> = ({ onNavigate }) => {
  const { playbooks, categories } = usePlaybooks();
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState<PlaybookCategory | 'all'>('all');

  const filtered = useMemo(() => {
    let items = activeCategory === 'all'
      ? [...playbooks]
      : playbooks.filter((p) => p.category === activeCategory);

    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter(
        (p) =>
          p.metadata.title.toLowerCase().includes(q) ||
          p.description.toLowerCase().includes(q) ||
          p.tags.some((t) => t.toLowerCase().includes(q))
      );
    }

    return items;
  }, [playbooks, activeCategory, search]);

  return (
    <div className="v3-library">
      {/* Header */}
      <div className="v3-library-header">
        <h1>Library</h1>
        <p className="v3-library-subtitle">
          Browse and search your playbook knowledge base.
        </p>
      </div>

      {/* Search Bar */}
      <div className="v3-library-toolbar">
        <div className="v3-search-wrapper">
          <span className="v3-search-icon">🔍</span>
          <input
            type="text"
            className="v3-search-input"
            placeholder="Search playbooks..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <span className="v3-library-count">
          {filtered.length} of {playbooks.length}
        </span>
      </div>

      {/* Category Filter Tags */}
      <div className="v3-filter-tags">
        <button
          className={`v3-filter-tag ${activeCategory === 'all' ? 'v3-filter-tag--active' : ''}`}
          onClick={() => setActiveCategory('all')}
        >
          All
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            className={`v3-filter-tag ${activeCategory === cat ? 'v3-filter-tag--active' : ''}`}
            onClick={() => setActiveCategory(cat)}
          >
            {CATEGORY_LABELS[cat]}
          </button>
        ))}
      </div>

      {/* Card Grid */}
      {filtered.length > 0 ? (
        <div className="v3-card-grid">
          {filtered.map((pb) => (
            <div
              key={pb.slug}
              className="v3-playbook-card"
              onClick={() => onNavigate(`#/3/playbook/${pb.slug}`)}
            >
              <div className="v3-card-category">
                {CATEGORY_LABELS[pb.category]}
              </div>
              <h3 className="v3-card-title">{pb.metadata.title}</h3>
              <p className="v3-card-description">{pb.description}</p>
              <div className="v3-card-tags">
                {pb.tags.slice(0, 4).map((tag) => (
                  <span key={tag} className="v3-card-tag">{tag}</span>
                ))}
                {pb.tags.length > 4 && (
                  <span className="v3-card-tag">+{pb.tags.length - 4}</span>
                )}
              </div>
              <div className="v3-card-meta">
                <span className="v3-card-meta-item">
                  <span>📄</span> {pb.metadata.type}
                </span>
                <span className="v3-card-meta-item">
                  <span>🔧</span> {pb.metadata.tooling}
                </span>
                <span className="v3-card-meta-item">
                  {pb.graph.nodes.length} nodes
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="v3-library-empty">
          <span className="v3-library-empty-icon">📭</span>
          No playbooks match your search.
        </div>
      )}
    </div>
  );
};

export default Library;
