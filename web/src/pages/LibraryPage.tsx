/**
 * LibraryPage — Playbook catalog backed by the API (with demo fallback).
 */

import React, { useEffect, useMemo, useState } from 'react';
import { useHashRouter } from '../router';
import { listPlaybooks, deletePlaybook, listSuggestions, ApiPlaybookSummary } from '../api/client';
import { allPlaybooks } from '../data';
import { PlaybookLibraryItem } from '../types';
import AIImprovePanel from '../components/AIImprovePanel';
import { parseApiDate } from '../lib/time';

interface LibraryPlaybook {
  id: string;
  title: string;
  description: string;
  categoryLabel: string;
  categoryKey: string;
  tags: string[];
  updatedAt?: string;
  nodeCount?: number;
  content?: string;
}

const CATEGORY_FILTERS = [
  { key: 'vulnerability-remediation', label: 'Vulnerability Remediation' },
  { key: 'incident-response', label: 'Incident Response' },
  { key: 'threat-hunting', label: 'Threat Hunting' },
  { key: 'custom', label: 'Custom' },
];

const LibraryPage: React.FC = () => {
  const { navigate } = useHashRouter();
  const [items, setItems] = useState<LibraryPlaybook[]>([]);
  const [loading, setLoading] = useState(true);
  const [usingFallback, setUsingFallback] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [activeTag, setActiveTag] = useState<string>('all');
  const [deleteTarget, setDeleteTarget] = useState<LibraryPlaybook | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [improveTarget, setImproveTarget] = useState<LibraryPlaybook | null>(null);
  const [pendingCount, setPendingCount] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const rows = await listSuggestions({ state: 'pending' });
        if (!cancelled) setPendingCount(rows.length);
      } catch {
        if (!cancelled) setPendingCount(null);
      }
    };
    refresh();
    const interval = window.setInterval(() => {
      if (document.visibilityState === 'visible') refresh();
    }, 60000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    let active = true;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await listPlaybooks();
        if (!active) return;
        setItems(response.map(mapApiToLibraryItem));
        setUsingFallback(false);
      } catch (err) {
        if (!active) return;
        setItems(allPlaybooks.map(mapFallbackToLibraryItem));
        setUsingFallback(true);
        setError('API unreachable — showing bundled demo playbooks.');
      } finally {
        if (active) setLoading(false);
      }
    };

    load();
    return () => {
      active = false;
    };
  }, []);

  const tags = useMemo(() => {
    const set = new Set<string>();
    items.forEach((item) => item.tags.forEach((tag) => set.add(tag)));
    return Array.from(set).sort();
  }, [items]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return items.filter((item) => {
      if (activeCategory !== 'all' && item.categoryKey !== activeCategory) return false;
      if (activeTag !== 'all' && !item.tags.includes(activeTag)) return false;
      if (!query) return true;
      const haystack = `${item.title} ${item.description} ${item.content || ''}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [items, search, activeCategory, activeTag]);

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      if (!usingFallback) {
        await deletePlaybook(deleteTarget.id);
      }
      setItems((prev) => prev.filter((item) => item.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch (err) {
      setError('Failed to delete playbook.');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117] text-slate-100">
      <div className="max-w-6xl mx-auto px-6 py-10">
        <div className="flex flex-col gap-6">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <h1 className="text-3xl font-semibold">Playbook Library</h1>
              <p className="text-slate-400 text-sm mt-1">
                Browse, filter, and manage operational playbooks.
              </p>
            </div>
            <div className="flex gap-3">
              <button
                className="px-4 py-2 rounded-md bg-gradient-to-r from-purple-600/80 to-blue-600/80 border border-purple-500/30 text-white hover:from-purple-500/80 hover:to-blue-500/80 shadow-sm shadow-purple-500/10"
                onClick={() => navigate('#/ai/generate')}
              >
                ✨ AI Generate
              </button>
              <button
                className="px-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700"
                onClick={() => navigate('#/executions')}
              >
                Executions
              </button>
              <button
                className="px-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 inline-flex items-center gap-2"
                onClick={() => navigate('#/suggestions')}
                aria-label={
                  pendingCount && pendingCount > 0
                    ? `Suggestions, ${pendingCount} pending`
                    : 'Suggestions'
                }
              >
                Suggestions
                {pendingCount !== null && pendingCount > 0 && (
                  <span
                    className="inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 rounded-full bg-amber-500/20 border border-amber-500/40 text-amber-200 text-xs font-medium"
                    aria-hidden="true"
                  >
                    {pendingCount > 99 ? '99+' : pendingCount}
                  </span>
                )}
              </button>
              <button
                className="px-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700"
                onClick={() => navigate('#/integrations')}
              >
                Integrations
              </button>
              <button
                className="px-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700"
                onClick={() => navigate('#/import')}
              >
                Import
              </button>
              <button
                className="px-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700"
                onClick={() => navigate('#/editor')}
              >
                New Playbook
              </button>
            </div>
          </div>

          <div className="flex flex-col gap-4">
            <input
              className="w-full rounded-md bg-slate-900 border border-slate-700 px-4 py-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Search by title or content..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <div className="flex flex-wrap gap-2">
              <button
                className={`px-3 py-1 rounded-full text-xs border ${activeCategory === 'all'
                  ? 'bg-blue-600 border-blue-500 text-white'
                  : 'bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800'
                }`}
                onClick={() => setActiveCategory('all')}
              >
                All
              </button>
              {CATEGORY_FILTERS.map((filter) => (
                <button
                  key={filter.key}
                  className={`px-3 py-1 rounded-full text-xs border ${activeCategory === filter.key
                    ? 'bg-blue-600 border-blue-500 text-white'
                    : 'bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800'
                  }`}
                  onClick={() => setActiveCategory(filter.key)}
                >
                  {filter.label}
                </button>
              ))}
              <div className="ml-auto">
                <select
                  className="rounded-md bg-slate-900 border border-slate-700 px-3 py-1 text-xs text-slate-300"
                  value={activeTag}
                  onChange={(e) => setActiveTag(e.target.value)}
                >
                  <option value="all">All Tags</option>
                  {tags.map((tag) => (
                    <option key={tag} value={tag}>{tag}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {error && (
            <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
              {error}
            </div>
          )}

          {loading ? (
            <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6 text-slate-400">
              Loading playbooks...
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {filtered.map((item) => (
                <div
                  key={item.id}
                  className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 shadow-sm hover:border-slate-600 transition cursor-pointer"
                  onClick={() => navigate(`#/1/playbook/${encodeURIComponent(item.id)}`)}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <h3 className="text-lg font-semibold text-slate-100">{item.title}</h3>
                      <p className="text-sm text-slate-400 mt-1">{item.description || 'No description provided.'}</p>
                    </div>
                    <span className="px-2 py-1 rounded-full text-xs border border-slate-700 bg-slate-800 text-slate-300">
                      {item.categoryLabel}
                    </span>
                  </div>

                  <div className="mt-4 flex flex-wrap gap-2">
                    {item.tags.length > 0 ? (
                      item.tags.map((tag) => (
                        <span
                          key={tag}
                          className="px-2 py-1 rounded-full text-[10px] uppercase tracking-wide bg-slate-800 text-slate-300"
                        >
                          {tag}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500">No tags</span>
                    )}
                  </div>

                  <div className="mt-4 flex flex-wrap items-center gap-4 text-xs text-slate-400">
                    {item.updatedAt && <span>Updated: {item.updatedAt}</span>}
                    <span>Nodes: {item.nodeCount ?? '—'}</span>
                  </div>

                  <div className="mt-4 flex gap-2">
                    <button
                      className="px-3 py-1 rounded-md border border-slate-700 bg-slate-800 text-xs text-slate-200 hover:bg-slate-700"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`#/editor/${encodeURIComponent(item.id)}`);
                      }}
                    >
                      Edit
                    </button>
                    <button
                      className="px-3 py-1 rounded-md border border-green-500/40 bg-green-500/10 text-xs text-green-200 hover:bg-green-500/20"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`#/executions?playbook=${encodeURIComponent(item.id)}`);
                      }}
                    >
                      ▶ Execute
                    </button>
                    <button
                      className="px-3 py-1 rounded-md border border-purple-500/40 bg-purple-500/10 text-xs text-purple-200 hover:bg-purple-500/20"
                      onClick={(e) => {
                        e.stopPropagation();
                        setImproveTarget(item);
                      }}
                      title="Improve with AI"
                    >
                      🤖
                    </button>
                    <button
                      className="px-3 py-1 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-200 hover:bg-red-500/20"
                      onClick={(e) => {
                        e.stopPropagation();
                        setDeleteTarget(item);
                      }}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}

              {filtered.length === 0 && (
                <div className="col-span-full rounded-lg border border-dashed border-slate-800 p-10 text-center text-slate-500">
                  No playbooks match your filters.
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {improveTarget && (
        <AIImprovePanel
          playbookId={improveTarget.id}
          playbookTitle={improveTarget.title}
          onClose={() => setImproveTarget(null)}
        />
      )}

      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-900 p-6">
            <h2 className="text-lg font-semibold text-slate-100">Delete playbook?</h2>
            <p className="text-sm text-slate-400 mt-2">
              This will remove <span className="text-slate-200">{deleteTarget.title}</span> from the library.
            </p>
            <div className="mt-6 flex justify-end gap-3">
              <button
                className="px-4 py-2 rounded-md border border-slate-700 bg-slate-800 text-sm text-slate-200"
                onClick={() => setDeleteTarget(null)}
                disabled={deleting}
              >
                Cancel
              </button>
              <button
                className="px-4 py-2 rounded-md bg-red-500 text-sm text-white hover:bg-red-400 disabled:opacity-60"
                onClick={handleDelete}
                disabled={deleting}
              >
                {deleting ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

function mapApiToLibraryItem(playbook: ApiPlaybookSummary): LibraryPlaybook {
  const categoryLabel = formatCategoryLabel(playbook.category);
  const categoryKey = normalizeCategoryKey(playbook.category);
  return {
    id: String(playbook.id),
    title: playbook.title || 'Untitled Playbook',
    description: playbook.description || '',
    categoryLabel,
    categoryKey,
    tags: (playbook.tags || []).map((tag) =>
      typeof tag === 'string' ? tag : tag.name,
    ),
    updatedAt: formatUpdatedDate(playbook.updated_at),
    nodeCount: playbook.node_count ?? playbook.graph_json?.nodes?.length,
    content: playbook.content_markdown,
  };
}

function mapFallbackToLibraryItem(playbook: PlaybookLibraryItem): LibraryPlaybook {
  return {
    id: playbook.slug,
    title: playbook.metadata.title,
    description: playbook.description,
    categoryLabel: formatCategoryLabel(playbook.category),
    categoryKey: normalizeCategoryKey(playbook.category),
    tags: playbook.tags,
    updatedAt: playbook.metadata.lastUpdated,
    nodeCount: playbook.graph.nodes.length,
    content: playbook.markdown,
  };
}

function normalizeCategoryKey(category?: string): string {
  const value = (category || '').toLowerCase().replace(/_/g, '-');
  if (value.includes('vulnerability')) return 'vulnerability-remediation';
  if (value.includes('incident')) return 'incident-response';
  if (value.includes('threat')) return 'threat-hunting';
  if (value.includes('custom')) return 'custom';
  return value || 'custom';
}

function formatCategoryLabel(category?: string): string {
  if (!category) return 'Custom';
  const normalized = category.replace(/_/g, '-').toLowerCase();
  if (normalized.includes('vulnerability')) return 'Vulnerability Remediation';
  if (normalized.includes('incident')) return 'Incident Response';
  if (normalized.includes('threat')) return 'Threat Hunting';
  if (normalized.includes('custom')) return 'Custom';
  return category.replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatUpdatedDate(updatedAt?: string): string | undefined {
  if (!updatedAt) return undefined;
  const date = parseApiDate(updatedAt);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toLocaleDateString();
}

export default LibraryPage;
