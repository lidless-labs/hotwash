/**
 * ExecutionsPage — List and manage playbook executions.
 */

import React, { useEffect, useMemo, useState } from 'react';
import { useHashRouter } from '../router';
import { API_BASE_URL, API_KEY } from '../api/client';
import { parseApiDate, relativeTime } from '../lib/time';

interface Execution {
  id: string;
  playbook_id: string;
  playbook_title?: string;
  incident_title: string;
  incident_id?: string;
  status: string;
  started_by?: string;
  started_at: string;
  completed_at?: string;
  steps_total?: number;
  steps_completed?: number;
}

interface PlaybookOption {
  id: string;
  title: string;
}

const STATUS_COLORS: Record<string, string> = {
  active: '#22c55e',
  paused: '#eab308',
  completed: '#3b82f6',
  abandoned: '#ef4444',
};

const FILTERS = ['all', 'active', 'paused', 'completed', 'abandoned'];

const ExecutionsPage: React.FC = () => {
  const { navigate } = useHashRouter();
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('all');
  const [showNewModal, setShowNewModal] = useState(false);
  const [playbooks, setPlaybooks] = useState<PlaybookOption[]>([]);
  const [newPlaybookId, setNewPlaybookId] = useState('');
  const [newIncidentTitle, setNewIncidentTitle] = useState('');
  const [newStartedBy, setNewStartedBy] = useState('');
  const [creating, setCreating] = useState(false);

  // Check for pre-selected playbook from URL query
  useEffect(() => {
    const hash = window.location.hash;
    const match = hash.match(/playbook=([^&]+)/);
    if (match) {
      setNewPlaybookId(decodeURIComponent(match[1]));
      setShowNewModal(true);
    }
  }, []);

  useEffect(() => {
    fetchExecutions();
  }, []);

  const fetchExecutions = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/executions`, {
        headers: {
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
      });
      if (!res.ok) throw new Error('Failed to fetch');
      const data = await res.json();
      setExecutions(Array.isArray(data) ? data : data.executions || []);
    } catch {
      setError('Could not load executions. Is the API running?');
      setExecutions([]);
    } finally {
      setLoading(false);
    }
  };

  const fetchPlaybooks = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/playbooks`, {
        headers: {
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
      });
      if (!res.ok) return;
      const data = await res.json();
      const list = Array.isArray(data) ? data : data.playbooks || [];
      setPlaybooks(list.map((p: any) => ({ id: p.id, title: p.title || 'Untitled' })));
    } catch {}
  };

  useEffect(() => {
    if (showNewModal) fetchPlaybooks();
  }, [showNewModal]);

  const handleCreate = async () => {
    if (!newPlaybookId || !newIncidentTitle.trim()) return;
    setCreating(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/executions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
        body: JSON.stringify({
          playbook_id: newPlaybookId,
          incident_title: newIncidentTitle.trim(),
          started_by: newStartedBy.trim() || undefined,
        }),
      });
      if (!res.ok) throw new Error('Failed to create');
      const created = await res.json();
      setShowNewModal(false);
      setNewIncidentTitle('');
      setNewStartedBy('');
      navigate(`#/executions/${created.id}`);
    } catch {
      setError('Failed to create execution.');
    } finally {
      setCreating(false);
    }
  };

  const filtered = useMemo(() => {
    if (filter === 'all') return executions;
    return executions.filter((e) => e.status === filter);
  }, [executions, filter]);

  const stats = useMemo(() => {
    const active = executions.filter((e) => e.status === 'active' || e.status === 'paused').length;
    const completed = executions.filter((e) => e.status === 'completed').length;
    const completedExecs = executions.filter((e) => e.status === 'completed' && e.started_at && e.completed_at);
    let avgTime = '—';
    if (completedExecs.length > 0) {
      const total = completedExecs.reduce((sum, e) => {
        return sum + (parseApiDate(e.completed_at!).getTime() - parseApiDate(e.started_at).getTime());
      }, 0);
      const avgMs = total / completedExecs.length;
      if (avgMs < 3600000) avgTime = `${Math.round(avgMs / 60000)}m`;
      else avgTime = `${(avgMs / 3600000).toFixed(1)}h`;
    }
    return { active, completed, avgTime };
  }, [executions]);

  return (
    <div className="min-h-screen bg-[#0d1117] text-slate-100">
      <div className="max-w-6xl mx-auto px-6 py-10">
        {/* Header */}
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between mb-6">
          <div>
            <h1 className="text-3xl font-semibold">Executions</h1>
            <p className="text-slate-400 text-sm mt-1">Track and manage active incident playbook executions.</p>
          </div>
          <div className="flex gap-3">
            <button
              className="px-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700"
              onClick={() => navigate('#/library')}
            >
              Library
            </button>
            <button
              className="px-4 py-2 rounded-md bg-blue-600 text-white hover:bg-blue-500"
              onClick={() => setShowNewModal(true)}
            >
              New Execution
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{stats.active}</div>
            <div className="text-xs text-slate-400 mt-1">Active</div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-center">
            <div className="text-2xl font-bold text-blue-400">{stats.completed}</div>
            <div className="text-xs text-slate-400 mt-1">Completed</div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-center">
            <div className="text-2xl font-bold text-slate-200">{stats.avgTime}</div>
            <div className="text-xs text-slate-400 mt-1">Avg Time</div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2 mb-6">
          {FILTERS.map((f) => (
            <button
              key={f}
              className={`px-3 py-1 rounded-full text-xs border capitalize ${
                filter === f
                  ? 'bg-blue-600 border-blue-500 text-white'
                  : 'bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800'
              }`}
              onClick={() => setFilter(f)}
            >
              {f}
            </button>
          ))}
        </div>

        {error && (
          <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200 mb-4">
            {error}
          </div>
        )}

        {loading ? (
          <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6 text-slate-400">Loading...</div>
        ) : filtered.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-800 p-10 text-center text-slate-500">
            {executions.length === 0
              ? 'No executions yet. Start one from any playbook.'
              : 'No executions match this filter.'}
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {filtered.map((exec) => {
              const total = exec.steps_total || 1;
              const done = exec.steps_completed || 0;
              const pct = Math.round((done / total) * 100);
              return (
                <div
                  key={exec.id}
                  className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 shadow-sm hover:border-slate-600 transition cursor-pointer"
                  onClick={() => navigate(`#/executions/${exec.id}`)}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="text-lg font-semibold text-slate-100 truncate">{exec.incident_title}</h3>
                      <p className="text-sm text-slate-400 mt-0.5 truncate">{exec.playbook_title || exec.playbook_id}</p>
                    </div>
                    <span
                      className="px-2 py-1 rounded-full text-xs font-medium capitalize whitespace-nowrap"
                      style={{
                        backgroundColor: `${STATUS_COLORS[exec.status] || '#6b7280'}20`,
                        color: STATUS_COLORS[exec.status] || '#6b7280',
                        border: `1px solid ${STATUS_COLORS[exec.status] || '#6b7280'}40`,
                      }}
                    >
                      {exec.status === 'active' && (
                        <span className="inline-block w-2 h-2 rounded-full mr-1 animate-pulse" style={{ backgroundColor: '#22c55e' }} />
                      )}
                      {exec.status}
                    </span>
                  </div>

                  {/* Progress */}
                  <div className="mt-3">
                    <div className="flex justify-between text-xs text-slate-400 mb-1">
                      <span>{done}/{total} steps</span>
                      <span>{pct}%</span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${pct}%`,
                          background: `linear-gradient(90deg, #3b82f6, #22c55e)`,
                        }}
                      />
                    </div>
                  </div>

                  <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
                    <span title={exec.started_at}>{relativeTime(exec.started_at)}</span>
                    {exec.started_by && <span>by {exec.started_by}</span>}
                  </div>

                  <div className="mt-3 flex gap-2">
                    {(exec.status === 'active' || exec.status === 'paused') && (
                      <button
                        className="px-3 py-1 rounded-md border border-slate-700 bg-slate-800 text-xs text-slate-200 hover:bg-slate-700"
                        onClick={(e) => { e.stopPropagation(); navigate(`#/executions/${exec.id}`); }}
                      >
                        Resume
                      </button>
                    )}
                    {exec.status === 'completed' && (
                      <button
                        className="px-3 py-1 rounded-md border border-blue-500/40 bg-blue-500/10 text-xs text-blue-200 hover:bg-blue-500/20"
                        onClick={(e) => { e.stopPropagation(); navigate(`#/executions/${exec.id}/report`); }}
                      >
                        View Report
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* New Execution Modal */}
      {showNewModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-900 p-6">
            <h2 className="text-lg font-semibold text-slate-100 mb-4">New Execution</h2>
            <div className="flex flex-col gap-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Playbook</label>
                <select
                  className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-100"
                  value={newPlaybookId}
                  onChange={(e) => setNewPlaybookId(e.target.value)}
                >
                  <option value="">Select a playbook...</option>
                  {playbooks.map((p) => (
                    <option key={p.id} value={p.id}>{p.title}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Incident Title</label>
                <input
                  className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., Ransomware on PROD-DB-01"
                  value={newIncidentTitle}
                  onChange={(e) => setNewIncidentTitle(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Started By (optional)</label>
                <input
                  className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Analyst name"
                  value={newStartedBy}
                  onChange={(e) => setNewStartedBy(e.target.value)}
                />
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button
                className="px-4 py-2 rounded-md border border-slate-700 bg-slate-800 text-sm text-slate-200"
                onClick={() => setShowNewModal(false)}
              >
                Cancel
              </button>
              <button
                className="px-4 py-2 rounded-md bg-blue-600 text-sm text-white hover:bg-blue-500 disabled:opacity-60"
                onClick={handleCreate}
                disabled={creating || !newPlaybookId || !newIncidentTitle.trim()}
              >
                {creating ? 'Creating...' : 'Start Execution'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ExecutionsPage;
