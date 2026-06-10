/**
 * ExecutionViewPage — Main operational view during an incident.
 * Split layout: step checklist (left) + detail panel (right).
 */

import React, { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { useHashRouter } from '../router';
import { API_BASE_URL, API_KEY } from '../api/client';
import { useExecutionSocket } from '../hooks/useExecutionSocket';
import { parseApiDate, relativeTime } from '../lib/time';

interface Step {
  node_id: string;
  node_type: string;
  node_label: string;
  phase?: string;
  status: string;
  assignee?: string;
  notes?: string[];
  evidence?: { filename: string; size: number; uploaded_at: string }[];
  decision_taken?: string;
  decision_options?: string[];
  started_at?: string;
  completed_at?: string;
}

interface Execution {
  id: string;
  playbook_id: string;
  incident_title: string;
  status: string;
  started_by?: string;
  started_at: string;
  completed_at?: string;
  notes?: string;
}

interface TimelineEvent {
  timestamp: string;
  event_type: string;
  actor?: string;
  description: string;
}

const STATUS_ICONS: Record<string, string> = {
  not_started: '⬜',
  in_progress: '🔵',
  completed: '✅',
  skipped: '⏭️',
  blocked: '🚫',
};

const STATUS_COLORS: Record<string, string> = {
  not_started: '#6b7280',
  in_progress: '#3b82f6',
  completed: '#22c55e',
  skipped: '#eab308',
  blocked: '#ef4444',
  active: '#22c55e',
  paused: '#eab308',
};

const STEP_STATUSES = ['not_started', 'in_progress', 'completed', 'skipped', 'blocked'];

const EVENT_COLORS: Record<string, string> = {
  step_started: '#3b82f6',
  step_completed: '#22c55e',
  note_added: '#6b7280',
  assignee_changed: '#a855f7',
  evidence_attached: '#f97316',
  execution_paused: '#eab308',
  execution_completed: '#3b82f6',
};

function formatDuration(ms: number): string {
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
  return `${Math.floor(ms / 3600000)}h ${Math.floor((ms % 3600000) / 60000)}m`;
}

interface ExecutionViewPageProps {
  executionId: string;
}

const ExecutionViewPage: React.FC<ExecutionViewPageProps> = ({ executionId }) => {
  const { navigate } = useHashRouter();
  const [execution, setExecution] = useState<Execution | null>(null);
  const [steps, setSteps] = useState<Step[]>([]);
  const [playbookTitle, setPlaybookTitle] = useState('');
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [collapsedPhases, setCollapsedPhases] = useState<Set<string>>(new Set());
  const [showTimeline, setShowTimeline] = useState(false);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [timelineFilters, setTimelineFilters] = useState<Set<string>>(new Set());
  const [newNote, setNewNote] = useState('');
  const [newAssignee, setNewAssignee] = useState('');
  const [uploading, setUploading] = useState(false);
  const [elapsedStr, setElapsedStr] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { lastEvent, connected } = useExecutionSocket(executionId);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/executions/${executionId}`, {
        headers: {
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
      });
      if (!res.ok) throw new Error('Failed to fetch');
      const data = await res.json();
      setExecution(data.execution);
      setSteps(data.steps || []);
      setPlaybookTitle(data.playbook_title || '');
    } catch {
      setError('Failed to load execution.');
    } finally {
      setLoading(false);
    }
  }, [executionId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Refetch on websocket event
  useEffect(() => {
    if (lastEvent) fetchData();
  }, [lastEvent, fetchData]);

  // Elapsed time counter
  useEffect(() => {
    if (!execution?.started_at) return;
    const update = () => {
      const end = execution.completed_at ? parseApiDate(execution.completed_at).getTime() : Date.now();
      setElapsedStr(formatDuration(end - parseApiDate(execution.started_at).getTime()));
    };
    update();
    if (!execution.completed_at) {
      const interval = setInterval(update, 1000);
      return () => clearInterval(interval);
    }
  }, [execution?.started_at, execution?.completed_at]);

  // Group steps by phase
  const phases = useMemo(() => {
    const map = new Map<string, Step[]>();
    steps.forEach((s) => {
      const phase = s.phase || 'Default';
      if (!map.has(phase)) map.set(phase, []);
      map.get(phase)!.push(s);
    });
    return map;
  }, [steps]);

  const selectedStep = useMemo(() => steps.find((s) => s.node_id === selectedStepId), [steps, selectedStepId]);

  const totalSteps = steps.length;
  const completedSteps = steps.filter((s) => s.status === 'completed' || s.status === 'skipped').length;
  const progressPct = totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0;

  const updateExecution = async (body: Record<string, any>) => {
    try {
      await fetch(`${API_BASE_URL}/api/executions/${executionId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
        body: JSON.stringify(body),
      });
      fetchData();
    } catch {}
  };

  const updateStep = async (nodeId: string, body: Record<string, any>) => {
    try {
      await fetch(`${API_BASE_URL}/api/executions/${executionId}/steps/${nodeId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
        body: JSON.stringify(body),
      });
      fetchData();
    } catch {}
  };

  const handleAddNote = async () => {
    if (!selectedStepId || !newNote.trim()) return;
    await updateStep(selectedStepId, { notes: newNote.trim() });
    setNewNote('');
  };

  const handleUploadEvidence = async (file: File) => {
    if (!selectedStepId) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      await fetch(`${API_BASE_URL}/api/executions/${executionId}/steps/${selectedStepId}/evidence`, {
        method: 'POST',
        headers: {
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
        body: formData,
      });
      fetchData();
    } catch {}
    setUploading(false);
  };

  const fetchTimeline = async () => {
    setTimelineLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/executions/${executionId}/timeline`, {
        headers: {
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
      });
      if (res.ok) {
        const data = await res.json();
        setTimeline(Array.isArray(data) ? data : data.events || []);
      }
    } catch {}
    setTimelineLoading(false);
  };

  const handleConfirmAction = (action: string) => {
    if (!confirm(`Are you sure you want to ${action} this execution?`)) return;
    const statusMap: Record<string, string> = { pause: 'paused', complete: 'completed', abandon: 'abandoned' };
    updateExecution({ status: statusMap[action] });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0d1117] text-slate-100 flex items-center justify-center">
        <div className="text-slate-400">Loading execution...</div>
      </div>
    );
  }

  if (error || !execution) {
    return (
      <div className="min-h-screen bg-[#0d1117] text-slate-100 flex items-center justify-center">
        <div className="text-red-400">{error || 'Execution not found.'}</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0d1117] text-slate-100 flex flex-col">
      {/* Top Bar */}
      <div className="border-b border-slate-800 bg-slate-900/80 px-6 py-3">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-4 min-w-0">
            <button className="text-slate-400 hover:text-slate-200 text-sm" onClick={() => navigate('#/executions')}>← Back</button>
            <div className="min-w-0">
              <h1 className="text-lg font-semibold truncate">{execution.incident_title}</h1>
              <p className="text-xs text-slate-400 truncate">{playbookTitle}</p>
            </div>
            <span
              className="px-2 py-1 rounded-full text-xs font-medium capitalize whitespace-nowrap"
              style={{
                backgroundColor: `${STATUS_COLORS[execution.status] || '#6b7280'}20`,
                color: STATUS_COLORS[execution.status] || '#6b7280',
              }}
            >
              {execution.status}
            </span>
            {/* WebSocket indicator */}
            <span title={connected ? 'Live updates active' : 'No live updates'}>
              <span className={`inline-block w-2 h-2 rounded-full ${connected ? 'bg-green-400' : 'bg-red-400'}`} />
            </span>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="text-sm text-slate-300">
              <span className="text-slate-500">Elapsed:</span> {elapsedStr}
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span>{completedSteps}/{totalSteps}</span>
              <div className="w-24 h-2 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${progressPct}%`, background: 'linear-gradient(90deg, #3b82f6, #22c55e)' }} />
              </div>
              <span>{progressPct}%</span>
            </div>
            <button className="px-3 py-1 rounded-md border border-slate-700 bg-slate-800 text-xs text-slate-200 hover:bg-slate-700" onClick={() => { setShowTimeline(true); fetchTimeline(); }}>Timeline</button>
            {execution.status === 'active' && (
              <button className="px-3 py-1 rounded-md border border-yellow-500/40 bg-yellow-500/10 text-xs text-yellow-200 hover:bg-yellow-500/20" onClick={() => handleConfirmAction('pause')}>Pause</button>
            )}
            {(execution.status === 'active' || execution.status === 'paused') && (
              <>
                <button className="px-3 py-1 rounded-md border border-blue-500/40 bg-blue-500/10 text-xs text-blue-200 hover:bg-blue-500/20" onClick={() => handleConfirmAction('complete')}>Complete</button>
                <button className="px-3 py-1 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-200 hover:bg-red-500/20" onClick={() => handleConfirmAction('abandon')}>Abandon</button>
              </>
            )}
            {execution.status === 'completed' && (
              <button className="px-3 py-1 rounded-md bg-blue-600 text-xs text-white hover:bg-blue-500" onClick={() => navigate(`#/executions/${executionId}/report`)}>View Report</button>
            )}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: Step List */}
        <div className="w-[60%] overflow-y-auto p-6 border-r border-slate-800">
          {Array.from(phases.entries()).map(([phase, phaseSteps]) => {
            const collapsed = collapsedPhases.has(phase);
            const phaseCompleted = phaseSteps.filter((s) => s.status === 'completed' || s.status === 'skipped').length;
            return (
              <div key={phase} className="mb-4">
                <button
                  className="flex items-center gap-2 w-full text-left text-sm font-medium text-slate-300 hover:text-slate-100 mb-2"
                  onClick={() => setCollapsedPhases((prev) => {
                    const next = new Set(prev);
                    collapsed ? next.delete(phase) : next.add(phase);
                    return next;
                  })}
                >
                  <span className="text-xs">{collapsed ? '▶' : '▼'}</span>
                  <span>{phase}</span>
                  <span className="text-xs text-slate-500 ml-auto">{phaseCompleted}/{phaseSteps.length}</span>
                </button>
                {!collapsed && (
                  <div className="flex flex-col gap-2 ml-4">
                    {phaseSteps.map((step) => {
                      const isSelected = step.node_id === selectedStepId;
                      const isDecision = step.node_type === 'decision';
                      const isExecute = step.node_type === 'execute' || step.node_type === 'action';
                      let duration = '';
                      if (step.started_at) {
                        const end = step.completed_at ? parseApiDate(step.completed_at).getTime() : Date.now();
                        duration = formatDuration(end - parseApiDate(step.started_at).getTime());
                      }
                      return (
                        <div
                          key={step.node_id}
                          className={`rounded-lg border p-3 cursor-pointer transition ${
                            isSelected
                              ? 'border-blue-500 bg-blue-500/10'
                              : 'border-slate-800 bg-slate-900/40 hover:border-slate-600'
                          } ${isDecision ? 'border-l-4 border-l-purple-500' : ''}`}
                          onClick={() => setSelectedStepId(step.node_id)}
                        >
                          <div className="flex items-center gap-2">
                            <span className="text-base">{STATUS_ICONS[step.status] || '⬜'}</span>
                            {isExecute && <span className="text-xs">⚡</span>}
                            {isDecision && <span className="text-xs">◆</span>}
                            <span className="text-sm font-medium text-slate-100 flex-1">{step.node_label}</span>
                            {step.assignee && (
                              <span className="px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-300">{step.assignee}</span>
                            )}
                            {duration && <span className="text-xs text-slate-500">{duration}</span>}
                          </div>
                          {isDecision && step.decision_taken && (
                            <div className="mt-1 text-xs text-purple-300 ml-7">Decision: {step.decision_taken}</div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
          {steps.length === 0 && (
            <div className="text-center text-slate-500 py-10">No steps found for this execution.</div>
          )}
        </div>

        {/* Right: Detail Panel */}
        <div className="w-[40%] overflow-y-auto p-6 bg-slate-900/30">
          {selectedStep ? (
            <div className="flex flex-col gap-5">
              <div>
                <h2 className="text-lg font-semibold">{selectedStep.node_label}</h2>
                <p className="text-xs text-slate-400 mt-1">Node: {selectedStep.node_id} · Type: {selectedStep.node_type}</p>
              </div>

              {/* Status */}
              <div>
                <label className="block text-xs text-slate-400 mb-1">Status</label>
                <select
                  className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-100"
                  value={selectedStep.status}
                  onChange={(e) => updateStep(selectedStep.node_id, { status: e.target.value })}
                >
                  {STEP_STATUSES.map((s) => (
                    <option key={s} value={s}>{STATUS_ICONS[s]} {s.replace('_', ' ')}</option>
                  ))}
                </select>
              </div>

              {/* Assignee */}
              <div>
                <label className="block text-xs text-slate-400 mb-1">Assignee</label>
                <div className="flex gap-2">
                  <input
                    className="flex-1 rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Analyst name..."
                    value={newAssignee || selectedStep.assignee || ''}
                    onChange={(e) => setNewAssignee(e.target.value)}
                    onBlur={() => {
                      if (newAssignee && newAssignee !== selectedStep.assignee) {
                        updateStep(selectedStep.node_id, { assignee: newAssignee });
                      }
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && newAssignee) {
                        updateStep(selectedStep.node_id, { assignee: newAssignee });
                      }
                    }}
                  />
                </div>
              </div>

              {/* Decision */}
              {(selectedStep.node_type === 'decision' && selectedStep.decision_options && selectedStep.decision_options.length > 0) && (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Decision</label>
                  <div className="flex flex-col gap-2">
                    {selectedStep.decision_options.map((opt) => (
                      <label key={opt} className="flex items-center gap-2 text-sm text-slate-200">
                        <input
                          type="radio"
                          name="decision"
                          checked={selectedStep.decision_taken === opt}
                          onChange={() => updateStep(selectedStep.node_id, { decision_taken: opt })}
                          className="accent-purple-500"
                        />
                        {opt}
                      </label>
                    ))}
                  </div>
                </div>
              )}

              {/* Notes */}
              <div>
                <label className="block text-xs text-slate-400 mb-1">Notes</label>
                <div className="max-h-40 overflow-y-auto mb-2 rounded-md bg-slate-800/50 border border-slate-700">
                  {selectedStep.notes && selectedStep.notes.length > 0 ? (
                    <div className="p-2 flex flex-col gap-1">
                      {selectedStep.notes.map((note, i) => (
                        <div key={i} className="text-xs text-slate-300 border-b border-slate-700/50 pb-1 last:border-0">{note}</div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-2 text-xs text-slate-500">No notes yet.</div>
                  )}
                </div>
                <div className="flex gap-2">
                  <input
                    className="flex-1 rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Add a note..."
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleAddNote(); }}
                  />
                  <button
                    className="px-3 py-2 rounded-md bg-slate-800 border border-slate-700 text-xs text-slate-200 hover:bg-slate-700"
                    onClick={handleAddNote}
                  >
                    Add
                  </button>
                </div>
              </div>

              {/* Evidence */}
              <div>
                <label className="block text-xs text-slate-400 mb-1">Evidence</label>
                {selectedStep.evidence && selectedStep.evidence.length > 0 && (
                  <div className="flex flex-col gap-1 mb-2">
                    {selectedStep.evidence.map((ev, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs text-slate-300 bg-slate-800/50 rounded px-2 py-1">
                        <span>📎</span>
                        <span className="flex-1 truncate">{ev.filename}</span>
                        <span className="text-slate-500">{(ev.size / 1024).toFixed(1)}KB</span>
                        <span className="text-slate-500" title={ev.uploaded_at}>{relativeTime(ev.uploaded_at)}</span>
                      </div>
                    ))}
                  </div>
                )}
                <input type="file" ref={fileInputRef} className="hidden" onChange={(e) => { if (e.target.files?.[0]) handleUploadEvidence(e.target.files[0]); }} />
                <div
                  className="border-2 border-dashed border-slate-700 rounded-lg p-4 text-center text-xs text-slate-500 hover:border-slate-500 cursor-pointer transition"
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
                  onDrop={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (e.dataTransfer.files?.[0]) handleUploadEvidence(e.dataTransfer.files[0]);
                  }}
                >
                  {uploading ? 'Uploading...' : 'Drop file here or click to upload'}
                </div>
              </div>

              {/* Quick Actions */}
              <div className="flex gap-2 pt-2 border-t border-slate-800">
                {selectedStep.status === 'not_started' && (
                  <button className="px-3 py-1.5 rounded-md bg-blue-600 text-xs text-white hover:bg-blue-500" onClick={() => updateStep(selectedStep.node_id, { status: 'in_progress' })}>Start Step</button>
                )}
                {selectedStep.status === 'in_progress' && (
                  <button className="px-3 py-1.5 rounded-md bg-green-600 text-xs text-white hover:bg-green-500" onClick={() => updateStep(selectedStep.node_id, { status: 'completed' })}>Complete Step</button>
                )}
                {selectedStep.status !== 'completed' && selectedStep.status !== 'skipped' && (
                  <button className="px-3 py-1.5 rounded-md border border-yellow-500/40 bg-yellow-500/10 text-xs text-yellow-200 hover:bg-yellow-500/20" onClick={() => updateStep(selectedStep.node_id, { status: 'skipped' })}>Skip Step</button>
                )}
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-slate-500 text-sm">
              Select a step to view details.
            </div>
          )}
        </div>
      </div>

      {/* Timeline Modal */}
      {showTimeline && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="w-full max-w-2xl max-h-[80vh] rounded-lg border border-slate-700 bg-slate-900 flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-slate-800">
              <h2 className="text-lg font-semibold">Timeline</h2>
              <button className="text-slate-400 hover:text-slate-200" onClick={() => setShowTimeline(false)}>✕</button>
            </div>
            {/* Filters */}
            <div className="flex flex-wrap gap-2 px-4 py-2 border-b border-slate-800">
              {Object.keys(EVENT_COLORS).map((type) => (
                <label key={type} className="flex items-center gap-1 text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={timelineFilters.size === 0 || timelineFilters.has(type)}
                    onChange={(e) => setTimelineFilters((prev) => {
                      const next = new Set(prev);
                      e.target.checked ? next.delete(type) : next.add(type);
                      if (next.size === Object.keys(EVENT_COLORS).length) return new Set();
                      return next;
                    })}
                    className="accent-blue-500"
                  />
                  <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: EVENT_COLORS[type] }} />
                  {type.replace(/_/g, ' ')}
                </label>
              ))}
            </div>
            <div className="flex-1 overflow-y-auto p-4">
              {timelineLoading ? (
                <div className="text-slate-400 text-sm">Loading timeline...</div>
              ) : timeline.length === 0 ? (
                <div className="text-slate-500 text-sm">No events recorded.</div>
              ) : (
                <div className="relative pl-6">
                  <div className="absolute left-2 top-0 bottom-0 w-0.5 bg-slate-800" />
                  {timeline
                    .filter((e) => timelineFilters.size === 0 || !timelineFilters.has(e.event_type))
                    .map((event, i) => (
                    <div key={i} className="relative mb-4 pl-4">
                      <div
                        className="absolute left-[-14px] top-1.5 w-3 h-3 rounded-full border-2 border-slate-900"
                        style={{ backgroundColor: EVENT_COLORS[event.event_type] || '#6b7280' }}
                      />
                      <div className="text-xs text-slate-500" title={event.timestamp}>{relativeTime(event.timestamp)}</div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span
                          className="px-1.5 py-0.5 rounded text-[10px] font-medium"
                          style={{
                            backgroundColor: `${EVENT_COLORS[event.event_type] || '#6b7280'}20`,
                            color: EVENT_COLORS[event.event_type] || '#6b7280',
                          }}
                        >
                          {event.event_type.replace(/_/g, ' ')}
                        </span>
                        {event.actor && <span className="text-xs text-slate-400">{event.actor}</span>}
                      </div>
                      <p className="text-sm text-slate-200 mt-0.5">{event.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ExecutionViewPage;
