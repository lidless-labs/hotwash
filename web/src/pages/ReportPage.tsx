/**
 * ReportPage — After-action report for a completed execution.
 * Clean, printable format with export options.
 */

import React, { useEffect, useState } from 'react';
import { useHashRouter } from '../router';
import { API_BASE_URL, API_KEY } from '../api/client';
import { parseApiDate } from '../lib/time';

interface ReportData {
  execution: {
    id: string;
    incident_title: string;
    status: string;
    started_by?: string;
    started_at: string;
    completed_at?: string;
  };
  playbook_title: string;
  metrics?: {
    total_duration?: string;
    steps_completed?: number;
    steps_total?: number;
    mean_step_time?: string;
    bottleneck_step?: string;
    bottleneck_time?: string;
  };
  timeline?: { timestamp: string; event_type: string; actor?: string; description: string }[];
  steps?: {
    node_id: string;
    node_label: string;
    status: string;
    assignee?: string;
    duration?: string;
    notes?: string[];
    evidence?: { filename: string; size: number }[];
  }[];
}

function formatDuration(start: string, end?: string): string {
  if (!end) return '—';
  const ms = parseApiDate(end).getTime() - parseApiDate(start).getTime();
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
}

interface ReportPageProps {
  executionId: string;
}

const ReportPage: React.FC<ReportPageProps> = ({ executionId }) => {
  const { navigate } = useHashRouter();
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied'>('idle');

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/executions/${executionId}/report`, {
          headers: {
            ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
          },
        });
        if (!res.ok) throw new Error('Failed to fetch report');
        setReport(await res.json());
      } catch {
        setError('Failed to load report.');
      } finally {
        setLoading(false);
      }
    })();
  }, [executionId]);

  const handleCopyMarkdown = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/executions/${executionId}/report/markdown`, {
        headers: {
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
      });
      if (!res.ok) throw new Error();
      const text = await res.text();
      await navigator.clipboard.writeText(text);
      setCopyStatus('copied');
      setTimeout(() => setCopyStatus('idle'), 2000);
    } catch {
      alert('Failed to copy markdown.');
    }
  };

  if (loading) {
    return <div className="min-h-screen bg-[#0d1117] text-slate-100 flex items-center justify-center"><div className="text-slate-400">Loading report...</div></div>;
  }
  if (error || !report) {
    return <div className="min-h-screen bg-[#0d1117] text-slate-100 flex items-center justify-center"><div className="text-red-400">{error || 'Report not found.'}</div></div>;
  }

  const exec = report.execution;
  const metrics = report.metrics;
  const duration = formatDuration(exec.started_at, exec.completed_at);

  return (
    <>
      <style>{`
        @media print {
          body { background: white !important; color: black !important; }
          .no-print { display: none !important; }
          .print-section { break-inside: avoid; }
          .report-container { max-width: 100% !important; padding: 0 !important; }
          .report-container * { color: black !important; background: white !important; border-color: #ccc !important; }
        }
      `}</style>
      <div className="min-h-screen bg-[#0d1117] text-slate-100">
        <div className="report-container max-w-4xl mx-auto px-6 py-10">
          {/* Nav */}
          <div className="no-print flex items-center justify-between mb-8">
            <button className="text-slate-400 hover:text-slate-200 text-sm" onClick={() => navigate(`#/executions/${executionId}`)}>← Back to Execution</button>
            <div className="flex gap-2">
              <button
                className="px-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-sm text-slate-200 hover:bg-slate-700"
                onClick={handleCopyMarkdown}
              >
                {copyStatus === 'copied' ? '✓ Copied!' : 'Copy Markdown'}
              </button>
              <button
                className="px-4 py-2 rounded-md bg-blue-600 text-sm text-white hover:bg-blue-500"
                onClick={() => window.print()}
              >
                Print
              </button>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="print-section mb-8">
            <h1 className="text-2xl font-bold mb-2">After-Action Report</h1>
            <h2 className="text-xl text-slate-300 mb-4">{exec.incident_title}</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <div className="text-slate-500">Playbook</div>
                <div className="text-slate-200">{report.playbook_title}</div>
              </div>
              <div>
                <div className="text-slate-500">Duration</div>
                <div className="text-slate-200">{duration}</div>
              </div>
              <div>
                <div className="text-slate-500">Outcome</div>
                <div className="text-slate-200 capitalize">{exec.status}</div>
              </div>
              <div>
                <div className="text-slate-500">Started By</div>
                <div className="text-slate-200">{exec.started_by || '—'}</div>
              </div>
            </div>
          </div>

          {/* Metrics */}
          {metrics && (
            <div className="print-section grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-center">
                <div className="text-xl font-bold text-slate-200">{metrics.total_duration || duration}</div>
                <div className="text-xs text-slate-400 mt-1">Total Duration</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-center">
                <div className="text-xl font-bold text-slate-200">{metrics.steps_completed || 0}/{metrics.steps_total || 0}</div>
                <div className="text-xs text-slate-400 mt-1">Steps Completed</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-center">
                <div className="text-xl font-bold text-slate-200">{metrics.mean_step_time || '—'}</div>
                <div className="text-xs text-slate-400 mt-1">Mean Step Time</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-center">
                <div className="text-xl font-bold text-slate-200">{metrics.bottleneck_step || '—'}</div>
                <div className="text-xs text-slate-400 mt-1">Bottleneck ({metrics.bottleneck_time || '—'})</div>
              </div>
            </div>
          )}

          {/* Timeline */}
          {report.timeline && report.timeline.length > 0 && (
            <div className="print-section mb-8">
              <h3 className="text-lg font-semibold mb-3">Key Events</h3>
              <div className="flex flex-col gap-2">
                {report.timeline.map((ev, i) => (
                  <div key={i} className="flex items-start gap-3 text-sm">
                    <span className="text-xs text-slate-500 whitespace-nowrap w-20">{parseApiDate(ev.timestamp).toLocaleTimeString()}</span>
                    <span className="text-slate-300">{ev.description}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Step Details */}
          {report.steps && report.steps.length > 0 && (
            <div className="print-section mb-8">
              <h3 className="text-lg font-semibold mb-3">Step Details</h3>
              <div className="flex flex-col gap-2">
                {report.steps.map((step) => {
                  const expanded = expandedSteps.has(step.node_id);
                  return (
                    <div key={step.node_id} className="rounded-lg border border-slate-800 bg-slate-900/40">
                      <button
                        className="w-full flex items-center gap-3 p-3 text-left text-sm"
                        onClick={() => setExpandedSteps((prev) => {
                          const next = new Set(prev);
                          expanded ? next.delete(step.node_id) : next.add(step.node_id);
                          return next;
                        })}
                      >
                        <span className="text-xs">{expanded ? '▼' : '▶'}</span>
                        <span className="flex-1 font-medium text-slate-100">{step.node_label}</span>
                        <span className="text-xs capitalize" style={{ color: step.status === 'completed' ? '#22c55e' : step.status === 'skipped' ? '#eab308' : '#6b7280' }}>
                          {step.status.replace('_', ' ')}
                        </span>
                        {step.assignee && <span className="text-xs text-slate-400">{step.assignee}</span>}
                        {step.duration && <span className="text-xs text-slate-500">{step.duration}</span>}
                      </button>
                      {expanded && (
                        <div className="px-3 pb-3 ml-7 text-xs text-slate-300 space-y-2">
                          {step.notes && step.notes.length > 0 && (
                            <div>
                              <div className="text-slate-500 mb-1">Notes:</div>
                              {step.notes.map((n, i) => <div key={i} className="text-slate-300">• {n}</div>)}
                            </div>
                          )}
                          {step.evidence && step.evidence.length > 0 && (
                            <div>
                              <div className="text-slate-500 mb-1">Evidence:</div>
                              {step.evidence.map((ev, i) => <div key={i} className="text-slate-300">📎 {ev.filename} ({(ev.size / 1024).toFixed(1)}KB)</div>)}
                            </div>
                          )}
                          {(!step.notes || step.notes.length === 0) && (!step.evidence || step.evidence.length === 0) && (
                            <div className="text-slate-500">No additional details.</div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default ReportPage;
