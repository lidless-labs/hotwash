import React, { useEffect, useMemo, useState } from 'react';
import FlowCanvas from '../components/FlowCanvas';
import { getSharedPlaybook } from '../api/client';
import { PlaybookGraph } from '../types';

interface SharedPageProps {
  token?: string;
}

const emptyGraph: PlaybookGraph = { nodes: [], edges: [] };

const SharedPage: React.FC<SharedPageProps> = ({ token }) => {
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [title, setTitle] = useState('Shared Playbook');
  const [category, setCategory] = useState('Custom');
  const [description, setDescription] = useState('');
  const [graph, setGraph] = useState<PlaybookGraph>(emptyGraph);

  useEffect(() => {
    let active = true;
    const load = async () => {
      if (!token) {
        setNotFound(true);
        setLoading(false);
        return;
      }

      setLoading(true);
      setNotFound(false);
      try {
        const data = await getSharedPlaybook(token);
        if (!active) return;
        setTitle(data.title || 'Shared Playbook');
        setCategory(formatCategoryLabel(data.category));
        setDescription(data.description || '');
        setGraph(data.graph_json || emptyGraph);
      } catch {
        if (!active) return;
        setNotFound(true);
      } finally {
        if (active) setLoading(false);
      }
    };

    load();
    return () => {
      active = false;
    };
  }, [token]);

  const phaseNodes = useMemo(() => graph.nodes.filter((node) => node.type === 'phase'), [graph]);

  if (loading) {
    return <div className="min-h-screen bg-[#0d1117] text-slate-300 p-10">Loading shared playbook...</div>;
  }

  if (notFound) {
    return (
      <div className="min-h-screen bg-[#0d1117] text-slate-100 flex items-center justify-center p-6">
        <div className="max-w-md w-full rounded-xl border border-slate-700 bg-slate-900/80 p-8 text-center">
          <h1 className="text-2xl font-semibold">Playbook not found</h1>
          <p className="text-sm text-slate-400 mt-2">This share link is invalid or has been revoked.</p>
          <a href="#/" className="inline-block mt-5 text-blue-400 hover:text-blue-300 text-sm">Return to Playbook Forge</a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0d1117] text-slate-100" data-print-page="shared-playbook">
      <div className="max-w-7xl mx-auto px-6 py-8">
        <header className="mb-6 print-header">
          <h1 className="text-3xl font-semibold">{title}</h1>
          <p className="mt-1 text-sm text-slate-400">{category}</p>
          {description && <p className="mt-3 text-sm text-slate-300">{description}</p>}
          <div className="mt-2 text-xs text-slate-500 print-meta">{new Date().toLocaleDateString()}</div>
        </header>

        <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
          <section className="rounded-lg border border-slate-800 bg-slate-900/50 min-h-[560px] print-flow-section">
            <FlowCanvas graph={graph} readOnly />
          </section>

          <aside className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 print-steps-section">
            <h2 className="text-lg font-semibold">Step Breakdown</h2>
            <div className="mt-4 space-y-4">
              {phaseNodes.length === 0 ? (
                <p className="text-sm text-slate-400">No phases found.</p>
              ) : phaseNodes.map((phase) => {
                const phaseId = phase.id;
                const phaseSteps = graph.edges
                  .filter((edge) => edge.source === phaseId)
                  .map((edge) => graph.nodes.find((node) => node.id === edge.target))
                  .filter(Boolean);

                return (
                  <div key={phase.id} className="phase-block border border-slate-800 rounded p-3">
                    <h3 className="text-sm font-semibold text-slate-200">{phase.label}</h3>
                    <ul className="mt-2 text-xs text-slate-300 space-y-1 list-disc pl-4">
                      {phaseSteps.length === 0 ? (
                        <li>No direct steps</li>
                      ) : phaseSteps.map((step) => <li key={step!.id}>{step!.label}</li>)}
                    </ul>
                  </div>
                );
              })}
            </div>
          </aside>
        </div>

        <footer className="mt-8 text-xs text-slate-500">
          Built with <a href="#/" className="text-blue-400 hover:text-blue-300">Playbook Forge</a>
        </footer>
      </div>
    </div>
  );
};

function formatCategoryLabel(category?: string): string {
  if (!category) return 'Custom';
  return category
    .replace(/_/g, ' ')
    .replace(/-/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export default SharedPage;
