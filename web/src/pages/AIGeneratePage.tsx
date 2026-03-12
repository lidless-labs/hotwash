import React from 'react';
import { useHashRouter } from '../router';
import AISettingsPanel from '../components/AISettingsPanel';

const AIGeneratePage: React.FC = () => {
  const { navigate } = useHashRouter();

  return (
    <div className="min-h-screen bg-[#0d1117] text-slate-100">
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-semibold flex items-center gap-3">
              <span className="text-2xl">✨</span> AI Playbook Generator
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              This workflow is not live yet. The backend AI and ATT&amp;CK endpoints are still being built.
            </p>
          </div>
          <button
            className="px-4 py-2 rounded-md border border-slate-700 bg-slate-800 text-sm text-slate-200 hover:bg-slate-700"
            onClick={() => navigate('#/library')}
          >
            Back to Library
          </button>
        </div>

        <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-8 mb-6">
          <div className="flex items-start gap-4">
            <div className="text-4xl">🚧</div>
            <div>
              <h2 className="text-xl font-semibold text-amber-100">Coming soon</h2>
              <p className="text-sm text-amber-50/80 mt-2 max-w-2xl">
                AI-assisted generation, ATT&amp;CK technique picking, and provider configuration are currently placeholders in the UI.
                To avoid broken requests, this page is intentionally read-only until the backend endpoints are implemented.
              </p>
              <ul className="mt-4 space-y-2 text-sm text-amber-50/80 list-disc list-inside">
                <li>Use the editor to build playbooks manually today.</li>
                <li>Use parse and import/export endpoints for current automation workflows.</li>
                <li>Return here once the AI generation service ships.</li>
              </ul>
            </div>
          </div>
        </div>

        <AISettingsPanel readOnly />
      </div>
    </div>
  );
};

export default AIGeneratePage;
