import React from 'react';

interface AISettingsPanelProps {
  onClose?: () => void;
  readOnly?: boolean;
}

const AISettingsPanel: React.FC<AISettingsPanelProps> = ({ onClose, readOnly = false }) => {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-6">
      <div className="flex items-center justify-between mb-5">
        <h2 className="text-lg font-semibold text-slate-100">⚙️ AI Configuration</h2>
        {onClose && (
          <button className="text-slate-400 hover:text-slate-200 text-xl" onClick={onClose}>×</button>
        )}
      </div>

      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 mb-4">
        <p className="text-sm text-amber-100 font-medium">Not yet implemented</p>
        <p className="text-sm text-amber-50/80 mt-2">
          Provider setup, key storage, connection testing, and AI generation settings are disabled until the matching backend APIs are available.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-md bg-slate-950 border border-slate-700 px-4 py-3">
          <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Status</div>
          <div className="text-sm text-slate-200">Coming soon</div>
        </div>
        <div className="rounded-md bg-slate-950 border border-slate-700 px-4 py-3">
          <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Current recommendation</div>
          <div className="text-sm text-slate-200">Use manual playbook authoring for now.</div>
        </div>
      </div>

      <div className="mt-5 text-xs text-slate-500">
        {readOnly
          ? 'This panel is shown in read-only mode so the UI does not call nonexistent endpoints.'
          : 'This modal is intentionally informational only.'}
      </div>
    </div>
  );
};

export default AISettingsPanel;
