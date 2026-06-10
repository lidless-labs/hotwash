/**
 * IntegrationsPage — Dashboard + configuration for external tool integrations.
 */

import React, { useEffect, useState, useRef } from 'react';
import { useHashRouter } from '../router';
import { parseApiDate } from '../lib/time';

const API_BASE = 'http://localhost:8000/api';

interface IntegrationData {
  tool_name: string;
  display_name: string;
  base_url: string;
  enabled: boolean;
  verify_ssl: boolean;
  mock_mode: boolean;
  last_checked: string | null;
  last_status: string;
  has_api_key: boolean;
  has_credentials: boolean;
}

interface IntegrationForm {
  base_url: string;
  api_key: string;
  username: string;
  password: string;
  enabled: boolean;
  verify_ssl: boolean;
  mock_mode: boolean;
}

const TOOL_ICONS: Record<string, string> = {
  thehive: '🐝',
  cortex: '🧠',
  wazuh: '🛡️',
  misp: '🔗',
};

const STATUS_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  connected: { bg: 'rgba(34,197,94,0.15)', text: '#22c55e', label: 'Connected' },
  disconnected: { bg: 'rgba(239,68,68,0.15)', text: '#ef4444', label: 'Disconnected' },
  error: { bg: 'rgba(239,68,68,0.15)', text: '#ef4444', label: 'Error' },
  unchecked: { bg: 'rgba(107,114,128,0.15)', text: '#6b7280', label: 'Unchecked' },
  mock: { bg: 'rgba(59,130,246,0.15)', text: '#3b82f6', label: 'Mock Mode' },
};

function getStatusInfo(i: IntegrationData) {
  if (i.mock_mode && i.last_status === 'connected') return STATUS_COLORS.mock;
  if (i.mock_mode && i.last_status === 'unchecked') return STATUS_COLORS.mock;
  return STATUS_COLORS[i.last_status] || STATUS_COLORS.unchecked;
}

const IntegrationsPage: React.FC = () => {
  const { navigate } = useHashRouter();
  const [integrations, setIntegrations] = useState<IntegrationData[]>([]);
  const [forms, setForms] = useState<Record<string, IntegrationForm>>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [testResults, setTestResults] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<Record<string, boolean>>({});
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const configRefs = useRef<Record<string, HTMLDivElement | null>>({});

  const fetchIntegrations = async () => {
    try {
      const res = await fetch(`${API_BASE}/integrations`);
      const data: IntegrationData[] = await res.json();
      setIntegrations(data);
      const newForms: Record<string, IntegrationForm> = {};
      data.forEach((i) => {
        if (!forms[i.tool_name]) {
          newForms[i.tool_name] = {
            base_url: i.base_url,
            api_key: '',
            username: '',
            password: '',
            enabled: i.enabled,
            verify_ssl: i.verify_ssl,
            mock_mode: i.mock_mode,
          };
        }
      });
      if (Object.keys(newForms).length) {
        setForms((prev) => ({ ...newForms, ...prev }));
      }
    } catch (e) {
      console.error('Failed to fetch integrations', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const handleSave = async (tool: string) => {
    setSaving((p) => ({ ...p, [tool]: true }));
    try {
      const form = forms[tool];
      const body: any = {
        base_url: form.base_url,
        enabled: form.enabled,
        verify_ssl: form.verify_ssl,
        mock_mode: form.mock_mode,
      };
      if (form.api_key) body.api_key = form.api_key;
      if (form.username) body.username = form.username;
      if (form.password) body.password = form.password;

      await fetch(`${API_BASE}/integrations/${tool}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      await fetchIntegrations();
    } finally {
      setSaving((p) => ({ ...p, [tool]: false }));
    }
  };

  const handleTest = async (tool: string) => {
    setTesting((p) => ({ ...p, [tool]: true }));
    try {
      const res = await fetch(`${API_BASE}/integrations/${tool}/test`, { method: 'POST' });
      const data = await res.json();
      setTestResults((p) => ({ ...p, [tool]: data }));
      await fetchIntegrations();
    } catch (e: any) {
      setTestResults((p) => ({ ...p, [tool]: { error: e.message } }));
    } finally {
      setTesting((p) => ({ ...p, [tool]: false }));
    }
  };

  const updateForm = (tool: string, field: keyof IntegrationForm, value: any) => {
    setForms((prev) => ({
      ...prev,
      [tool]: { ...prev[tool], [field]: value },
    }));
  };

  const scrollToConfig = (tool: string) => {
    setExpanded((p) => ({ ...p, [tool]: true }));
    setTimeout(() => {
      configRefs.current[tool]?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 p-8 flex items-center justify-center">
        <p className="text-slate-400">Loading integrations…</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 max-w-6xl mx-auto">
      <div className="flex flex-col gap-6">
        {/* Header */}
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-3xl font-semibold">Integrations</h1>
            <p className="text-slate-400 text-sm mt-1">
              Configure and monitor connections to external security tools.
            </p>
          </div>
          <button
            className="px-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700"
            onClick={() => navigate('#/library')}
          >
            ← Library
          </button>
        </div>

        {/* Dashboard Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {integrations.map((i) => {
            const status = getStatusInfo(i);
            const testResult = testResults[i.tool_name]?.result;
            return (
              <div
                key={i.tool_name}
                className="rounded-lg border border-slate-800 bg-slate-900 p-5 flex flex-col gap-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-2xl">{TOOL_ICONS[i.tool_name] || '⚙️'}</span>
                    <span className="font-semibold text-lg">{i.display_name}</span>
                  </div>
                  <span
                    className="text-xs font-medium px-2 py-1 rounded-full"
                    style={{ backgroundColor: status.bg, color: status.text }}
                  >
                    {status.label}
                  </span>
                </div>

                {i.last_checked && (
                  <p className="text-xs text-slate-500">
                    Last checked: {parseApiDate(i.last_checked).toLocaleString()}
                  </p>
                )}

                {/* Mock stats */}
                {testResult?.stats && (
                  <div className="text-xs text-slate-400 space-y-0.5">
                    {Object.entries(testResult.stats).map(([k, v]) => (
                      <div key={k} className="flex justify-between">
                        <span>{k.replace(/_/g, ' ')}</span>
                        <span className="text-slate-200 font-medium">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                )}

                <button
                  className="mt-auto text-sm px-3 py-1.5 rounded bg-slate-800 border border-slate-700 hover:bg-slate-700 text-slate-300"
                  onClick={() => scrollToConfig(i.tool_name)}
                >
                  Configure
                </button>
              </div>
            );
          })}
        </div>

        {/* Configuration Forms */}
        <div className="flex flex-col gap-4 mt-4">
          <h2 className="text-xl font-semibold text-slate-300">Configuration</h2>
          {integrations.map((i) => {
            const form = forms[i.tool_name];
            if (!form) return null;
            const isExpanded = expanded[i.tool_name] ?? false;
            const isSaving = saving[i.tool_name] ?? false;
            const isTesting = testing[i.tool_name] ?? false;
            const testResult = testResults[i.tool_name];

            return (
              <div
                key={i.tool_name}
                ref={(el) => { configRefs.current[i.tool_name] = el; }}
                className="rounded-lg border border-slate-800 bg-slate-900 overflow-hidden"
              >
                <button
                  className="w-full flex items-center justify-between p-4 hover:bg-slate-800/50 transition-colors"
                  onClick={() => setExpanded((p) => ({ ...p, [i.tool_name]: !isExpanded }))}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xl">{TOOL_ICONS[i.tool_name] || '⚙️'}</span>
                    <span className="font-medium">{i.display_name}</span>
                    <span
                      className="text-xs px-2 py-0.5 rounded-full ml-2"
                      style={{
                        backgroundColor: getStatusInfo(i).bg,
                        color: getStatusInfo(i).text,
                      }}
                    >
                      {getStatusInfo(i).label}
                    </span>
                  </div>
                  <span className="text-slate-500">{isExpanded ? '▲' : '▼'}</span>
                </button>

                {isExpanded && (
                  <div className="p-4 pt-0 flex flex-col gap-3 border-t border-slate-800">
                    {/* Base URL */}
                    <label className="flex flex-col gap-1">
                      <span className="text-xs text-slate-400">Base URL</span>
                      <input
                        className="rounded bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="https://thehive.example.com"
                        value={form.base_url}
                        onChange={(e) => updateForm(i.tool_name, 'base_url', e.target.value)}
                      />
                    </label>

                    {/* API Key */}
                    <label className="flex flex-col gap-1">
                      <span className="text-xs text-slate-400">
                        API Key {i.has_api_key && <span className="text-green-500">(set)</span>}
                      </span>
                      <input
                        type="password"
                        className="rounded bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Enter API key…"
                        value={form.api_key}
                        onChange={(e) => updateForm(i.tool_name, 'api_key', e.target.value)}
                      />
                    </label>

                    {/* Wazuh-specific: Username + Password */}
                    {i.tool_name === 'wazuh' && (
                      <>
                        <label className="flex flex-col gap-1">
                          <span className="text-xs text-slate-400">
                            Username {i.has_credentials && <span className="text-green-500">(set)</span>}
                          </span>
                          <input
                            className="rounded bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="wazuh-api-user"
                            value={form.username}
                            onChange={(e) => updateForm(i.tool_name, 'username', e.target.value)}
                          />
                        </label>
                        <label className="flex flex-col gap-1">
                          <span className="text-xs text-slate-400">Password</span>
                          <input
                            type="password"
                            className="rounded bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="Enter password…"
                            value={form.password}
                            onChange={(e) => updateForm(i.tool_name, 'password', e.target.value)}
                          />
                        </label>
                      </>
                    )}

                    {/* Toggles */}
                    <div className="flex flex-wrap gap-4 mt-1">
                      <ToggleField
                        label="Enabled"
                        value={form.enabled}
                        onChange={(v) => updateForm(i.tool_name, 'enabled', v)}
                      />
                      <ToggleField
                        label="Verify SSL"
                        value={form.verify_ssl}
                        onChange={(v) => updateForm(i.tool_name, 'verify_ssl', v)}
                      />
                      <ToggleField
                        label="Mock Mode"
                        value={form.mock_mode}
                        onChange={(v) => updateForm(i.tool_name, 'mock_mode', v)}
                      />
                    </div>

                    {/* Test result */}
                    {testResult && (
                      <div className="mt-2 rounded bg-slate-950 border border-slate-700 p-3 text-xs">
                        <pre className="text-slate-300 whitespace-pre-wrap overflow-auto max-h-40">
                          {JSON.stringify(testResult, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex gap-3 mt-2">
                      <button
                        className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium disabled:opacity-50"
                        onClick={() => handleTest(i.tool_name)}
                        disabled={isTesting}
                      >
                        {isTesting ? 'Testing…' : 'Test Connection'}
                      </button>
                      <button
                        className="px-4 py-2 rounded bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm font-medium disabled:opacity-50"
                        onClick={() => handleSave(i.tool_name)}
                        disabled={isSaving}
                      >
                        {isSaving ? 'Saving…' : 'Save'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

/* Simple toggle component */
const ToggleField: React.FC<{ label: string; value: boolean; onChange: (v: boolean) => void }> = ({
  label,
  value,
  onChange,
}) => (
  <label className="flex items-center gap-2 cursor-pointer select-none">
    <div
      className="w-9 h-5 rounded-full relative transition-colors"
      style={{ backgroundColor: value ? '#3b82f6' : '#374151' }}
      onClick={() => onChange(!value)}
    >
      <div
        className="absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform"
        style={{ transform: value ? 'translateX(18px)' : 'translateX(2px)' }}
      />
    </div>
    <span className="text-xs text-slate-400">{label}</span>
  </label>
);

export default IntegrationsPage;
