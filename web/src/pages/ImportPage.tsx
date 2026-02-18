import React, { useMemo, useRef, useState } from 'react';
import { bulkImportPlaybooks, importPlaybook, BulkImportResultItem } from '../api/client';
import { useHashRouter } from '../router';

type TabKey = 'json' | 'markdown';

interface JsonPreview {
  title: string;
  category: string;
  nodeCount: number;
  raw: Record<string, any>;
  fileName: string;
}

interface MarkdownFileItem {
  file: File;
  status: 'ready' | 'uploading' | 'success' | 'failed';
  message?: string;
}

const ImportPage: React.FC = () => {
  const { navigate } = useHashRouter();
  const [tab, setTab] = useState<TabKey>('json');
  const [dragging, setDragging] = useState(false);
  const [jsonPreview, setJsonPreview] = useState<JsonPreview | null>(null);
  const [jsonImporting, setJsonImporting] = useState(false);
  const [markdownFiles, setMarkdownFiles] = useState<MarkdownFileItem[]>([]);
  const [bulkImporting, setBulkImporting] = useState(false);
  const [progressText, setProgressText] = useState<string>('');
  const [results, setResults] = useState<BulkImportResultItem[]>([]);
  const [error, setError] = useState<string | null>(null);

  const jsonInputRef = useRef<HTMLInputElement>(null);
  const mdInputRef = useRef<HTMLInputElement>(null);

  const summary = useMemo(() => {
    const succeeded = results.filter((r) => r.success !== false).length;
    const failed = results.length - succeeded;
    return { succeeded, failed };
  }, [results]);

  const parseJsonFile = async (file: File) => {
    const text = await file.text();
    const raw = JSON.parse(text) as Record<string, any>;
    const graph = raw.graph_json || raw.graph || { nodes: [] };
    setJsonPreview({
      title: raw.title || 'Untitled Playbook',
      category: raw.category || 'custom',
      nodeCount: Array.isArray(graph.nodes) ? graph.nodes.length : 0,
      raw,
      fileName: file.name,
    });
  };

  const addMarkdownFiles = (files: File[]) => {
    const md = files.filter((f) => f.name.toLowerCase().endsWith('.md'));
    setMarkdownFiles(md.map((file) => ({ file, status: 'ready' })));
  };

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    setError(null);
    const files = Array.from(e.dataTransfer.files || []);
    if (!files.length) return;

    try {
      if (tab === 'json') {
        await parseJsonFile(files[0]);
      } else {
        addMarkdownFiles(files);
      }
    } catch {
      setError('Failed to parse dropped file(s).');
    }
  };

  const handleJsonImport = async () => {
    if (!jsonPreview) return;
    setJsonImporting(true);
    setError(null);
    setProgressText('Importing JSON playbook...');
    try {
      const created = await importPlaybook(jsonPreview.raw);
      navigate(`#/editor/${encodeURIComponent(created.id)}`);
    } catch {
      setError('JSON import failed. Please verify file format.');
    } finally {
      setJsonImporting(false);
      setProgressText('');
    }
  };

  const handleBulkImport = async () => {
    if (!markdownFiles.length) return;
    setBulkImporting(true);
    setError(null);
    setProgressText(`Importing ${markdownFiles.length} markdown file(s)...`);
    setMarkdownFiles((prev) => prev.map((f) => ({ ...f, status: 'uploading' })));

    try {
      const apiResults = await bulkImportPlaybooks(markdownFiles.map((item) => item.file));
      setResults(apiResults);
      setMarkdownFiles((prev) => prev.map((f) => {
        const match = apiResults.find((r) => r.filename === f.file.name || r.title === f.file.name);
        if (match?.success === false) {
          return { ...f, status: 'failed', message: match.error || 'Import failed' };
        }
        return { ...f, status: 'success' };
      }));
    } catch {
      setError('Bulk markdown import failed.');
      setMarkdownFiles((prev) => prev.map((f) => ({ ...f, status: 'failed', message: 'Import request failed' })));
    } finally {
      setBulkImporting(false);
      setProgressText('');
    }
  };

  const tabClass = (key: TabKey) => `px-4 py-2 rounded-md text-sm border ${tab === key
    ? 'bg-blue-600 border-blue-500 text-white'
    : 'bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800'
  }`;

  return (
    <div className="min-h-screen bg-[#0d1117] text-slate-100">
      <div className="max-w-5xl mx-auto px-6 py-10">
        <div className="flex flex-col gap-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h1 className="text-3xl font-semibold">Import Playbooks</h1>
              <p className="text-sm text-slate-400 mt-1">Upload JSON or bulk Markdown files.</p>
            </div>
            <button className="px-4 py-2 rounded-md border border-slate-700 bg-slate-800 text-sm" onClick={() => navigate('#/library')}>
              Back to Library
            </button>
          </div>

          <div className="flex gap-2">
            <button className={tabClass('json')} onClick={() => setTab('json')}>JSON Import</button>
            <button className={tabClass('markdown')} onClick={() => setTab('markdown')}>Markdown Import</button>
          </div>

          <div
            className={`rounded-xl border-2 border-dashed p-10 text-center cursor-pointer transition ${dragging
              ? 'border-blue-500 bg-blue-500/10'
              : 'border-slate-700 bg-slate-900/50 hover:border-slate-500'
            }`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => tab === 'json' ? jsonInputRef.current?.click() : mdInputRef.current?.click()}
          >
            <div className="text-4xl mb-3">⬆</div>
            <p className="text-slate-300">Drop files here or click to browse</p>
            <p className="text-xs text-slate-500 mt-2">{tab === 'json' ? 'Accepts .json' : 'Accepts one or more .md files'}</p>
          </div>

          <input
            ref={jsonInputRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              try {
                setError(null);
                await parseJsonFile(file);
              } catch {
                setError('Invalid JSON file.');
              }
            }}
          />

          <input
            ref={mdInputRef}
            type="file"
            accept=".md,text/markdown"
            multiple
            className="hidden"
            onChange={(e) => {
              const files = Array.from(e.target.files || []);
              addMarkdownFiles(files);
            }}
          />

          {progressText && (
            <div className="rounded-md border border-blue-500/40 bg-blue-500/10 px-4 py-2 text-sm text-blue-200">
              {progressText}
            </div>
          )}

          {error && (
            <div className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm text-red-200">
              {error}
            </div>
          )}

          {tab === 'json' && jsonPreview && (
            <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-5">
              <h2 className="text-lg font-semibold">Preview</h2>
              <div className="mt-3 grid gap-2 text-sm text-slate-300">
                <div><span className="text-slate-500">File:</span> {jsonPreview.fileName}</div>
                <div><span className="text-slate-500">Title:</span> {jsonPreview.title}</div>
                <div><span className="text-slate-500">Category:</span> {jsonPreview.category}</div>
                <div><span className="text-slate-500">Node count:</span> {jsonPreview.nodeCount}</div>
              </div>
              <button
                className="mt-4 px-4 py-2 rounded-md bg-blue-600 text-sm text-white hover:bg-blue-500 disabled:opacity-60"
                onClick={handleJsonImport}
                disabled={jsonImporting}
              >
                {jsonImporting ? 'Importing...' : 'Import'}
              </button>
            </div>
          )}

          {tab === 'markdown' && (
            <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-5">
              <h2 className="text-lg font-semibold">Markdown Files</h2>
              <div className="mt-3 space-y-2">
                {markdownFiles.length === 0 ? (
                  <p className="text-sm text-slate-500">No files selected.</p>
                ) : markdownFiles.map((item) => (
                  <div key={item.file.name} className="flex items-center justify-between rounded border border-slate-800 px-3 py-2 text-sm">
                    <span>{item.file.name}</span>
                    <span className="text-xs text-slate-400">
                      {item.status === 'ready' && 'Ready'}
                      {item.status === 'uploading' && 'Uploading...'}
                      {item.status === 'success' && 'Imported'}
                      {item.status === 'failed' && (item.message || 'Failed')}
                    </span>
                  </div>
                ))}
              </div>
              <button
                className="mt-4 px-4 py-2 rounded-md bg-blue-600 text-sm text-white hover:bg-blue-500 disabled:opacity-60"
                onClick={handleBulkImport}
                disabled={bulkImporting || markdownFiles.length === 0}
              >
                {bulkImporting ? 'Importing...' : 'Import All'}
              </button>
            </div>
          )}

          {results.length > 0 && (
            <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-5">
              <h2 className="text-lg font-semibold">Results Summary</h2>
              <p className="text-sm text-slate-300 mt-2">{summary.succeeded} succeeded, {summary.failed} failed.</p>
              <div className="mt-3 space-y-2 text-sm">
                {results.map((result, idx) => (
                  <div key={`${result.filename || result.title || idx}`} className="rounded border border-slate-800 px-3 py-2">
                    <div className="text-slate-200">{result.filename || result.title || `File ${idx + 1}`}</div>
                    <div className={`text-xs mt-1 ${result.success === false ? 'text-red-300' : 'text-emerald-300'}`}>
                      {result.success === false ? (result.error || 'Failed') : 'Imported'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ImportPage;
