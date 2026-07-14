/**
 * MarkdownRenderer Component
 *
 * Lightweight markdown-to-JSX renderer with zero external dependencies.
 * Handles: headers, lists, code blocks, bold, italic, links, blockquotes.
 */

import React from 'react';
import './MarkdownRenderer.css';
import { safeHref } from './urlSafety';

interface MarkdownRendererProps {
  content: string;
  className?: string;
}

/**
 * Convert a markdown string to an array of React elements.
 * This is a simple, single-pass renderer — not a full AST parser.
 */
function renderMarkdown(content: string): React.ReactNode[] {
  const lines = content.split('\n');
  const elements: React.ReactNode[] = [];
  let i = 0;
  let key = 0;

  const nextKey = () => `md-${key++}`;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // Empty line
    if (!trimmed) {
      i++;
      continue;
    }

    // Code block
    if (trimmed.startsWith('```')) {
      const lang = trimmed.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing ```
      elements.push(
        <pre key={nextKey()}>
          {lang && <span className="code-lang">{lang}</span>}
          <code>{codeLines.join('\n')}</code>
        </pre>
      );
      continue;
    }

    // Blockquote
    if (trimmed.startsWith('>')) {
      const quoteLines: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ''));
        i++;
      }
      elements.push(
        <blockquote key={nextKey()}>
          {quoteLines.map((ql, idx) => (
            <p key={idx}>{renderInline(ql)}</p>
          ))}
        </blockquote>
      );
      continue;
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
      elements.push(<hr key={nextKey()} />);
      i++;
      continue;
    }

    // Headers
    const headerMatch = trimmed.match(/^(#{1,6})\s+(.+)$/);
    if (headerMatch) {
      const level = headerMatch[1].length;
      const text = headerMatch[2];
      const Tag = `h${level}` as keyof JSX.IntrinsicElements;
      elements.push(
        <Tag key={nextKey()}>{renderInline(text)}</Tag>
      );
      i++;
      continue;
    }

    // Unordered list
    if (/^[-*]\s/.test(trimmed)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && /^\s*[-*]\s/.test(lines[i])) {
        items.push(
          <li key={nextKey()}>
            {renderInline(lines[i].replace(/^\s*[-*]\s/, ''))}
          </li>
        );
        i++;
      }
      elements.push(<ul key={nextKey()}>{items}</ul>);
      continue;
    }

    // Ordered list
    if (/^\d+\.\s/.test(trimmed)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && /^\s*\d+\.\s/.test(lines[i])) {
        items.push(
          <li key={nextKey()}>
            {renderInline(lines[i].replace(/^\s*\d+\.\s/, ''))}
          </li>
        );
        i++;
      }
      elements.push(<ol key={nextKey()}>{items}</ol>);
      continue;
    }

    // Table
    if (trimmed.includes('|') && i + 1 < lines.length && /^\|?\s*[-:]+/.test(lines[i + 1].trim())) {
      const headerCells = parsePipeRow(trimmed);
      i++; // skip separator row
      i++;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].trim().includes('|')) {
        rows.push(parsePipeRow(lines[i].trim()));
        i++;
      }
      elements.push(
        <table key={nextKey()}>
          <thead>
            <tr>
              {headerCells.map((cell, ci) => (
                <th key={ci}>{renderInline(cell)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, ri) => (
              <tr key={ri}>
                {row.map((cell, ci) => (
                  <td key={ci}>{renderInline(cell)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      );
      continue;
    }

    // Paragraph (default)
    elements.push(
      <p key={nextKey()}>{renderInline(trimmed)}</p>
    );
    i++;
  }

  return elements;
}

/**
 * Parse a pipe-delimited table row into cells.
 */
function parsePipeRow(line: string): string[] {
  return line
    .replace(/^\||\|$/g, '')
    .split('|')
    .map((c) => c.trim());
}

// Above this per-line length, skip inline markdown parsing and render the raw
// text (still React-escaped). The inline matcher re-scans the remaining string
// on every iteration, which is quadratic on a single very long crafted line;
// this cap keeps an adversarial playbook from freezing the tab.
const INLINE_MAX_LEN = 10000;

/**
 * Render inline markdown (bold, italic, code, links) to React nodes.
 */
function renderInline(text: string): React.ReactNode {
  if (!text) return null;
  if (text.length > INLINE_MAX_LEN) return text;

  // Pattern order matters: code first (to avoid matching inside code), then links, bold, italic
  const parts: React.ReactNode[] = [];
  let remaining = text;
  let inlineKey = 0;

  while (remaining.length > 0) {
    // Inline code
    let match = remaining.match(/^(.*?)`([^`]+)`(.*)$/s);
    if (match) {
      if (match[1]) parts.push(renderInlineSimple(match[1], inlineKey++));
      parts.push(<code key={`ic-${inlineKey++}`}>{match[2]}</code>);
      remaining = match[3];
      continue;
    }

    // Link: [text](url)
    match = remaining.match(/^(.*?)\[([^\]]+)\]\(([^)]+)\)(.*)$/s);
    if (match) {
      if (match[1]) parts.push(renderInlineSimple(match[1], inlineKey++));
      parts.push(
        <a key={`a-${inlineKey++}`} href={safeHref(match[3])} target="_blank" rel="noopener noreferrer">
          {match[2]}
        </a>
      );
      remaining = match[4];
      continue;
    }

    // Bold: **text**
    match = remaining.match(/^(.*?)\*\*([^*]+)\*\*(.*)$/s);
    if (match) {
      if (match[1]) parts.push(renderInlineSimple(match[1], inlineKey++));
      parts.push(<strong key={`b-${inlineKey++}`}>{match[2]}</strong>);
      remaining = match[3];
      continue;
    }

    // Italic: *text* (single asterisk not preceded by another)
    match = remaining.match(/^(.*?)\*([^*]+)\*(.*)$/s);
    if (match) {
      if (match[1]) parts.push(renderInlineSimple(match[1], inlineKey++));
      parts.push(<em key={`i-${inlineKey++}`}>{match[2]}</em>);
      remaining = match[3];
      continue;
    }

    // No more inline patterns — output rest as text
    parts.push(<React.Fragment key={`t-${inlineKey++}`}>{remaining}</React.Fragment>);
    break;
  }

  return parts.length === 1 ? parts[0] : <>{parts}</>;
}

/**
 * Render simple text that may still have bold/italic but we treat as plain to avoid infinite loops.
 */
function renderInlineSimple(text: string, _key: number): React.ReactNode {
  return <React.Fragment key={`ts-${_key}`}>{text}</React.Fragment>;
}

const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({
  content,
  className,
}) => {
  const rendered = renderMarkdown(content);

  return (
    <div className={`md-renderer ${className ?? ''}`}>
      {rendered}
    </div>
  );
};

export default MarkdownRenderer;
