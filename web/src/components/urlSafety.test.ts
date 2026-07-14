import { describe, expect, it } from 'vitest';

import { safeHref } from './urlSafety';

describe('safeHref', () => {
  it('passes through http, https and mailto URLs', () => {
    expect(safeHref('https://example.com/x')).toBe('https://example.com/x');
    expect(safeHref('http://example.com')).toBe('http://example.com');
    expect(safeHref('HTTPS://Example.com')).toBe('HTTPS://Example.com');
    expect(safeHref('mailto:soc@example.com')).toBe('mailto:soc@example.com');
  });

  it('keeps relative and anchor URLs', () => {
    expect(safeHref('/playbooks/1')).toBe('/playbooks/1');
    expect(safeHref('#section')).toBe('#section');
    expect(safeHref('page.html')).toBe('page.html');
  });

  it('neutralizes javascript: and other executable schemes', () => {
    expect(safeHref('javascript:alert(1)')).toBe('#');
    expect(safeHref('JavaScript:alert(document.cookie)')).toBe('#');
    expect(safeHref('vbscript:msgbox(1)')).toBe('#');
    expect(safeHref('data:text/html,<script>alert(1)</script>')).toBe('#');
    expect(safeHref('file:///etc/passwd')).toBe('#');
  });

  it('neutralizes scheme-obfuscation via embedded tab/newline/CR', () => {
    expect(safeHref('java\tscript:alert(1)')).toBe('#');
    expect(safeHref('java\nscript:alert(1)')).toBe('#');
    expect(safeHref('  javascript:alert(1)  ')).toBe('#');
  });

  it('returns # for empty input', () => {
    expect(safeHref('')).toBe('#');
    expect(safeHref('   ')).toBe('#');
  });
});
