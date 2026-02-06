/**
 * V2 Theme — Dark SOC Operator / Mission Control
 *
 * Deep navy base, electric cyan accents, status indicators,
 * JetBrains Mono for data, Barlow Condensed for headers.
 */

import { PlaybookTheme } from '../../types';

export const v2Theme: PlaybookTheme = {
  name: 'dark-soc-operator',
  colors: {
    background: '#0B1426',   // Deep navy
    surface: '#162035',       // Charcoal panel
    border: '#1E3050',        // Subtle divider
    text: '#E2E8F0',          // Primary text white
    textSecondary: '#64748B', // Dim text
    accent: '#06B6D4',        // Electric cyan
    accentHover: '#22D3EE',   // Bright cyan hover
  },
  fonts: {
    body: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
    heading: "'Barlow Condensed', 'Oswald', 'Arial Narrow', sans-serif",
    mono: "'JetBrains Mono', 'Fira Code', monospace",
  },
  nodeColors: {
    phase: { border: '#06B6D4', bg: '#0B1E33', badge: '#22D3EE' },
    step: { border: '#22C55E', bg: '#0B2618', badge: '#4ADE80' },
    decision: { border: '#F59E0B', bg: '#2A1E08', badge: '#FBBF24' },
    execute: { border: '#EF4444', bg: '#2A0E0E', badge: '#F87171' },
  },
  edgeColor: '#06B6D4',
};

/** V2 color constants for direct use in CSS-in-JS */
export const V2_COLORS = {
  deepNavy: '#0B1426',
  charcoalPanel: '#162035',
  borderSubtle: '#1E3050',
  statusGreen: '#22C55E',
  warningAmber: '#F59E0B',
  criticalRed: '#EF4444',
  electricCyan: '#06B6D4',
  brightCyan: '#22D3EE',
  textWhite: '#E2E8F0',
  textDim: '#64748B',
  surfaceHover: '#1C2A45',
  cardShadow: 'rgba(0, 0, 0, 0.4)',
} as const;

/** Status bar config */
export const STATUS_BAR_TEXT = 'PLAYBOOK FORGE • SOC OPERATIONS CENTER';
