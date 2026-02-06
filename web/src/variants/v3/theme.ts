/**
 * V3 Theme — Clean Documentation / Knowledge Base
 *
 * GitBook/Notion-inspired: white backgrounds, Literata serif for reading,
 * Inter for UI, subtle indigo accents. Content-first design.
 */

import { PlaybookTheme } from '../../types';

export const v3Theme: PlaybookTheme = {
  name: 'clean-documentation',
  colors: {
    background: '#FFFFFF',     // Pure white
    surface: '#F8FAFC',        // Light gray surface
    border: '#E2E8F0',         // Border gray
    text: '#1E293B',           // Dark text
    textSecondary: '#64748B',  // Secondary text
    accent: '#4F46E5',         // Indigo accent
    accentHover: '#4338CA',    // Indigo hover
  },
  fonts: {
    body: "'Literata', 'Georgia', 'Times New Roman', serif",
    heading: "'Inter', 'system-ui', '-apple-system', 'Segoe UI', sans-serif",
    mono: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
  },
  nodeColors: {
    phase: { border: '#4F46E5', bg: '#EEF2FF', badge: '#4F46E5' },
    step: { border: '#0891B2', bg: '#ECFEFF', badge: '#0891B2' },
    decision: { border: '#D97706', bg: '#FFFBEB', badge: '#D97706' },
    execute: { border: '#16A34A', bg: '#F0FDF4', badge: '#16A34A' },
  },
  edgeColor: '#94A3B8',
};

/** V3 color constants for direct use */
export const V3_COLORS = {
  white: '#FFFFFF',
  lightGray: '#F8FAFC',
  borderGray: '#E2E8F0',
  textDark: '#1E293B',
  textSecondary: '#64748B',
  textTertiary: '#94A3B8',
  accentIndigo: '#4F46E5',
  accentIndigoLight: '#EEF2FF',
  accentIndigoHover: '#4338CA',
  successGreen: '#16A34A',
  successGreenLight: '#F0FDF4',
  warningAmber: '#D97706',
  warningAmberLight: '#FFFBEB',
  infoCyan: '#0891B2',
  infoCyanLight: '#ECFEFF',
  codeBg: '#1E293B',
  codeText: '#E2E8F0',
  sidebarBg: '#F8FAFC',
  sidebarHover: '#F1F5F9',
  sidebarActive: '#EEF2FF',
} as const;
