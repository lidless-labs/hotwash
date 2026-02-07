/**
 * GuidedTour — Interactive onboarding tour using driver.js (CDN)
 *
 * Auto-starts on first visit. Uses localStorage to track completion.
 * Can be retriggered via the "Take Tour" button exposed by variant layouts.
 * Relies on `data-tour` attributes placed on key UI elements.
 */

import { useCallback, useEffect, useRef } from 'react';

/** localStorage key to track tour completion */
const TOUR_STORAGE_KEY = 'playbook-forge-tour-complete';

/** driver.js types (loaded via CDN) */
interface DriverStep {
  element?: string;
  popover: {
    title: string;
    description: string;
    side?: 'top' | 'bottom' | 'left' | 'right';
    align?: 'start' | 'center' | 'end';
  };
}

interface DriverInstance {
  drive: () => void;
  destroy: () => void;
}

interface DriverConfig {
  showProgress: boolean;
  showButtons: string[];
  steps: DriverStep[];
  onDestroyed?: () => void;
}

interface DriverStatic {
  driver: (config: DriverConfig) => DriverInstance;
}

/** Get driver.js from window (loaded via CDN) */
function getDriverJs(): DriverStatic | null {
  const win = window as unknown as Record<string, unknown>;
  if (win.driver && typeof win.driver === 'object') {
    return win.driver as unknown as DriverStatic;
  }
  return null;
}

/** Tour step definitions */
const TOUR_STEPS: DriverStep[] = [
  {
    element: '[data-tour="library"]',
    popover: {
      title: '📚 Playbook Library',
      description:
        'Browse your collection of incident response playbooks. Filter by category — vulnerability remediation, threat hunting, compliance, and more.',
      side: 'right',
      align: 'start',
    },
  },
  {
    element: '[data-tour="import"]',
    popover: {
      title: '📝 Import / Create',
      description:
        'Paste or upload a Markdown playbook to instantly parse it into an interactive flowchart. Supports both Markdown and Mermaid syntax.',
      side: 'right',
      align: 'start',
    },
  },
  {
    element: '[data-tour="flow-canvas"]',
    popover: {
      title: '🗺️ Flowchart Canvas',
      description:
        'Your playbook visualized as an interactive flowchart. Drag to pan, scroll to zoom, and click nodes to explore each step.',
      side: 'top',
      align: 'center',
    },
  },
  {
    element: '[data-tour="decision-node"]',
    popover: {
      title: '🔀 Decision Nodes',
      description:
        'Diamond-shaped decision points represent branching logic — where the IR workflow splits based on conditions like severity or threat type.',
      side: 'bottom',
      align: 'center',
    },
  },
  {
    element: '[data-tour="step-details"]',
    popover: {
      title: '📋 Step Details',
      description:
        'Each step node contains detailed instructions, commands, and context for that phase of the incident response workflow.',
      side: 'left',
      align: 'center',
    },
  },
  {
    element: '[data-tour="dashboard"]',
    popover: {
      title: '📊 Dashboard',
      description:
        'View aggregate statistics — total playbooks, node counts, category coverage, and more. Your IR readiness at a glance.',
      side: 'right',
      align: 'start',
    },
  },
  {
    element: '[data-tour="variant-back"]',
    popover: {
      title: '🎨 Variant Picker',
      description:
        'Playbook Forge ships with 5 unique UI themes — from military field manuals to SOC dashboards to academic papers. Try them all!',
      side: 'right',
      align: 'end',
    },
  },
];

interface GuidedTourProps {
  /** When true, start the tour regardless of localStorage state */
  forceStart?: boolean;
  /** Callback when tour completes or is dismissed */
  onComplete?: () => void;
}

/**
 * GuidedTour component — renders nothing visible.
 * Manages the driver.js tour lifecycle.
 */
const GuidedTour: React.FC<GuidedTourProps> = ({ forceStart = false, onComplete }) => {
  const driverRef = useRef<DriverInstance | null>(null);
  const hasStarted = useRef(false);

  const markComplete = useCallback(() => {
    localStorage.setItem(TOUR_STORAGE_KEY, 'true');
    onComplete?.();
  }, [onComplete]);

  useEffect(() => {
    // Only start once per mount
    if (hasStarted.current) return;

    const isCompleted = localStorage.getItem(TOUR_STORAGE_KEY) === 'true';
    if (!forceStart && isCompleted) return;

    // Wait for driver.js CDN to load and DOM to settle
    const timeout = setTimeout(() => {
      const driverJs = getDriverJs();
      if (!driverJs) return;

      // Filter steps to only those with matching DOM elements
      const availableSteps = TOUR_STEPS.filter((step) => {
        if (!step.element) return true;
        return document.querySelector(step.element) !== null;
      });

      if (availableSteps.length === 0) return;

      hasStarted.current = true;

      const instance = driverJs.driver({
        showProgress: true,
        showButtons: ['next', 'previous', 'close'],
        steps: availableSteps,
        onDestroyed: markComplete,
      });

      driverRef.current = instance;
      instance.drive();
    }, 1200); // Give the page time to render

    return () => {
      clearTimeout(timeout);
      driverRef.current?.destroy();
    };
  }, [forceStart, markComplete]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      driverRef.current?.destroy();
    };
  }, []);

  return null;
};

export default GuidedTour;

/**
 * Utility: check if the tour has been completed
 */
export function isTourComplete(): boolean {
  return localStorage.getItem(TOUR_STORAGE_KEY) === 'true';
}

/**
 * Utility: reset tour completion state
 */
export function resetTour(): void {
  localStorage.removeItem(TOUR_STORAGE_KEY);
}
