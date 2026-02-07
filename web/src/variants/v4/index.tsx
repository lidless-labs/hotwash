/**
 * Variant 4: Interactive Blueprint / Engineering Schematic
 *
 * Deep blueprint blue backgrounds, white/cyan line work, engineering grid overlay,
 * drawing border with tick marks, title block in bottom-right.
 * Flowchart is the centerpiece. IBM Plex Mono for everything, Oswald for headers.
 */

import React, { useMemo } from 'react';
import { RouteMatch } from '../../router';
import { usePlaybooks } from '../../hooks/usePlaybooks';
import { usePlaybook } from '../../hooks/usePlaybook';
import V4Layout from './V4Layout';
import Dashboard from './pages/Dashboard';
import Library from './pages/Library';
import PlaybookViewer from './pages/PlaybookViewer';
import Import from './pages/Import';
import DocsPage from '../../pages/DocsPage';

interface V4AppProps {
  route: RouteMatch;
  onNavigate: (path: string) => void;
}

const V4App: React.FC<V4AppProps> = ({ route, onNavigate }) => {
  const { playbooks } = usePlaybooks();
  const { playbook } = usePlaybook(route.params.slug);

  // Build title block data based on current page
  const titleBlockData = useMemo(() => {
    if (route.page === 'playbook' && playbook) {
      return {
        title: playbook.metadata.title,
        type: playbook.metadata.type,
        tooling: playbook.metadata.tooling,
        nodes: playbook.graph.nodes.length,
        edges: playbook.graph.edges.length,
      };
    }

    // Aggregate stats for non-playbook views
    const totalNodes = playbooks.reduce((s, p) => s + p.graph.nodes.length, 0);
    const totalEdges = playbooks.reduce((s, p) => s + p.graph.edges.length, 0);

    return {
      title: 'Playbook Forge',
      type: 'Interactive Blueprint',
      nodes: totalNodes,
      edges: totalEdges,
    };
  }, [route.page, playbook, playbooks]);

  // Render the active page
  const renderPage = () => {
    switch (route.page) {
      case 'dashboard':
      case 'home':
        return <Dashboard />;
      case 'library':
        return <Library onNavigate={onNavigate} />;
      case 'playbook':
        return (
          <PlaybookViewer
            slug={route.params.slug}
            onNavigate={onNavigate}
          />
        );
      case 'import':
        return <Import />;
      case 'docs':
        return <DocsPage />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <V4Layout
      activePage={route.page}
      activeSlug={route.params.slug}
      onNavigate={onNavigate}
      titleBlockData={titleBlockData}
    >
      {renderPage()}
    </V4Layout>
  );
};

export default V4App;
