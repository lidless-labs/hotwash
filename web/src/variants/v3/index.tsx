/**
 * Variant 3: Clean Documentation / Knowledge Base
 *
 * GitBook/Notion-inspired: left sidebar with expandable categories,
 * breadcrumb navigation, tabbed playbook viewer, clean white content area.
 * Literata serif for reading, Inter for UI. Content is king.
 */

import React, { useMemo } from 'react';
import { RouteMatch } from '../../router';
import { usePlaybooks } from '../../hooks/usePlaybooks';
import V3Layout from './V3Layout';
import Dashboard from './pages/Dashboard';
import Library from './pages/Library';
import PlaybookViewer from './pages/PlaybookViewer';
import Import from './pages/Import';
import DocsPage from '../../pages/DocsPage';

interface V3AppProps {
  route: RouteMatch;
  onNavigate: (path: string) => void;
}

const V3App: React.FC<V3AppProps> = ({ route, onNavigate }) => {
  const { playbooks } = usePlaybooks();

  // Build playbook nav items for sidebar
  const playbookNavItems = useMemo(
    () =>
      playbooks.map((pb) => ({
        id: `pb-${pb.slug}`,
        icon: '📄',
        label: pb.metadata.title,
        page: 'playbook',
        slug: pb.slug,
      })),
    [playbooks]
  );

  // Build breadcrumbs based on current route
  const breadcrumbs = useMemo(() => {
    switch (route.page) {
      case 'dashboard':
      case 'home':
        return [{ label: 'Overview' }];
      case 'library':
        return [{ label: 'Library' }];
      case 'import':
        return [{ label: 'Import' }];
      case 'docs':
        return [{ label: 'Documentation' }];
      case 'playbook': {
        const pb = playbooks.find((p) => p.slug === route.params.slug);
        return [
          { label: 'Library', path: '#/3/library' },
          { label: pb?.metadata.title || route.params.slug || 'Playbook' },
        ];
      }
      default:
        return [];
    }
  }, [route, playbooks]);

  // Determine if content area should be wide
  const isWide = route.page === 'dashboard';

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
    <V3Layout
      activePage={route.page}
      activeSlug={route.params.slug}
      onNavigate={onNavigate}
      playbookNavItems={playbookNavItems}
      breadcrumbs={breadcrumbs}
      wide={isWide}
    >
      {renderPage()}
    </V3Layout>
  );
};

export default V3App;
