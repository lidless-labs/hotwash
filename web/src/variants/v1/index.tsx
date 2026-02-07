/**
 * Variant 1: Technical Manual / Field Guide
 *
 * Military field manual aesthetic with classification banners,
 * sidebar table of contents, section numbering, and typewriter typography.
 */

import React, { useMemo } from 'react';
import { RouteMatch } from '../../router';
import { usePlaybooks } from '../../hooks/usePlaybooks';
import V1Layout from './V1Layout';
import Dashboard from './pages/Dashboard';
import Library from './pages/Library';
import PlaybookViewer from './pages/PlaybookViewer';
import Import from './pages/Import';
import DocsPage from '../../pages/DocsPage';

interface V1AppProps {
  route: RouteMatch;
  onNavigate: (path: string) => void;
}

const V1App: React.FC<V1AppProps> = ({ route, onNavigate }) => {
  const { playbooks } = usePlaybooks();

  // Build extra nav items for playbooks (appendices)
  const playbookNavItems = useMemo(
    () =>
      playbooks.map((pb, idx) => ({
        id: `pb-${pb.slug}`,
        number: `A.${idx + 1}`,
        label: pb.metadata.title,
        page: 'playbook',
        slug: pb.slug,
      })),
    [playbooks]
  );

  // Determine the figure number for a playbook
  const figureNumber = useMemo(() => {
    if (route.page !== 'playbook' || !route.params.slug) return 1;
    const idx = playbooks.findIndex((p) => p.slug === route.params.slug);
    return idx >= 0 ? idx + 1 : 1;
  }, [route, playbooks]);

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
            figureNumber={figureNumber}
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
    <V1Layout
      activePage={route.page}
      activeSlug={route.params.slug}
      onNavigate={onNavigate}
      extraNavItems={playbookNavItems}
    >
      {renderPage()}
    </V1Layout>
  );
};

export default V1App;
