/**
 * Variant 2: Dark SOC Operator / Mission Control
 *
 * Dense, data-first dashboard design with status indicators,
 * split-pane editing, terminal-style import, and SOC aesthetic.
 */

import React from 'react';
import { RouteMatch } from '../../router';
import V2Layout from './V2Layout';
import Dashboard from './pages/Dashboard';
import Library from './pages/Library';
import PlaybookViewer from './pages/PlaybookViewer';
import Import from './pages/Import';

interface V2AppProps {
  route: RouteMatch;
  onNavigate: (path: string) => void;
}

const V2App: React.FC<V2AppProps> = ({ route, onNavigate }) => {
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
      default:
        return <Dashboard />;
    }
  };

  return (
    <V2Layout
      activePage={route.page}
      onNavigate={onNavigate}
    >
      {renderPage()}
    </V2Layout>
  );
};

export default V2App;
