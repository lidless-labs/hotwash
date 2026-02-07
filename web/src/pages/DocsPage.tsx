/**
 * DocsPage — In-App Help & Documentation
 *
 * Comprehensive documentation covering playbook formats, node types,
 * flowchart navigation, IR methodology, and FAQ.
 * Styled to inherit the active variant's theme.
 */

import React from 'react';
import './DocsPage.css';

const DocsPage: React.FC = () => {
  return (
    <div className="docs-page">
      <h1>Documentation</h1>
      <p className="docs-subtitle">
        Everything you need to know about building, importing, and visualizing incident response playbooks.
      </p>

      {/* Table of Contents */}
      <div className="docs-toc">
        <div className="docs-toc-title">Contents</div>
        <ol>
          <li><a href="#docs-overview">Overview</a></li>
          <li><a href="#docs-formats">Playbook Formats</a></li>
          <li><a href="#docs-building">Building Playbooks</a></li>
          <li><a href="#docs-flowchart">Flowchart Navigation</a></li>
          <li><a href="#docs-nodes">Node Types Explained</a></li>
          <li><a href="#docs-ir">IR Methodology</a></li>
          <li><a href="#docs-faq">FAQ</a></li>
        </ol>
      </div>

      {/* 1. Overview */}
      <section id="docs-overview" className="docs-section">
        <h2>1. Overview</h2>
        <p>
          Playbook Forge transforms textual incident response playbooks — written in Markdown
          or Mermaid syntax — into interactive visual flowcharts. It provides SOC analysts,
          incident responders, and security teams with an intuitive way to create, browse,
          and navigate procedural workflows.
        </p>
        <p>
          The application ships with <strong>5 unique UI variants</strong>, each offering a
          distinct visual theme and layout. Every variant includes a Dashboard, Library,
          Import page, and Playbook Viewer with a full interactive flowchart canvas.
        </p>
        <h3>Key Capabilities</h3>
        <ul>
          <li>Parse structured Markdown into node-edge flowcharts</li>
          <li>Import Mermaid diagrams for direct visualization</li>
          <li>Browse and filter playbooks by category</li>
          <li>Interactive canvas with drag, pan, zoom, and minimap</li>
          <li>Custom node types with variant-specific theming</li>
          <li>Client-side parsing for instant, zero-latency feedback</li>
        </ul>
      </section>

      {/* 2. Playbook Formats */}
      <section id="docs-formats" className="docs-section">
        <h2>2. Playbook Formats</h2>

        <h3>Markdown Format</h3>
        <p>
          Playbooks are structured Markdown documents where heading levels map to flowchart
          node types. The parser uses heading prefixes to determine the node type:
        </p>
        <table className="docs-table">
          <thead>
            <tr>
              <th>Markdown Pattern</th>
              <th>Node Type</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code className="docs-inline-code"># Title</code></td>
              <td>—</td>
              <td>Playbook title (metadata, not a node)</td>
            </tr>
            <tr>
              <td><code className="docs-inline-code">## Phase N: ...</code></td>
              <td>Phase</td>
              <td>Major IR phase grouping</td>
            </tr>
            <tr>
              <td><code className="docs-inline-code">### Step N.N: ...</code></td>
              <td>Step</td>
              <td>Individual action step</td>
            </tr>
            <tr>
              <td><code className="docs-inline-code">### Decision: ...</code></td>
              <td>Decision</td>
              <td>Branching point with conditions</td>
            </tr>
            <tr>
              <td><code className="docs-inline-code">### Execute: ...</code></td>
              <td>Execute</td>
              <td>Automated or manual execution task</td>
            </tr>
          </tbody>
        </table>

        <h3>Example Markdown Playbook</h3>
        <code className="docs-code">{`# Vulnerability Remediation: Python

## Phase 1: Identification
### Step 1.1: Scan Dependencies
Run \`pip audit\` to identify known vulnerabilities.

### Step 1.2: Review CVE Database
Cross-reference findings with NVD/MITRE.

## Phase 2: Assessment
### Decision: Severity Check
- **Critical/High** → Immediate patching
- **Medium/Low** → Schedule for next sprint

## Phase 3: Remediation
### Execute: Apply Patches
Update affected packages and run regression tests.`}</code>

        <h3>Mermaid Format</h3>
        <p>
          Mermaid flowchart syntax is also supported. Nodes are defined with shape brackets
          that map to node types, and edges define the connections between them:
        </p>
        <code className="docs-code">{`graph TD
    A[Start: Alert Received] --> B{Severity?}
    B -->|Critical| C[Escalate to IR Team]
    B -->|Low| D[Log and Monitor]
    C --> E[Contain Threat]
    E --> F[Eradicate & Recover]
    F --> G[Post-Incident Review]
    D --> G`}</code>
        <p>
          In Mermaid syntax, curly braces <code className="docs-inline-code">{'{}'}</code> create
          diamond-shaped decision nodes, square brackets <code className="docs-inline-code">[]</code> create
          rectangular step nodes, and edge labels are specified
          with <code className="docs-inline-code">|label|</code>.
        </p>
      </section>

      {/* 3. Building Playbooks */}
      <section id="docs-building" className="docs-section">
        <h2>3. Building Playbooks</h2>
        <p>
          To create a new playbook, navigate to the <strong>Import</strong> page. You can either:
        </p>
        <ol>
          <li>
            <strong>Paste Markdown</strong> — Write or paste a structured Markdown document
            following the heading conventions above. The parser will instantly generate a flowchart.
          </li>
          <li>
            <strong>Paste Mermaid</strong> — Paste a Mermaid flowchart definition for direct
            graph visualization.
          </li>
        </ol>

        <h3>Best Practices</h3>
        <ul>
          <li>
            <strong>Start with phases.</strong> Use <code className="docs-inline-code">## Phase N: Name</code> to
            establish the major stages of your workflow.
          </li>
          <li>
            <strong>Break down into steps.</strong> Each phase should contain granular steps
            using <code className="docs-inline-code">### Step N.N: Name</code>.
          </li>
          <li>
            <strong>Mark decision points explicitly.</strong> Use <code className="docs-inline-code">### Decision: ...</code> to
            create branching logic in your flowchart.
          </li>
          <li>
            <strong>Use execution tasks for automation.</strong> Mark
            automated or manual execution steps
            with <code className="docs-inline-code">### Execute: ...</code>.
          </li>
          <li>
            <strong>Add detail in body text.</strong> Content below each heading becomes the
            node's descriptive metadata — include commands, references, and notes.
          </li>
        </ul>
      </section>

      {/* 4. Flowchart Navigation */}
      <section id="docs-flowchart" className="docs-section">
        <h2>4. Flowchart Navigation</h2>
        <p>
          The flowchart canvas is powered by React Flow and supports rich interactive controls:
        </p>
        <table className="docs-table">
          <thead>
            <tr>
              <th>Action</th>
              <th>How</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Pan the canvas</td>
              <td>Click and drag on empty space</td>
            </tr>
            <tr>
              <td>Zoom in/out</td>
              <td>Scroll wheel or pinch gesture</td>
            </tr>
            <tr>
              <td>Fit to view</td>
              <td>Click the fit-view button in the controls panel</td>
            </tr>
            <tr>
              <td>Move a node</td>
              <td>Click and drag any node</td>
            </tr>
            <tr>
              <td>Select a node</td>
              <td>Click on it to highlight</td>
            </tr>
            <tr>
              <td>Minimap navigation</td>
              <td>Click anywhere on the minimap to jump to that area</td>
            </tr>
            <tr>
              <td>Zoom controls</td>
              <td>Use the +/− buttons in the bottom-left control panel</td>
            </tr>
          </tbody>
        </table>
        <p>
          Edges between nodes are animated with directional arrows showing the flow
          of the incident response process. Edge labels indicate conditions at
          decision branch points.
        </p>
      </section>

      {/* 5. Node Types Explained */}
      <section id="docs-nodes" className="docs-section">
        <h2>5. Node Types Explained</h2>
        <p>
          Playbook Forge uses five distinct node types, each with a specific role
          in the IR workflow and unique visual styling per variant:
        </p>
        <div className="docs-node-grid">
          <div className="docs-node-card">
            <div className="docs-node-card-title">🔷 Phase</div>
            <div className="docs-node-card-desc">
              Major IR workflow stage. Groups related steps under a named phase
              (e.g., Identification, Containment, Eradication).
            </div>
          </div>
          <div className="docs-node-card">
            <div className="docs-node-card-title">🔹 Step</div>
            <div className="docs-node-card-desc">
              Individual action or task within a phase. Contains specific instructions,
              commands, or procedures to execute.
            </div>
          </div>
          <div className="docs-node-card">
            <div className="docs-node-card-title">🔀 Decision</div>
            <div className="docs-node-card-desc">
              Branching point where the workflow splits based on conditions — severity
              levels, yes/no checks, or classification criteria.
            </div>
          </div>
          <div className="docs-node-card">
            <div className="docs-node-card-title">⚡ Execute</div>
            <div className="docs-node-card-desc">
              Automated or manual execution task — running scripts, applying patches,
              deploying configurations, or triggering integrations.
            </div>
          </div>
          <div className="docs-node-card">
            <div className="docs-node-card-title">🔗 Merge</div>
            <div className="docs-node-card-desc">
              Convergence point where multiple branches reunite into a single flow.
              Typically follows decision branches.
            </div>
          </div>
        </div>
        <p>
          Each variant applies its own visual treatment — colors, shapes, borders, and
          typography — to these node types while maintaining consistent semantic meaning.
        </p>
      </section>

      {/* 6. IR Methodology */}
      <section id="docs-ir" className="docs-section">
        <h2>6. IR Methodology</h2>
        <p>
          Playbook Forge playbooks are designed around the NIST SP 800-61 incident response
          lifecycle, adapted for modern SOC workflows:
        </p>
        <ol>
          <li>
            <strong>Preparation</strong> — Establish IR policies, build playbooks, configure
            monitoring tools, and train the team before incidents occur.
          </li>
          <li>
            <strong>Detection &amp; Analysis</strong> — Identify potential security events through
            SIEM alerts, threat intelligence, and anomaly detection. Triage and classify.
          </li>
          <li>
            <strong>Containment</strong> — Limit the scope and impact of the incident. Short-term
            containment (isolate host) and long-term containment (patch, harden).
          </li>
          <li>
            <strong>Eradication</strong> — Remove the root cause — malware, unauthorized access,
            vulnerable software. Verify complete removal.
          </li>
          <li>
            <strong>Recovery</strong> — Restore affected systems to normal operation. Monitor
            closely for signs of persistence or reinfection.
          </li>
          <li>
            <strong>Post-Incident Activity</strong> — Lessons learned, documentation updates,
            playbook refinement, and metric reporting.
          </li>
        </ol>
        <p>
          Each playbook in the library maps its phases to one or more stages of this lifecycle.
          The flowchart visualization makes it easy to see how steps connect and where
          decision points branch the workflow.
        </p>
      </section>

      {/* 7. FAQ */}
      <section id="docs-faq" className="docs-section">
        <h2>7. FAQ</h2>

        <div className="docs-faq-item">
          <div className="docs-faq-q">Q: Do I need the backend running to use the app?</div>
          <div className="docs-faq-a">
            Not for most features. The frontend includes a client-side Markdown parser and
            ships with built-in template playbooks. The backend is needed for the Mermaid
            parser and API-based parsing.
          </div>
        </div>

        <div className="docs-faq-item">
          <div className="docs-faq-q">Q: What's the difference between the 5 variants?</div>
          <div className="docs-faq-a">
            Each variant provides a unique visual theme and layout — from a military field manual
            (V1) to a SOC dashboard (V2) to an academic paper (V5). The underlying data
            and functionality are identical; only the presentation differs.
          </div>
        </div>

        <div className="docs-faq-item">
          <div className="docs-faq-q">Q: Can I export my flowcharts?</div>
          <div className="docs-faq-a">
            Currently, flowcharts can be exported via browser screenshot or print. Variant 5
            (Minimal Academic) includes print-optimized CSS for clean paper output.
          </div>
        </div>

        <div className="docs-faq-item">
          <div className="docs-faq-q">Q: What Markdown syntax is required?</div>
          <div className="docs-faq-a">
            Standard Markdown with structured headings. Use <code className="docs-inline-code">##</code> for
            phases, <code className="docs-inline-code">###</code> for steps, and prefix with keywords
            like &quot;Decision:&quot; or &quot;Execute:&quot; to control node types. See the
            Playbook Formats section above for full details.
          </div>
        </div>

        <div className="docs-faq-item">
          <div className="docs-faq-q">Q: How do I add a new playbook to the library?</div>
          <div className="docs-faq-a">
            Navigate to the Import page and paste your Markdown content. The parser will
            generate a flowchart instantly. To add playbooks permanently, add them to
            the <code className="docs-inline-code">web/src/data/</code> directory following the
            existing template format.
          </div>
        </div>

        <div className="docs-faq-item">
          <div className="docs-faq-q">Q: Can I create custom node types?</div>
          <div className="docs-faq-a">
            The current parser supports Phase, Step, Decision, Execute, and Merge node types.
            Custom node types can be added by extending the parser in
            <code className="docs-inline-code">web/src/parsers/markdownParser.ts</code> and
            creating corresponding React components in the nodes directory.
          </div>
        </div>
      </section>
    </div>
  );
};

export default DocsPage;
