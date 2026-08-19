import { api } from '../api.js';
import { escapeHtml } from '../utils.js';

export const id = 'settings';
export const label = 'Settings';

export async function render(container) {
  const [ai, es] = await Promise.all([api.getAiStatus(), api.esStatus()]);

  container.innerHTML = `
    <h1>Settings</h1>

    <div class="card">
      <h3>AI Assist</h3>
      <p>Status: ${ai.enabled ? '<span class="badge low">enabled</span>' : '<span class="badge neutral">disabled</span>'}</p>
      <p class="muted">Configure by setting <code>ANTHROPIC_API_KEY</code> as an environment variable on the backend. AI is
      used only for optional narrative explanations - every deterministic calculation (parsing, ECS confidence, detection
      thresholds, MITRE mapping, rule syntax validation, statistics) works identically with or without it.</p>
    </div>

    <div class="card">
      <h3>Elasticsearch Integration</h3>
      <p>Status: ${es.configured ? '<span class="badge low">configured</span>' : '<span class="badge neutral">not configured</span>'}</p>
      <p class="muted">Configure via environment variables on the backend: <code>ELASTICSEARCH_URL</code>,
      <code>ELASTICSEARCH_USERNAME</code> / <code>ELASTICSEARCH_PASSWORD</code> or <code>ELASTICSEARCH_API_KEY</code>,
      and <code>ELASTICSEARCH_INDEX</code>. No credentials are ever stored or transmitted by this frontend directly -
      the backend applies them server-side. The application is fully functional without Elasticsearch configured.</p>
    </div>

    <div class="card">
      <h3>Upload &amp; Security Limits</h3>
      <ul>
        <li>Allowed file types: .json, .jsonl, .ndjson, .txt, .log, .csv</li>
        <li>Uploaded files never execute - they are parsed as data only</li>
        <li>Requests are rate-limited per client</li>
        <li>All generated queries are syntax-validated before display; no query is ever executed against a live system by this tool</li>
      </ul>
    </div>
  `;
}
