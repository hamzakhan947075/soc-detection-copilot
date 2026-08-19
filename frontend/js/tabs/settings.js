import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml } from '../utils.js';

export const id = 'settings';
export const label = 'Settings';

export async function render(container) {
  const [ai, providers, es] = await Promise.all([api.getAiStatus(), api.getAiProviders(), api.esStatus()]);

  container.innerHTML = `
    <h1>Settings</h1>

    <div class="card">
      <h3>AI Assist</h3>
      <p class="muted">AI is used only for optional narrative text (detection explanations, ECS mapping guidance,
      false-positive analysis) shown alongside the deterministic results in the Detection Engineering, ECS Mapping,
      and False Positive Analysis tabs. Every deterministic calculation (parsing, ECS confidence, detection
      thresholds, MITRE mapping, rule syntax validation, statistics) works identically with or without this
      configured.</p>

      <div id="aiStatusBox" class="section-gap"></div>

      <div class="select-row section-gap">
        <div>
          <label>Provider</label>
          <select id="aiProviderSelect">
            ${providers.providers.map((p) => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.label)}</option>`).join('')}
          </select>
        </div>
        <div>
          <label>API Key</label>
          <input type="password" id="aiKeyInput" placeholder="Paste your API key" autocomplete="off" />
        </div>
        <div>
          <label>Model <span class="muted">(optional - default shown as placeholder)</span></label>
          <input type="text" id="aiModelInput" placeholder="" />
        </div>
        <div id="aiBaseUrlRow" style="display:none; flex:2">
          <label>Base URL <span class="muted">(required for Custom)</span></label>
          <input type="text" id="aiBaseUrlInput" placeholder="https://your-provider.example.com/v1" />
        </div>
      </div>

      <div class="select-row">
        <button class="primary" id="aiSaveBtn">Save</button>
        <button id="aiTestBtn">Test Connection</button>
        <button id="aiClearBtn">Clear</button>
      </div>
      <p class="muted section-gap">Keys entered here are held in this server process's memory only for the
      current session - never written to a file, never logged, and cleared on restart. To persist a key across
      restarts, set it as an environment variable instead (see <code>backend/.env.example</code>): <code>ANTHROPIC_API_KEY</code>,
      <code>GROQ_API_KEY</code>, <code>OPENAI_API_KEY</code>, or <code>AI_API_KEY</code> + <code>AI_BASE_URL</code> for a
      custom OpenAI-compatible endpoint.</p>
      <div id="aiTestResult"></div>
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

  renderAiStatus(container, ai);
  wireEvents(container, providers.providers);
}

function renderAiStatus(container, ai) {
  const box = container.querySelector('#aiStatusBox');
  if (!ai.enabled) {
    box.innerHTML = '<span class="badge neutral">disabled</span> <span class="muted">No provider configured yet.</span>';
    return;
  }
  const sourceLabel = ai.source === 'session' ? 'entered in this Settings tab' : 'from environment variables';
  box.innerHTML = `
    <span class="badge low">enabled</span>
    <strong>${escapeHtml(ai.providerLabel)}</strong>
    &middot; model <code>${escapeHtml(ai.model)}</code>
    &middot; key <code>${escapeHtml(ai.maskedApiKey)}</code>
    <span class="muted">(${escapeHtml(sourceLabel)})</span>
  `;
  state.aiEnabled = true;
  const topbarBadge = document.getElementById('aiStatus');
  if (topbarBadge) {
    topbarBadge.textContent = `AI: enabled (${ai.providerLabel})`;
    topbarBadge.className = 'ai-status on';
  }
}

function wireEvents(container, providers) {
  const providerSelect = container.querySelector('#aiProviderSelect');
  const modelInput = container.querySelector('#aiModelInput');
  const baseUrlRow = container.querySelector('#aiBaseUrlRow');

  function syncForProvider() {
    const meta = providers.find((p) => p.id === providerSelect.value);
    modelInput.placeholder = meta ? meta.defaultModel || 'model name' : '';
    baseUrlRow.style.display = meta && meta.requiresBaseUrl ? '' : 'none';
  }
  providerSelect.addEventListener('change', syncForProvider);
  syncForProvider();

  container.querySelector('#aiSaveBtn').addEventListener('click', async () => {
    const provider = providerSelect.value;
    const apiKey = container.querySelector('#aiKeyInput').value.trim();
    const model = modelInput.value.trim();
    const baseUrl = container.querySelector('#aiBaseUrlInput').value.trim();

    if (!apiKey) {
      setStatus('Enter an API key before saving.', true);
      return;
    }
    setStatus('Saving AI configuration…');
    try {
      const ai = await api.setAiConfig({ provider, apiKey, model: model || undefined, baseUrl: baseUrl || undefined });
      renderAiStatus(container, ai);
      container.querySelector('#aiKeyInput').value = '';
      setStatus('AI configuration saved for this session.');
    } catch (err) {
      setStatus(err.message, true);
    }
  });

  container.querySelector('#aiTestBtn').addEventListener('click', async () => {
    const resultEl = container.querySelector('#aiTestResult');
    resultEl.innerHTML = '<p class="muted">Testing…</p>';
    try {
      const result = await api.testAiConfig();
      resultEl.innerHTML = result.success ? `<div class="ok-box">Provider responded successfully: "${escapeHtml(result.reply)}"</div>` : '';
    } catch (err) {
      const codeNote = err.code ? ` <span class="muted">(${escapeHtml(err.code)}${err.retryable ? ', transient - may succeed if you try again' : ''})</span>` : '';
      resultEl.innerHTML = `<div class="error-box">${escapeHtml(err.message)}${codeNote}</div>`;
    }
  });

  container.querySelector('#aiClearBtn').addEventListener('click', async () => {
    setStatus('Clearing AI configuration…');
    try {
      const ai = await api.clearAiConfig();
      renderAiStatus(container, ai);
      container.querySelector('#aiTestResult').innerHTML = '';
      setStatus(ai.enabled ? 'Session key cleared; falling back to environment configuration.' : 'AI configuration cleared.');
      if (!ai.enabled) {
        const topbarBadge = document.getElementById('aiStatus');
        if (topbarBadge) {
          topbarBadge.textContent = 'AI: disabled (deterministic mode)';
          topbarBadge.className = 'ai-status off';
        }
      }
    } catch (err) {
      setStatus(err.message, true);
    }
  });
}
