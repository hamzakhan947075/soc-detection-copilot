import { api } from '../api.js';
import { state, setStatus, setSessionLabel } from '../state.js';
import { escapeHtml } from '../utils.js';
import { controller } from '../controller.js';

export const id = 'ingestion';
export const label = 'Log Ingestion';

const ALLOWED_EXT = ['.json', '.jsonl', '.ndjson', '.txt', '.log', '.csv'];

export async function render(container) {
  const { samples } = await api.getSamples();
  const esStatus = await api.esStatus().catch(() => ({ configured: false }));

  container.innerHTML = `
    <h1>Log Ingestion</h1>
    <p>Upload a raw Elastic export, paste events directly, load a bundled sample dataset, or (if configured) fetch
    directly from Elasticsearch. Logs are not assumed to already be ECS-compliant.</p>

    <div class="two-col">
      <div class="card">
        <h3>Upload File</h3>
        <div class="dropzone" id="dropzone">
          Drop a .json / .jsonl / .ndjson / .txt / .log / .csv file here, or click to browse
          <input type="file" id="fileInput" accept="${ALLOWED_EXT.join(',')}" style="display:none" />
        </div>
      </div>

      <div class="card">
        <h3>Paste Raw Events</h3>
        <div class="field-row">
          <textarea id="pasteArea" placeholder='{"@timestamp":"...","message":"Failed password for invalid user admin from 192.168.1.10"}'></textarea>
        </div>
        <button class="primary" id="pasteSubmit">Ingest Pasted Text</button>
      </div>
    </div>

    <div class="card">
      <h3>Sample Dataset Mode</h3>
      <p class="muted">Run the full pipeline without Elastic access.</p>
      <div class="sample-list">
        ${samples
          .map((s) => `<div class="sample-chip" data-name="${escapeHtml(s.name)}"><strong>${escapeHtml(s.name)}</strong><br><span class="muted">${escapeHtml(s.description)}</span></div>`)
          .join('')}
      </div>
    </div>

    <div class="card">
      <h3>Elasticsearch (Optional)</h3>
      ${
        esStatus.configured
          ? `<div class="select-row">
               <button id="esTestBtn">Test Connection</button>
               <div style="flex:2">
                 <label>Index</label>
                 <input type="text" id="esIndex" placeholder="logs-*" />
               </div>
               <button class="primary" id="esFetchBtn">Fetch Logs</button>
             </div>
             <div id="esResult"></div>`
          : `<p class="muted">Not configured. Set ELASTICSEARCH_URL and credentials via environment variables to enable direct fetch. The application is fully usable without this.</p>`
      }
    </div>

    <div id="ingestResult"></div>
  `;

  wireEvents(container);
}

function wireEvents(container) {
  const dropzone = container.querySelector('#dropzone');
  const fileInput = container.querySelector('#fileInput');

  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag');
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) handleFile(fileInput.files[0]);
  });

  container.querySelector('#pasteSubmit').addEventListener('click', async () => {
    const text = container.querySelector('#pasteArea').value;
    if (!text.trim()) {
      setStatus('Paste some log content first.', true);
      return;
    }
    await ingest(() => api.pasteText(text, 'pasted-events.txt'));
  });

  container.querySelectorAll('.sample-chip').forEach((chip) => {
    chip.addEventListener('click', async () => {
      await ingest(() => api.loadSample(chip.dataset.name));
    });
  });

  const esTestBtn = container.querySelector('#esTestBtn');
  if (esTestBtn) {
    esTestBtn.addEventListener('click', async () => {
      const resultEl = container.querySelector('#esResult');
      resultEl.innerHTML = '<p class="muted">Testing connection…</p>';
      try {
        const result = await api.esTestConnection();
        resultEl.innerHTML = `<div class="ok-box">Connected to cluster "${escapeHtml(result.clusterName)}" (v${escapeHtml(result.version)})</div>`;
      } catch (err) {
        resultEl.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
      }
    });
  }
  const esFetchBtn = container.querySelector('#esFetchBtn');
  if (esFetchBtn) {
    esFetchBtn.addEventListener('click', async () => {
      const index = container.querySelector('#esIndex').value;
      await ingest(() => api.esFetch({ index, size: 1000 }));
    });
  }
}

async function handleFile(file) {
  const resultEl = document.getElementById('ingestResult');
  if (!file.size) {
    showIngestError(resultEl, `"${file.name}" is empty (0 bytes) - nothing to ingest.`);
    return;
  }
  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    showIngestError(resultEl, `File type "${ext}" is not allowed. Allowed: ${ALLOWED_EXT.join(', ')}`);
    return;
  }
  await ingest(() => api.uploadFile(file));
}

function showIngestError(resultEl, message) {
  setStatus(message, true);
  if (resultEl) resultEl.innerHTML = `<div class="error-box section-gap">${escapeHtml(message)}</div>`;
}

async function ingest(fn) {
  const resultEl = document.getElementById('ingestResult');
  setStatus('Ingesting…');
  if (resultEl) resultEl.innerHTML = `<p class="muted section-gap">Ingesting…</p>`;
  try {
    const result = await fn();
    state.sessionId = result.sessionId;
    state.logSource = result.logSource;
    state.fieldDiscovery = result.fieldDiscovery;
    state.mappings = null;
    state.normalizeResult = null;
    state.detections = null;
    state.rules = [];
    state.lastTestResult = null;
    state.lastFpAnalysis = null;
    state.lastTuning = null;

    setSessionLabel(`Session ${result.sessionId.slice(0, 8)} - ${result.totalParsed} events (${result.format})`);
    const message = `Ingested ${result.totalParsed} events. Detected source: ${result.logSource.source} (${result.logSource.confidence}%).`;
    setStatus(message);
    if (resultEl) resultEl.innerHTML = `<div class="ok-box section-gap">${escapeHtml(message)}</div>`;
    controller.goTo('fields');
  } catch (err) {
    showIngestError(resultEl, err.message);
  }
}
