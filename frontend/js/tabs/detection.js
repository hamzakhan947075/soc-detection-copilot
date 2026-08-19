import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml, severityBadge, confidenceBar } from '../utils.js';
import { controller } from '../controller.js';

export const id = 'detection';
export const label = 'Detection Engineering';

export async function render(container) {
  if (!state.normalizeResult) {
    container.innerHTML = `<div class="card"><h1>Detection Engineering</h1><p class="muted">Complete ECS Mapping and normalization first.</p></div>`;
    return;
  }

  container.innerHTML = `
    <h1>Detection Engineering Analysis</h1>
    <p>Analyzes the normalized dataset for suspicious authentication, host, network, web, and firewall behaviors.</p>
    <button class="primary" id="runDetectBtn">${state.detections ? 'Re-run Analysis' : 'Run Detection Analysis'}</button>
    <div id="detectionResults" class="section-gap"></div>
  `;

  container.querySelector('#runDetectBtn').addEventListener('click', async () => {
    setStatus('Running detection engineering analysis…');
    try {
      const result = await api.detect(state.sessionId);
      state.detections = result.detections;
      setStatus(`Found ${result.detections.length} detection candidate(s).`);
      renderResults(container);
    } catch (err) {
      setStatus(err.message, true);
      const resultsEl = container.querySelector('#detectionResults');
      if (resultsEl) resultsEl.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    }
  });

  if (state.detections) renderResults(container);
}

function renderResults(container) {
  const target = container.querySelector('#detectionResults');
  if (!state.detections || state.detections.length === 0) {
    target.innerHTML = `<div class="card"><p class="muted">No suspicious behaviors identified in this dataset.</p></div>`;
    return;
  }

  target.innerHTML = state.detections
    .map(
      (d) => `
    <div class="detection-card">
      <div class="detection-head">
        <div>
          <div class="detection-title">${escapeHtml(d.name)}</div>
          <div class="detection-meta">${escapeHtml(d.category)} &middot; ${d.mitre.techniqueId ? `${escapeHtml(d.mitre.techniqueId)} - ${escapeHtml(d.mitre.techniqueName)}` : 'MITRE mapping uncertain'}</div>
        </div>
        <div>${severityBadge(d.severity)}</div>
      </div>
      <p class="muted">${escapeHtml(d.description)}</p>
      <p>Confidence: ${confidenceBar(d.confidence)}</p>
      <p class="muted">Required fields: ${d.requiredFields.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')}</p>
      ${d.recommendedThreshold ? `<p class="muted">Recommended threshold: &ge; ${d.recommendedThreshold.count} events${d.recommendedThreshold.windowMinutes ? ` within ${d.recommendedThreshold.windowMinutes} minutes` : ''}</p>` : ''}
      <ul class="evidence-list">${d.evidence.slice(0, 5).map((e) => `<li>${escapeHtml(e)}</li>`).join('')}</ul>
      <div class="select-row">
        <button class="generate-rule-btn" data-id="${escapeHtml(d.id)}">Generate Detection Rule &rarr;</button>
        <button class="explain-ai-btn" data-id="${escapeHtml(d.id)}">${state.aiEnabled ? '✨ Explain with AI' : '✨ Explain (deterministic)'}</button>
      </div>
      <div class="ai-explanation muted" data-explain-for="${escapeHtml(d.id)}"></div>
    </div>`
    )
    .join('');

  target.querySelectorAll('.generate-rule-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.selectedDetectionId = btn.dataset.id;
      controller.goTo('rules');
    });
  });

  target.querySelectorAll('.explain-ai-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const box = target.querySelector(`.ai-explanation[data-explain-for="${btn.dataset.id}"]`);
      box.textContent = 'Thinking…';
      try {
        const explanation = await api.explainDetection(state.sessionId, btn.dataset.id);
        const label = explanation.source === 'ai' ? '✨ AI' : 'Deterministic summary';
        box.innerHTML = `<strong>${escapeHtml(label)}:</strong> ${escapeHtml(explanation.text)}`;
      } catch (err) {
        box.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
        setStatus(err.message, true);
      }
    });
  });
}
