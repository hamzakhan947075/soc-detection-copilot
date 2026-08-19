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
    <p>Analyzes the normalized dataset for suspicious authentication, host, network, web, and firewall behaviors using a fixed, deterministic catalog of behaviors.</p>
    <div class="select-row">
      <button class="primary" id="runDetectBtn">${hasDeterministicDetections() ? 'Re-run Analysis' : 'Run Detection Analysis'}</button>
      ${
        state.aiEnabled
          ? `<button id="suggestAiBtn">✨ Suggest AI Detections</button>`
          : `<span class="muted">✨ AI-suggested detections need AI configured (Settings tab) - there's no deterministic fallback for this one, since it depends on the model looking at your actual data.</span>`
      }
    </div>
    <p class="muted">AI-suggested detections look at a real sample of your normalized data for patterns the fixed catalog above wouldn't catch - but every proposed condition is re-checked against the real dataset before it's shown, and a condition that doesn't actually match anything is dropped rather than shown as a detection. They're always clearly labeled and never replace the deterministic results above.</p>
    <div id="detectionResults" class="section-gap"></div>
  `;

  container.querySelector('#runDetectBtn').addEventListener('click', async () => {
    setStatus('Running detection engineering analysis…');
    try {
      const result = await api.detect(state.sessionId);
      state.detections = [...result.detections, ...(state.detections || []).filter((d) => d.source === 'ai')];
      setStatus(`Found ${result.detections.length} detection candidate(s).`);
      render(container);
    } catch (err) {
      setStatus(err.message, true);
      const resultsEl = container.querySelector('#detectionResults');
      if (resultsEl) resultsEl.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    }
  });

  const suggestAiBtn = container.querySelector('#suggestAiBtn');
  if (suggestAiBtn) {
    suggestAiBtn.addEventListener('click', async () => {
      setStatus('Asking AI to suggest detections from the real normalized data…');
      suggestAiBtn.disabled = true;
      try {
        const result = await api.suggestAiDetections(state.sessionId);
        state.detections = [...(state.detections || []).filter((d) => d.source !== 'ai'), ...result.detections];
        const note =
          result.acceptedCount > 0
            ? `AI suggested ${result.rawSuggestedCount} pattern(s); ${result.acceptedCount} verified against your real data and kept.`
            : `AI proposed ${result.rawSuggestedCount} pattern(s), but none held up against the real data - nothing added.`;
        setStatus(note);
        render(container);
      } catch (err) {
        setStatus(err.message, true);
        const resultsEl = container.querySelector('#detectionResults');
        if (resultsEl) resultsEl.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
        suggestAiBtn.disabled = false;
      }
    });
  }

  if (state.detections) renderResults(container);
}

function hasDeterministicDetections() {
  return Array.isArray(state.detections) && state.detections.some((d) => d.source !== 'ai');
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
        <div>${d.source === 'ai' ? '<span class="badge ai-suggested">✨ AI-suggested</span> ' : ''}${severityBadge(d.severity)}</div>
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
