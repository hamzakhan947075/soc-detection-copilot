import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml } from '../utils.js';
import { controller } from '../controller.js';

export const id = 'tuning';
export const label = 'Detection Tuning';

export async function render(container) {
  const rule = state.rules.find((r) => r.ruleId === state.selectedRuleId);

  if (!rule || !state.lastFpAnalysis) {
    container.innerHTML = `<div class="card"><h1>Detection Tuning</h1><p class="muted">Test a rule first from the Rule Testing tab.</p></div>`;
    return;
  }

  container.innerHTML = `
    <h1>Detection Tuning</h1>
    <button class="primary" id="tuneBtn">Get Tuning Recommendation</button>
    <div id="tuningOutput" class="section-gap"></div>
  `;

  container.querySelector('#tuneBtn').addEventListener('click', async () => {
    setStatus('Computing tuning recommendation…');
    try {
      const tuning = await api.tuneRule(state.sessionId, rule.ruleId);
      state.lastTuning = tuning;
      renderTuning(container, tuning);
      setStatus('Tuning recommendation ready.');
    } catch (err) {
      setStatus(err.message, true);
      const outputEl = container.querySelector('#tuningOutput');
      if (outputEl) outputEl.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    }
  });

  if (state.lastTuning) renderTuning(container, state.lastTuning);
}

function renderTuning(container, tuning) {
  const target = container.querySelector('#tuningOutput');

  if (!tuning.applicable) {
    target.innerHTML = `<div class="card"><p class="muted">${escapeHtml(tuning.reason)}</p></div>`;
    return;
  }

  target.innerHTML = `
    <div class="card">
      <div class="grid grid-2">
        <div class="stat-card"><div class="stat-value">${tuning.currentThreshold}</div><div class="stat-label">Current Threshold</div></div>
        <div class="stat-card"><div class="stat-value">${tuning.suggestedThreshold}</div><div class="stat-label">Suggested Threshold</div></div>
      </div>
      <p class="section-gap">${escapeHtml(tuning.reason)}</p>
      ${
        tuning.after
          ? `<div class="two-col section-gap">
              <div class="stat-card"><div class="stat-value">${tuning.before.eventsMatched}</div><div class="stat-label">Matches Before Tuning</div></div>
              <div class="stat-card"><div class="stat-value">${tuning.after.eventsMatched}</div><div class="stat-label">Matches After Tuning</div></div>
            </div>`
          : ''
      }
      <button class="primary section-gap" id="toReportBtn">Continue to Reports &rarr;</button>
    </div>`;

  target.querySelector('#toReportBtn').addEventListener('click', () => controller.goTo('reports'));
}
