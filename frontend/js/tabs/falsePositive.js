import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml } from '../utils.js';

export const id = 'falsepositive';
export const label = 'False Positive Analysis';

export async function render(container) {
  const rule = state.rules.find((r) => r.ruleId === state.selectedRuleId);

  if (!rule || !state.lastFpAnalysis) {
    container.innerHTML = `<div class="card"><h1>False Positive Analysis</h1><p class="muted">Test a rule first from the Rule Testing tab.</p></div>`;
    return;
  }

  const fp = state.lastFpAnalysis;

  container.innerHTML = `
    <h1>False Positive Analysis</h1>
    <p class="muted">${escapeHtml(fp.note)}</p>

    <div class="grid grid-3">
      <div class="stat-card"><div class="stat-value">${fp.likelyTruePositiveCount}</div><div class="stat-label">Likely True Positives</div></div>
      <div class="stat-card"><div class="stat-value">${fp.potentialFalsePositiveCount}</div><div class="stat-label">Potential False Positives</div></div>
      <div class="stat-card"><div class="stat-value badge ${fp.riskLevel === 'low' ? 'low' : fp.riskLevel === 'medium' ? 'medium' : 'critical'}" style="font-size:20px">${escapeHtml(fp.falsePositiveRatePercent)}%</div><div class="stat-label">False Positive Rate (${escapeHtml(fp.riskLevel)} risk)</div></div>
    </div>

    <div class="card section-gap">
      <div class="detection-head">
        <h3 style="margin:0">Why These May Occur</h3>
        <button id="explainFpBtn">${state.aiEnabled ? '✨ Explain with AI' : '✨ Explain (deterministic)'}</button>
      </div>
      <ul>${rule.falsePositiveScenarios.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul>
      <div id="fpAiExplanation" class="muted"></div>
    </div>

    <div class="card">
      <h3>Recommended Exclusions</h3>
      <div class="warn-box">Exclusions are recommendations only. Nothing is applied automatically - an analyst must review and approve each exclusion before deployment.</div>
      <ul class="section-gap">${rule.recommendedExclusions.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul>
    </div>
  `;

  container.querySelector('#explainFpBtn').addEventListener('click', async () => {
    const box = container.querySelector('#fpAiExplanation');
    box.textContent = 'Thinking…';
    try {
      const explanation = await api.explainFalsePositives(state.sessionId, rule.ruleId);
      const label = explanation.source === 'ai' ? '✨ AI' : 'Deterministic summary';
      box.innerHTML = `<strong>${escapeHtml(label)}:</strong> ${escapeHtml(explanation.text)}`;
    } catch (err) {
      box.textContent = '';
      setStatus(err.message, true);
    }
  });
}
