import { state } from '../state.js';
import { escapeHtml } from '../utils.js';

export const id = 'investigation';
export const label = 'Investigation';

export async function render(container) {
  const rule = state.rules.find((r) => r.ruleId === state.selectedRuleId) || state.rules[state.rules.length - 1];

  if (!rule) {
    container.innerHTML = `<div class="card"><h1>Investigation</h1><p class="muted">Generate a rule to see its investigation checklist.</p></div>`;
    return;
  }

  container.innerHTML = `
    <h1>Investigation Workflow</h1>
    <div class="card">
      <h3>${escapeHtml(rule.ruleName)}</h3>
      <ol>${rule.investigationSteps.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ol>
    </div>
    <div class="card">
      <h3>Response Recommendation</h3>
      <p>${escapeHtml(rule.responseRecommendation)}</p>
    </div>
  `;
}
