import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml } from '../utils.js';
import { controller } from '../controller.js';

export const id = 'testing';
export const label = 'Rule Testing';

export async function render(container) {
  if (state.rules.length === 0) {
    container.innerHTML = `<div class="card"><h1>Rule Testing</h1><p class="muted">Generate a rule first from the Rule Builder tab.</p></div>`;
    return;
  }

  const selectedId = state.selectedRuleId || state.rules[state.rules.length - 1].ruleId;
  const rule = state.rules.find((r) => r.ruleId === selectedId);

  container.innerHTML = `
    <h1>Rule Testing</h1>
    <div class="select-row">
      <div style="flex:2">
        <label>Rule</label>
        <select id="ruleSelect">
          ${state.rules.map((r) => `<option value="${escapeHtml(r.ruleId)}" ${r.ruleId === selectedId ? 'selected' : ''}>${escapeHtml(r.ruleName)} (${escapeHtml(r.ruleType)})</option>`).join('')}
        </select>
      </div>
      <div><button class="primary" id="runTestBtn">Test Against Loaded Logs</button></div>
    </div>
    <div id="testOutput"></div>
  `;

  container.querySelector('#ruleSelect').addEventListener('change', (e) => {
    state.selectedRuleId = e.target.value;
    render(container);
  });

  container.querySelector('#runTestBtn').addEventListener('click', async () => {
    setStatus('Running rule against loaded dataset…');
    try {
      const { testResult, fpAnalysis } = await api.testRule(state.sessionId, state.selectedRuleId || selectedId);
      state.lastTestResult = testResult;
      state.lastFpAnalysis = fpAnalysis;
      renderResult(container, rule, testResult, fpAnalysis);
      setStatus(`Matched ${testResult.eventsMatched}/${testResult.eventsTested} events (${testResult.matchRatePercent}%).`);
    } catch (err) {
      setStatus(err.message, true);
    }
  });

  if (state.lastTestResult) renderResult(container, rule, state.lastTestResult, state.lastFpAnalysis);
}

function renderResult(container, rule, testResult, fpAnalysis) {
  const target = container.querySelector('#testOutput');
  target.innerHTML = `
    <div class="grid grid-4 section-gap">
      <div class="stat-card"><div class="stat-value">${testResult.eventsTested}</div><div class="stat-label">Events Tested</div></div>
      <div class="stat-card"><div class="stat-value">${testResult.eventsMatched}</div><div class="stat-label">Events Matched</div></div>
      <div class="stat-card"><div class="stat-value">${testResult.matchRatePercent}%</div><div class="stat-label">Match Rate</div></div>
      <div class="stat-card"><div class="stat-value">${fpAnalysis.likelyTruePositiveCount}</div><div class="stat-label">Potential True Positives</div></div>
    </div>

    ${
      testResult.groupingSummary
        ? `<div class="card section-gap">
            <h3>Threshold Grouping</h3>
            <div class="table-wrap"><table>
              <thead><tr><th>Group Value</th><th>Event Count</th><th>Passes Threshold</th></tr></thead>
              <tbody>${testResult.groupingSummary
                .map((g) => `<tr><td class="mono">${escapeHtml(g.groupValue)}</td><td>${g.eventCount}</td><td>${g.passesThreshold ? '<span class="badge low">yes</span>' : '<span class="badge neutral">no</span>'}</td></tr>`)
                .join('')}</tbody>
            </table></div>
          </div>`
        : ''
    }

    <div class="card section-gap">
      <h3>Matched Events (first ${Math.min(testResult.matchedEvents.length, 25)})</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>#</th><th>Matched Fields</th></tr></thead>
        <tbody>
          ${testResult.matchedEvents
            .slice(0, 25)
            .map(
              (m) => `<tr><td>${m.index}</td><td>${m.matchedFields.map((f) => `<code>${escapeHtml(f.field)}=${escapeHtml(JSON.stringify(f.value))}</code>`).join(' ')}</td></tr>`
            )
            .join('')}
        </tbody>
      </table></div>
    </div>

    <button class="primary" id="toFpBtn">Continue to False Positive Analysis &rarr;</button>
  `;

  target.querySelector('#toFpBtn').addEventListener('click', () => controller.goTo('falsepositive'));
}
