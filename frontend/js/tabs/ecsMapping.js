import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml, confidenceBar, statusBadge } from '../utils.js';
import { controller } from '../controller.js';

export const id = 'ecs';
export const label = 'ECS Mapping';

const ECS_TYPES = ['keyword', 'date', 'long', 'ip', 'wildcard', 'match_only_text', 'boolean'];

export async function render(container) {
  if (!state.sessionId) {
    container.innerHTML = `<div class="card"><h1>ECS Mapping</h1><p class="muted">Ingest a dataset first.</p></div>`;
    return;
  }

  if (!state.mappings) {
    const suggested = await api.getSuggestedMappings(state.sessionId);
    state.mappings = mergeWithFieldList(suggested.mappings, state.fieldDiscovery.fields);
  }

  container.innerHTML = `
    <h1>ECS Mapping Engine</h1>

    <div class="flow-diagram">
      <div class="flow-step">Raw Elastic Event</div><span class="flow-arrow">&rarr;</span>
      <div class="flow-step">Field Discovery</div><span class="flow-arrow">&rarr;</span>
      <div class="flow-step">Normalization</div><span class="flow-arrow">&rarr;</span>
      <div class="flow-step">ECS Mapping</div><span class="flow-arrow">&rarr;</span>
      <div class="flow-step">Validation</div><span class="flow-arrow">&rarr;</span>
      <div class="flow-step">Normalized ECS Event</div>
    </div>

    <div class="card">
      <h3>Field &rarr; ECS Mapping (editable)</h3>
      <p class="muted">Review each suggested mapping. Fields below 75% confidence are marked <span class="badge uncertain">uncertain</span> and need analyst review before approval.</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Raw Field</th><th>ECS Field</th><th>ECS Type</th><th>Confidence</th><th>Status</th><th>AI Check</th></tr></thead>
          <tbody id="mappingBody">
            ${state.mappings.map((m, i) => mappingRow(m, i)).join('')}
          </tbody>
        </table>
      </div>
      <div class="section-gap">
        <button class="primary" id="approveBtn">Approve Mappings &amp; Normalize</button>
      </div>
    </div>

    <div id="normalizedPreview"></div>
  `;

  if (state.normalizeResult) {
    renderNormalizedPreview(container);
  }

  wireEvents(container);
}

function mergeWithFieldList(suggested, allFields) {
  const bySuggested = new Map(suggested.map((m) => [m.rawField, m]));
  return allFields.map((f) => {
    const s = bySuggested.get(f.field);
    return s
      ? s
      : { rawField: f.field, ecsField: null, ecsType: 'keyword', confidence: 0, status: 'unmapped' };
  });
}

function mappingRow(m, i) {
  const aiCell =
    m.status === 'excluded'
      ? '<span class="muted">-</span>'
      : `<button class="ai-check-btn" data-index="${i}">${state.aiEnabled ? '✨ Check with AI' : '✨ Check (deterministic)'}</button>`;
  return `<tr data-index="${i}">
    <td class="mono">${escapeHtml(m.rawField)}</td>
    <td><input type="text" class="mono ecs-field-input" data-index="${i}" value="${escapeHtml(m.ecsField || '')}" placeholder="e.g. source.ip" /></td>
    <td>
      <select class="ecs-type-select" data-index="${i}">
        ${ECS_TYPES.map((t) => `<option value="${t}" ${t === m.ecsType ? 'selected' : ''}>${t}</option>`).join('')}
      </select>
    </td>
    <td>${m.ecsField ? confidenceBar(m.confidence || 0) : '<span class="muted">-</span>'}</td>
    <td>${statusBadge(m.status)}</td>
    <td>${aiCell}</td>
  </tr>
  <tr class="ai-explain-row" data-explain-for="${i}" style="display:none"><td colspan="6"></td></tr>`;
}

function wireEvents(container) {
  container.querySelectorAll('.ecs-field-input').forEach((input) => {
    input.addEventListener('change', () => {
      const i = Number(input.dataset.index);
      state.mappings[i].ecsField = input.value.trim() || null;
      state.mappings[i].status = 'analyst-approved';
      renderRowBadge(container, i);
    });
  });
  container.querySelectorAll('.ecs-type-select').forEach((sel) => {
    sel.addEventListener('change', () => {
      const i = Number(sel.dataset.index);
      state.mappings[i].ecsType = sel.value;
    });
  });

  container.querySelectorAll('.ai-check-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const i = Number(btn.dataset.index);
      const m = state.mappings[i];
      const row = container.querySelector(`tr.ai-explain-row[data-explain-for="${i}"]`);
      const cell = row.querySelector('td');
      row.style.display = '';
      cell.className = 'muted';
      cell.textContent = 'Thinking…';
      try {
        const result = await api.explainMapping(state.sessionId, {
          rawField: m.rawField,
          ecsField: m.ecsField,
          ecsType: m.ecsType,
          confidence: m.confidence,
        });
        const label = result.source === 'ai' ? '✨ AI' : 'Deterministic summary';
        cell.innerHTML = `<strong>${escapeHtml(label)}:</strong> ${escapeHtml(result.text)}`;
      } catch (err) {
        cell.textContent = '';
        row.style.display = 'none';
        setStatus(err.message, true);
      }
    });
  });

  container.querySelector('#approveBtn').addEventListener('click', async () => {
    setStatus('Approving mappings and normalizing…');
    try {
      await api.putMappings(state.sessionId, state.mappings);
      const result = await api.normalize(state.sessionId);
      state.normalizeResult = result;
      setStatus(`Normalized ${state.fieldDiscovery.totalEvents} events - ${result.coveragePercent}% ECS field coverage.`);
      renderNormalizedPreview(container);
    } catch (err) {
      setStatus(err.message, true);
    }
  });
}

function renderRowBadge(container, i) {
  const cell = container.querySelector(`tr[data-index="${i}"] td:nth-child(5)`);
  if (cell) cell.innerHTML = statusBadge(state.mappings[i].status);
}

function renderNormalizedPreview(container) {
  const preview = container.querySelector('#normalizedPreview');
  const sample = state.normalizeResult.sample.slice(0, 3);

  preview.innerHTML = `
    <div class="card section-gap">
      <h3>Normalized Event Preview (ECS coverage: ${state.normalizeResult.coveragePercent}%)</h3>
      ${sample
        .map(
          (s) => `
        <div class="two-col section-gap">
          <div>
            <h3>Raw Event</h3>
            <pre>${escapeHtml(JSON.stringify(s.raw, null, 2))}</pre>
          </div>
          <div>
            <h3>Normalized ECS Event</h3>
            <pre>${escapeHtml(JSON.stringify(s.normalized, null, 2))}</pre>
          </div>
        </div>
        <p class="muted">${s.changes.length} field(s) mapped${s.unmapped.length ? `, ${s.unmapped.length} left unmapped` : ''}.</p>
      `
        )
        .join('<hr style="border-color:var(--border);opacity:0.4">')}
      <button class="primary" id="toDetectBtn">Continue to Detection Engineering &rarr;</button>
    </div>`;

  preview.querySelector('#toDetectBtn').addEventListener('click', () => controller.goTo('detection'));
}
