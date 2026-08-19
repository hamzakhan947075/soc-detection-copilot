import { escapeHtml } from './utils.js';
import { resolveStage } from './state.js';

let stages = [];

export function setStages(list) {
  stages = list;
}

export function renderPipelineBar() {
  const container = document.getElementById('pipelineBar');
  if (!container || stages.length === 0) return;

  const currentId = resolveStage();
  const currentOrder = (stages.find((s) => s.id === currentId) || stages[0]).order;

  container.innerHTML = stages
    .map((stage, idx) => {
      const cls = stage.order < currentOrder ? 'done' : stage.order === currentOrder ? 'current' : '';
      const arrow = idx < stages.length - 1 ? '<span class="pipeline-arrow">&rarr;</span>' : '';
      return `<div class="pipeline-step ${cls}" title="${escapeHtml(stage.description)}"><span class="num">${stage.order}</span>${escapeHtml(stage.label)}</div>${arrow}`;
    })
    .join('');
}
