'use strict';

/**
 * Assembles the final Detection Engineering Report for a single detection +
 * generated rule, and renders it to JSON, Markdown, or CSV. PDF export is
 * intentionally not implemented: a correct PDF renderer is a substantial
 * dependency on its own, and JSON/Markdown/CSV already cover automation,
 * human review, and spreadsheet import respectively.
 */
function buildReport({ detection, rule, testResult, fpAnalysis, tuning, logSource, ecsCoveragePercent }) {
  const ruleStatus = rule.queryValid ? (testResult ? 'Validated' : 'Generated (Not Yet Tested)') : 'Invalid - Needs Correction';
  const fpRisk = fpAnalysis ? fpAnalysis.riskLevel : 'unknown';

  return {
    generatedAt: new Date().toISOString(),
    detection: detection.name,
    logSource: logSource ? logSource.source : 'Unknown',
    ecsCoveragePercent: ecsCoveragePercent ?? null,
    detectionConfidence: detection.confidence,
    mitre: detection.mitre,
    severity: detection.severity,
    ruleStatus,
    ruleType: rule.ruleType,
    query: rule.query,
    falsePositiveRisk: fpRisk,
    testSummary: testResult
      ? {
          eventsTested: testResult.eventsTested,
          eventsMatched: testResult.eventsMatched,
          matchRatePercent: testResult.matchRatePercent,
        }
      : null,
    tuning: tuning || null,
    recommendedAction: buildRecommendedAction(ruleStatus, fpRisk),
    investigationSteps: rule.investigationSteps,
    falsePositiveScenarios: rule.falsePositiveScenarios,
    recommendedExclusions: rule.recommendedExclusions,
    references: rule.references,
  };
}

function buildRecommendedAction(ruleStatus, fpRisk) {
  if (ruleStatus !== 'Validated') return 'Complete rule validation and testing before deployment.';
  if (fpRisk === 'high') return 'Do not deploy as-is; apply exclusions and re-test before deployment.';
  if (fpRisk === 'medium') return 'Deploy after applying the recommended exclusions/tuning.';
  return 'Ready to deploy to production.';
}

function toMarkdown(report) {
  const lines = [
    '# Detection Engineering Report',
    '',
    `**Detection:** ${report.detection}`,
    `**Log Source:** ${report.logSource}`,
    `**ECS Coverage:** ${report.ecsCoveragePercent !== null ? report.ecsCoveragePercent + '%' : 'N/A'}`,
    `**Detection Confidence:** ${Math.round(report.detectionConfidence * 100)}%`,
    `**MITRE:** ${report.mitre.techniqueId || 'Uncertain'} - ${report.mitre.techniqueName || 'N/A'} (${report.mitre.tacticName || 'N/A'})`,
    `**Severity:** ${report.severity}`,
    `**Rule Status:** ${report.ruleStatus}`,
    `**Rule Type:** ${report.ruleType}`,
    `**False Positive Risk:** ${report.falsePositiveRisk}`,
    '',
    '## Query',
    '```',
    report.query,
    '```',
    '',
  ];

  if (report.testSummary) {
    lines.push(
      '## Test Summary',
      `- Events Tested: ${report.testSummary.eventsTested}`,
      `- Events Matched: ${report.testSummary.eventsMatched}`,
      `- Match Rate: ${report.testSummary.matchRatePercent}%`,
      ''
    );
  }

  if (report.tuning && report.tuning.applicable) {
    lines.push(
      '## Tuning',
      `- Current Threshold: ${report.tuning.currentThreshold}`,
      `- Suggested Threshold: ${report.tuning.suggestedThreshold}`,
      `- Reason: ${report.tuning.reason}`,
      ''
    );
  }

  lines.push('## Investigation Steps', ...report.investigationSteps.map((s, i) => `${i + 1}. ${s}`), '');
  lines.push('## Potential False Positives', ...report.falsePositiveScenarios.map((s) => `- ${s}`), '');
  lines.push('## Recommended Exclusions (require analyst approval)', ...report.recommendedExclusions.map((s) => `- ${s}`), '');
  lines.push('## Recommended Action', report.recommendedAction, '');
  lines.push('## References', ...report.references.map((r) => `- ${r}`));

  return lines.join('\n');
}

function toCsv(report) {
  const rows = [
    ['field', 'value'],
    ['detection', report.detection],
    ['logSource', report.logSource],
    ['ecsCoveragePercent', String(report.ecsCoveragePercent)],
    ['detectionConfidence', String(report.detectionConfidence)],
    ['mitreTechniqueId', report.mitre.techniqueId || ''],
    ['mitreTechniqueName', report.mitre.techniqueName || ''],
    ['severity', report.severity],
    ['ruleStatus', report.ruleStatus],
    ['falsePositiveRisk', report.falsePositiveRisk],
    ['eventsTested', report.testSummary ? String(report.testSummary.eventsTested) : ''],
    ['eventsMatched', report.testSummary ? String(report.testSummary.eventsMatched) : ''],
    ['matchRatePercent', report.testSummary ? String(report.testSummary.matchRatePercent) : ''],
    ['recommendedAction', report.recommendedAction],
  ];
  return rows.map((row) => row.map(csvEscape).join(',')).join('\n');
}

function csvEscape(value) {
  const str = String(value ?? '');
  if (/[",\n]/.test(str)) return `"${str.replace(/"/g, '""')}"`;
  return str;
}

module.exports = { buildReport, toMarkdown, toCsv };
