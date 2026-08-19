'use strict';

const { getConditionsFor } = require('./queryConditions');
const { buildKql, buildLucene, buildEql, buildEsql, buildSigma } = require('./queryLanguages');
const { validateRule } = require('../rule-validation/ruleValidator');
const { getChecklist } = require('../investigation/investigationChecklists');
const { getFpGuidance } = require('../false-positive/fpGuidance');

const SEVERITY_RISK_SCORE = { low: 25, medium: 50, high: 70, critical: 95 };

const RESPONSE_RECOMMENDATIONS = {
  authentication: 'Disable or reset credentials for the targeted account(s) if compromise is confirmed; block the source IP at the perimeter if malicious.',
  linux: 'Isolate the affected host from the network pending investigation; rotate credentials used on the host.',
  windows: 'Isolate the affected endpoint via EDR; rotate credentials and review persistence mechanisms before returning to service.',
  network: 'Block the destination IP/domain at the firewall/proxy; review egress traffic from the affected host.',
  web: 'Block the source IP at the WAF; patch the affected application endpoint; review for successful exploitation.',
  firewall: 'Confirm the traffic was blocked as intended; escalate to network team if repeated from the same source.',
};

/**
 * Builds a full, production-oriented detection rule from a Detection
 * Candidate plus the analyst's selections. Every structural field required
 * by the rule spec (severity, risk score, query, index, schedule, MITRE,
 * FP guidance, investigation steps, etc.) is populated here.
 */
function buildRule(detection, options = {}) {
  const {
    ruleType = 'kql', // kql | esql | eql | lucene | sigma | threshold
    indexPattern,
    severityOverride,
  } = options;

  const severity = severityOverride || detection.severity;
  const conditions = detection.ruleConditions || getConditionsFor(detection.mitreHint);
  const resolvedIndex = indexPattern || 'logs-*';

  const language = ruleType === 'threshold' ? 'kql' : ruleType;
  const query = generateQuery(language, conditions, resolvedIndex, detection);
  const validation = validateRule(query, language);

  const checklist = getChecklist(detection.category);
  const fpGuidance = getFpGuidance(detection.mitreHint);

  return {
    ruleName: detection.name,
    description: detection.description,
    severity,
    riskScore: SEVERITY_RISK_SCORE[severity] || 50,
    ruleType: language,
    conditions,
    query,
    queryValid: validation.valid,
    queryValidationErrors: validation.errors,
    requiredFields: detection.requiredFields,
    dataSource: detection.category,
    indexPattern: resolvedIndex,
    schedule: 'Every 1 minute',
    lookbackWindow: detection.recommendedThreshold ? `${detection.recommendedThreshold.windowMinutes || 5} minutes` : '5 minutes',
    threshold: detection.recommendedThreshold
      ? {
          count: detection.recommendedThreshold.count || 10,
          windowMinutes: detection.recommendedThreshold.windowMinutes || 5,
          distinctField: detection.recommendedThreshold.distinctField || null,
        }
      : null,
    groupingFields: detection.recommendedThreshold ? detection.recommendedThreshold.groupBy || [] : [],
    mitre: detection.mitre,
    falsePositiveScenarios: fpGuidance.scenarios,
    recommendedExclusions: fpGuidance.recommendedExclusions,
    tuningRecommendations: [],
    investigationSteps: checklist,
    responseRecommendation: RESPONSE_RECOMMENDATIONS[detection.category] || 'Escalate to a senior analyst for triage.',
    references: buildReferences(detection),
  };
}

function generateQuery(language, conditions, index, detection) {
  switch (language) {
    case 'esql':
      return buildEsql(conditions, index, detection.recommendedThreshold);
    case 'eql':
      return buildEql(conditions, detection.category);
    case 'lucene':
      return buildLucene(conditions);
    case 'sigma':
      return buildSigma({
        ruleName: detection.name,
        description: detection.description,
        conditions,
        mitre: detection.mitre,
        severity: detection.severity,
        logsourceCategory: detection.category,
        threshold: detection.recommendedThreshold,
      });
    case 'kql':
    default:
      return buildKql(conditions);
  }
}

function buildReferences(detection) {
  const refs = [];
  if (detection.mitre && detection.mitre.techniqueId) {
    refs.push(`https://attack.mitre.org/techniques/${detection.mitre.techniqueId.replace('.', '/')}/`);
  }
  refs.push('https://www.elastic.co/guide/en/ecs/current/index.html');
  return refs;
}

module.exports = { buildRule, SEVERITY_RISK_SCORE };
