'use strict';

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

/** Aggregates dashboard metrics for a single session, per section 19 of the spec. */
function buildDashboard(session) {
  const fieldDiscovery = session.fieldDiscovery;
  const mappings = session.mappings || [];
  const detections = session.detections || [];
  const rules = [...session.rules.values()];

  const mappedFields = mappings.filter((m) => m.ecsField).length;
  const mappingCoverage = mappings.length > 0 ? Math.round((mappedFields / mappings.length) * 10000) / 100 : 0;

  const validatedRules = rules.filter((r) => r.queryValid).length;
  const totalPotentialFPs = rules.reduce((sum, r) => sum + (r.lastFpAnalysis ? r.lastFpAnalysis.potentialFalsePositiveCount : 0), 0);

  const mitreTechniques = new Set(detections.filter((d) => d.mitre && d.mitre.techniqueId).map((d) => d.mitre.techniqueId));
  const highRiskFindings = detections.filter((d) => d.severity === 'high' || d.severity === 'critical').length;

  return {
    logsProcessed: session.events ? session.events.length : 0,
    uniqueFields: fieldDiscovery ? fieldDiscovery.uniqueFieldCount : 0,
    ecsMappedFields: mappedFields,
    mappingCoveragePercent: mappingCoverage,
    detectionCandidates: detections.length,
    rulesGenerated: rules.length,
    rulesValidated: validatedRules,
    potentialFalsePositives: totalPotentialFPs,
    mitreTechniques: mitreTechniques.size,
    highRiskFindings,
    severityBreakdown: SEVERITY_ORDER.reduce((acc, sev) => {
      acc[sev] = detections.filter((d) => d.severity === sev).length;
      return acc;
    }, {}),
  };
}

module.exports = { buildDashboard };
