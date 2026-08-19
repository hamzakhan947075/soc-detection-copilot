'use strict';

const STAGES = [
  { id: 'ingest', order: 1, label: 'INGEST', description: 'Upload, paste, load a sample dataset, or fetch from Elasticsearch.' },
  { id: 'discover', order: 2, label: 'DISCOVER', description: 'Detect format, identify the log source, and profile every field.' },
  { id: 'normalize', order: 3, label: 'NORMALIZE', description: 'Approve or override ECS mappings for each field.' },
  { id: 'ecs-map', order: 4, label: 'ECS MAP', description: 'Build the normalized ECS event and compare to the raw event.' },
  { id: 'analyze', order: 5, label: 'ANALYZE', description: 'Run detection engineering analysis across auth, host, network, web and firewall behaviors.' },
  { id: 'detect', order: 6, label: 'DETECT', description: 'Review Detection Candidates with severity, confidence and MITRE hints.' },
  { id: 'generate-rule', order: 7, label: 'GENERATE RULE', description: 'Generate a KQL / ES|QL / EQL / Lucene / Sigma rule for a detection.' },
  { id: 'validate', order: 8, label: 'VALIDATE', description: 'Validate rule syntax and test it against the loaded dataset.' },
  { id: 'tune', order: 9, label: 'TUNE', description: 'Review false-positive analysis and threshold tuning recommendations.' },
  { id: 'deploy', order: 10, label: 'DEPLOY', description: 'Export the final Detection Engineering Report as a production-ready detection.' },
];

module.exports = { STAGES };
