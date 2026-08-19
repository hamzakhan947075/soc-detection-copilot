'use strict';

const express = require('express');
const config = require('../config/env');
const { upload } = require('../ingestion/upload');
const { fromUpload, fromPaste } = require('../ingestion/logSource');
const { listSampleDatasets, loadSampleDataset } = require('../ingestion/sampleDatasets');
const esClient = require('../ingestion/elasticsearchClient');

const { ingest, defaultMappings, normalizeAll } = require('../pipeline/pipelineOrchestrator');
const { createSession, getSession } = require('../pipeline/sessionStore');
const { STAGES } = require('../pipeline/stages');
const { runDetectionEngine } = require('../detection-engine/detectionEngine');
const { buildRule } = require('../rule-generation/ruleBuilder');
const { testRule } = require('../testing/ruleTester');
const { analyzeFalsePositives } = require('../false-positive/fpAnalysis');
const { recommendTuning } = require('../tuning/tuning');
const { buildReport, toMarkdown, toCsv } = require('../reporting/reportGenerator');
const { buildDashboard } = require('../reporting/dashboard');
const { MITRE_LOOKUP } = require('../mitre/mitreMap');
const { explainDetection, isEnabled: aiEnabled } = require('../ai/aiAssist');

const router = express.Router();

function requireSession(req, res, next) {
  const session = getSession(req.params.sessionId);
  if (!session) {
    res.status(404).json({ error: 'Session not found or expired. Please re-ingest your dataset.' });
    return;
  }
  req.session = session;
  next();
}

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

// ---------- Pipeline metadata ----------
router.get('/pipeline', (_req, res) => {
  res.json({ stages: STAGES });
});

router.get('/mitre/techniques', (_req, res) => {
  res.json({ techniques: MITRE_LOOKUP });
});

router.get('/ai/status', (_req, res) => {
  res.json({ enabled: aiEnabled() });
});

// ---------- Sample datasets ----------
router.get('/samples', (_req, res) => {
  res.json({ samples: listSampleDatasets() });
});

router.post('/samples/:name/load', (req, res) => {
  const dataset = loadSampleDataset(req.params.name);
  if (!dataset) {
    res.status(404).json({ error: `Sample dataset "${req.params.name}" was not found.` });
    return;
  }
  const result = ingest(dataset.rawText, dataset.filename);
  const session = createSession({ events: result.events, fieldDiscovery: result.fieldDiscovery, logSource: result.logSource, ingestMeta: result });
  res.status(201).json(toSessionSummary(session, result));
});

// ---------- Ingestion (file upload or paste) ----------
router.post('/sessions', upload.single('file'), (req, res) => {
  let rawText;
  let filenameHint = '';

  if (req.file) {
    rawText = req.file.buffer.toString('utf8');
    filenameHint = req.file.originalname || '';
  } else if (req.body && typeof req.body.text === 'string') {
    if (Buffer.byteLength(req.body.text, 'utf8') > config.upload.maxPasteBytes) {
      res.status(400).json({ error: `Pasted text exceeds the maximum allowed size of ${config.upload.maxPasteBytes} bytes.` });
      return;
    }
    rawText = req.body.text;
    filenameHint = req.body.filename || '';
  } else {
    res.status(400).json({ error: 'Provide either a file upload (field "file") or a JSON body with a "text" field.' });
    return;
  }

  if (!rawText || !rawText.trim()) {
    res.status(400).json({ error: 'No log content was provided.' });
    return;
  }

  const source = req.file ? fromUpload(req.file.buffer, filenameHint) : fromPaste(rawText);
  const result = ingest(source.rawText, filenameHint);
  const session = createSession({ events: result.events, fieldDiscovery: result.fieldDiscovery, logSource: result.logSource, ingestMeta: result });
  res.status(201).json(toSessionSummary(session, result));
});

function toSessionSummary(session, result) {
  return {
    sessionId: session.id,
    format: result.format,
    formatReason: result.formatReason,
    totalParsed: result.totalParsed,
    truncated: result.truncated,
    logSource: result.logSource,
    fieldDiscovery: result.fieldDiscovery,
  };
}

router.get('/sessions/:sessionId', requireSession, (req, res) => {
  const s = req.session;
  res.json({
    sessionId: s.id,
    stage: s.stage,
    eventCount: s.events.length,
    logSource: s.logSource,
    fieldDiscovery: s.fieldDiscovery,
    mappingsApproved: Boolean(s.mappings),
    normalized: Boolean(s.normalizedEvents),
    detectionCount: s.detections ? s.detections.length : 0,
    ruleCount: s.rules.size,
  });
});

// ---------- Field discovery / ECS mapping ----------
router.get('/sessions/:sessionId/fields', requireSession, (req, res) => {
  res.json(req.session.fieldDiscovery);
});

router.get('/sessions/:sessionId/mappings/suggested', requireSession, (req, res) => {
  res.json({ mappings: defaultMappings(req.session.fieldDiscovery) });
});

router.put('/sessions/:sessionId/mappings', requireSession, (req, res) => {
  const { mappings } = req.body || {};
  if (!Array.isArray(mappings)) {
    res.status(400).json({ error: '"mappings" must be an array of {rawField, ecsField, ecsType}.' });
    return;
  }
  const sanitized = mappings
    .filter((m) => m && typeof m.rawField === 'string')
    .map((m) => ({
      rawField: m.rawField,
      ecsField: typeof m.ecsField === 'string' && m.ecsField.trim() ? m.ecsField.trim() : null,
      ecsType: typeof m.ecsType === 'string' ? m.ecsType : 'keyword',
      confidence: typeof m.confidence === 'number' ? m.confidence : null,
      status: m.status || 'analyst-approved',
    }));
  req.session.mappings = sanitized;
  req.session.stage = 'mapped';
  res.json({ mappings: sanitized });
});

// ---------- Normalization ----------
router.post('/sessions/:sessionId/normalize', requireSession, (req, res) => {
  const session = req.session;
  const mappings = session.mappings || defaultMappings(session.fieldDiscovery);
  session.mappings = mappings;

  const { normalizedEvents, sampleChanges, coveragePercent, totalChanges } = normalizeAll(session.events, mappings);
  session.normalizedEvents = normalizedEvents;
  session.normalizationSample = sampleChanges;
  session.ecsCoveragePercent = coveragePercent;
  session.stage = 'normalized';

  res.json({ coveragePercent, totalChanges, sample: sampleChanges });
});

router.get('/sessions/:sessionId/normalized/sample', requireSession, (req, res) => {
  if (!req.session.normalizationSample) {
    res.status(409).json({ error: 'Dataset has not been normalized yet. Call POST /normalize first.' });
    return;
  }
  res.json({ sample: req.session.normalizationSample, coveragePercent: req.session.ecsCoveragePercent });
});

// ---------- Detection engineering ----------
router.post('/sessions/:sessionId/detect', requireSession, (req, res) => {
  const session = req.session;
  if (!session.normalizedEvents) {
    res.status(409).json({ error: 'Dataset has not been normalized yet. Call POST /normalize first.' });
    return;
  }
  const result = runDetectionEngine(session.normalizedEvents);
  session.detections = result.detections;
  session.stage = 'detected';
  res.json(result);
});

router.get('/sessions/:sessionId/detections', requireSession, (req, res) => {
  res.json({ detections: req.session.detections || [] });
});

router.get(
  '/sessions/:sessionId/detections/:detectionId/explain',
  requireSession,
  asyncHandler(async (req, res) => {
    const detection = (req.session.detections || []).find((d) => d.id === req.params.detectionId);
    if (!detection) {
      res.status(404).json({ error: 'Detection not found.' });
      return;
    }
    const explanation = await explainDetection(detection);
    res.json(explanation);
  })
);

// ---------- Rule generation ----------
router.post('/sessions/:sessionId/rules', requireSession, (req, res) => {
  const session = req.session;
  const { detectionId, ruleType, indexPattern, severityOverride } = req.body || {};
  const detection = (session.detections || []).find((d) => d.id === detectionId);
  if (!detection) {
    res.status(404).json({ error: 'Detection not found. Run detection first and pass a valid detectionId.' });
    return;
  }

  const resolvedIndex = indexPattern || (session.logSource && session.logSource.recommendedDataset ? `logs-${session.logSource.recommendedDataset}-*` : 'logs-*');
  const rule = buildRule(detection, { ruleType, indexPattern: resolvedIndex, severityOverride });
  const ruleId = `rule-${Date.now().toString(36)}-${Math.round(Math.random() * 1e6)}`;
  session.rules.set(ruleId, { ...rule, ruleId, detectionId });
  session.stage = 'rule-generated';
  res.status(201).json({ ruleId, ...rule });
});

router.get('/sessions/:sessionId/rules', requireSession, (req, res) => {
  res.json({ rules: [...req.session.rules.values()] });
});

router.get('/sessions/:sessionId/rules/:ruleId', requireSession, (req, res) => {
  const rule = req.session.rules.get(req.params.ruleId);
  if (!rule) {
    res.status(404).json({ error: 'Rule not found.' });
    return;
  }
  res.json(rule);
});

// ---------- Rule testing / false positives / tuning ----------
router.post('/sessions/:sessionId/rules/:ruleId/test', requireSession, (req, res) => {
  const session = req.session;
  const rule = session.rules.get(req.params.ruleId);
  if (!rule) {
    res.status(404).json({ error: 'Rule not found.' });
    return;
  }
  if (!session.normalizedEvents) {
    res.status(409).json({ error: 'Dataset has not been normalized yet.' });
    return;
  }
  const detection = (session.detections || []).find((d) => d.id === rule.detectionId);
  const testResult = testRule(rule, session.normalizedEvents);
  const fpAnalysis = analyzeFalsePositives(testResult, detection || { matchedEventIndexes: [] });

  rule.lastTestResult = testResult;
  rule.lastFpAnalysis = fpAnalysis;
  session.stage = 'validated';

  res.json({ testResult, fpAnalysis });
});

router.get('/sessions/:sessionId/rules/:ruleId/tune', requireSession, (req, res) => {
  const session = req.session;
  const rule = session.rules.get(req.params.ruleId);
  if (!rule) {
    res.status(404).json({ error: 'Rule not found.' });
    return;
  }
  if (!rule.lastFpAnalysis) {
    res.status(409).json({ error: 'Rule has not been tested yet. Call POST /test first.' });
    return;
  }
  const tuning = recommendTuning(rule, rule.lastFpAnalysis, session.normalizedEvents);
  rule.tuningRecommendations = tuning.applicable ? [tuning.reason] : [];
  session.stage = 'tuned';
  res.json(tuning);
});

// ---------- Reporting ----------
router.get('/sessions/:sessionId/rules/:ruleId/report', requireSession, (req, res) => {
  const session = req.session;
  const rule = session.rules.get(req.params.ruleId);
  if (!rule) {
    res.status(404).json({ error: 'Rule not found.' });
    return;
  }
  const detection = (session.detections || []).find((d) => d.id === rule.detectionId);
  const format = (req.query.format || 'json').toString().toLowerCase();

  const report = buildReport({
    detection: detection || { name: rule.ruleName, description: rule.description, confidence: 0, mitre: rule.mitre, severity: rule.severity, matchedEventIndexes: [] },
    rule,
    testResult: rule.lastTestResult,
    fpAnalysis: rule.lastFpAnalysis,
    tuning: rule.tuningRecommendations && rule.tuningRecommendations.length ? { applicable: true, currentThreshold: rule.threshold?.count, suggestedThreshold: rule.threshold?.count, reason: rule.tuningRecommendations[0] } : null,
    logSource: session.logSource,
    ecsCoveragePercent: session.ecsCoveragePercent ?? null,
  });

  if (format === 'markdown' || format === 'md') {
    res.type('text/markdown').send(toMarkdown(report));
    return;
  }
  if (format === 'csv') {
    res.type('text/csv').send(toCsv(report));
    return;
  }
  res.json(report);
});

// ---------- Dashboard ----------
router.get('/sessions/:sessionId/dashboard', requireSession, (req, res) => {
  res.json(buildDashboard(req.session));
});

// ---------- Elasticsearch (optional, env-configured) ----------
router.get('/elasticsearch/status', (_req, res) => {
  res.json({ configured: esClient.isConfigured() });
});

router.post(
  '/elasticsearch/test-connection',
  asyncHandler(async (_req, res) => {
    try {
      const result = await esClient.testConnection();
      res.json(result);
    } catch (err) {
      res.status(400).json({ connected: false, error: err.message });
    }
  })
);

router.get(
  '/elasticsearch/indices',
  asyncHandler(async (_req, res) => {
    try {
      const indices = await esClient.listIndices();
      res.json({ indices });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  })
);

router.post(
  '/elasticsearch/fetch',
  asyncHandler(async (req, res) => {
    const { index, from, to, size } = req.body || {};
    try {
      const docs = await esClient.fetchLogs({ index, from, to, size });
      const result = ingest(JSON.stringify(docs), `${index || 'elasticsearch'}.json`);
      const session = createSession({ events: result.events, fieldDiscovery: result.fieldDiscovery, logSource: result.logSource, ingestMeta: result });
      res.status(201).json(toSessionSummary(session, result));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  })
);

module.exports = router;
