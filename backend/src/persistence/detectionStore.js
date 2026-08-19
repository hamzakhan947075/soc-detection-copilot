'use strict';

const db = require('./db');
const { assertValidTransition } = require('../detections/detectionLifecycle');

const getStmt = db.prepare('SELECT * FROM detection_definitions WHERE evaluator_id = @evaluator_id');
const insertStmt = db.prepare(`
  INSERT INTO detection_definitions
    (evaluator_id, name, description, category, severity, confidence, mitre_json, ecs_requirements_json, rule_conditions_json, query, query_language, status, version, author, created_at, updated_at)
  VALUES
    (@evaluator_id, @name, @description, @category, @severity, @confidence, @mitre_json, @ecs_requirements_json, @rule_conditions_json, @query, @query_language, @status, @version, @author, @created_at, @updated_at)
`);
const updateFieldsStmt = db.prepare(`
  UPDATE detection_definitions
  SET name = @name, description = @description, category = @category, severity = @severity, confidence = @confidence,
      mitre_json = @mitre_json, ecs_requirements_json = @ecs_requirements_json, rule_conditions_json = @rule_conditions_json,
      query = @query, query_language = @query_language, updated_at = @updated_at
  WHERE evaluator_id = @evaluator_id
`);
const updateStatusStmt = db.prepare(`
  UPDATE detection_definitions SET status = @status, version = @version, updated_at = @updated_at WHERE evaluator_id = @evaluator_id
`);
const insertHistoryStmt = db.prepare(`
  INSERT INTO detection_history (evaluator_id, version, status, changed_at, author, note)
  VALUES (@evaluator_id, @version, @status, @changed_at, @author, @note)
`);
const historyStmt = db.prepare('SELECT * FROM detection_history WHERE evaluator_id = @evaluator_id ORDER BY id ASC');
const listAllStmt = db.prepare('SELECT * FROM detection_definitions ORDER BY updated_at DESC');

function rowToRecord(row) {
  if (!row) return null;
  return {
    evaluatorId: row.evaluator_id,
    name: row.name,
    description: row.description,
    category: row.category,
    severity: row.severity,
    confidence: row.confidence,
    mitre: row.mitre_json ? JSON.parse(row.mitre_json) : null,
    ecsRequirements: row.ecs_requirements_json ? JSON.parse(row.ecs_requirements_json) : [],
    ruleConditions: row.rule_conditions_json ? JSON.parse(row.rule_conditions_json) : null,
    query: row.query,
    queryLanguage: row.query_language,
    status: row.status,
    version: row.version,
    author: row.author,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function historyRowToRecord(row) {
  return { version: row.version, status: row.status, changedAt: row.changed_at, author: row.author, note: row.note };
}

/**
 * Creates or refreshes the persisted definition for a detection, keyed by
 * its stable evaluator id (detections/detectionRecord.js's
 * `${category}.${mitreHint}` - the same detection *type*, not one session's
 * specific instance of it). Descriptive fields (name/description/severity/
 * mitre/ecsRequirements/ruleConditions/query) are refreshed on every call so
 * the persisted copy tracks the current behavior-engine output; status and
 * version are never touched here - only `transition()` changes those.
 */
function upsertFromDetectionRecord(record, { author = 'system' } = {}) {
  const evaluatorId = record.evaluator.id;
  const now = new Date().toISOString();
  const existing = getStmt.get({ evaluator_id: evaluatorId });

  const fields = {
    evaluator_id: evaluatorId,
    name: record.name,
    description: record.description,
    category: record.dataSources[0] || null,
    severity: record.severity,
    confidence: record.confidence,
    mitre_json: JSON.stringify(record.mitre),
    ecs_requirements_json: JSON.stringify(record.ecsRequirements),
    rule_conditions_json: JSON.stringify(record.ruleConditions),
    query: record.query,
    query_language: record.queryLanguage,
  };

  if (!existing) {
    insertStmt.run({ ...fields, status: 'draft', version: 1, author, created_at: now, updated_at: now });
    insertHistoryStmt.run({ evaluator_id: evaluatorId, version: 1, status: 'draft', changed_at: now, author, note: 'Detection first persisted' });
  } else {
    updateFieldsStmt.run({ ...fields, updated_at: now });
  }
  return rowToRecord(getStmt.get({ evaluator_id: evaluatorId }));
}

/**
 * Moves a persisted detection to `nextStatus`, enforcing the lifecycle
 * rules in detections/detectionLifecycle.js (e.g. you cannot approve a
 * detection that was never tested). Promoting to "approved" or
 * "production" bumps the version - those are real release boundaries;
 * every other transition keeps the current version.
 */
function transition(evaluatorId, nextStatus, { author = 'system', note = '' } = {}) {
  const existing = getStmt.get({ evaluator_id: evaluatorId });
  if (!existing) {
    throw new Error(`No persisted detection found for evaluator id "${evaluatorId}". Persist it first.`);
  }
  assertValidTransition(existing.status, nextStatus);

  const bumpsVersion = nextStatus === 'approved' || nextStatus === 'production';
  const newVersion = bumpsVersion ? existing.version + 1 : existing.version;
  const now = new Date().toISOString();

  updateStatusStmt.run({ evaluator_id: evaluatorId, status: nextStatus, version: newVersion, updated_at: now });
  insertHistoryStmt.run({ evaluator_id: evaluatorId, version: newVersion, status: nextStatus, changed_at: now, author, note });
  return rowToRecord(getStmt.get({ evaluator_id: evaluatorId }));
}

function get(evaluatorId) {
  return rowToRecord(getStmt.get({ evaluator_id: evaluatorId }));
}

function listAll() {
  return listAllStmt.all().map(rowToRecord);
}

function history(evaluatorId) {
  return historyStmt.all({ evaluator_id: evaluatorId }).map(historyRowToRecord);
}

module.exports = { upsertFromDetectionRecord, transition, get, listAll, history };
