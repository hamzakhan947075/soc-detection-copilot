'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

/**
 * Minimal SQLite-backed persistence for exactly one thing: the Detection
 * lifecycle (see detections/detectionLifecycle.js). Everything else in the
 * app (session data, parsed events, field discovery, mappings) stays in the
 * existing in-memory sessionStore - that data is genuinely ephemeral
 * (cheap to re-derive by re-ingesting), lifecycle status is not (an
 * analyst's "approved"/"production" decision must survive a restart to
 * mean anything).
 *
 * Deliberately not coupled to SQLite beyond this file and
 * persistence/detectionStore.js - detectionStore's public functions return
 * plain objects, not SQL rows or prepared statements, so a future move to
 * PostgreSQL only touches these two files.
 */

const DEFAULT_DB_PATH = path.join(__dirname, '..', '..', 'data', 'detections.sqlite');

function resolveDbPath() {
  if (process.env.DETECTION_DB_PATH) return process.env.DETECTION_DB_PATH;
  if (process.env.NODE_ENV === 'test') return ':memory:';
  return DEFAULT_DB_PATH;
}

const dbPath = resolveDbPath();
if (dbPath !== ':memory:') {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
}

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS detection_definitions (
    evaluator_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT,
    severity TEXT,
    confidence REAL,
    mitre_json TEXT,
    ecs_requirements_json TEXT,
    rule_conditions_json TEXT,
    query TEXT,
    query_language TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    version INTEGER NOT NULL DEFAULT 1,
    author TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS detection_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluator_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    author TEXT,
    note TEXT,
    FOREIGN KEY (evaluator_id) REFERENCES detection_definitions(evaluator_id)
  );

  CREATE INDEX IF NOT EXISTS idx_detection_history_evaluator_id ON detection_history(evaluator_id);
`);

module.exports = db;
