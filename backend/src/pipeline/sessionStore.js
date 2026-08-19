'use strict';

const crypto = require('crypto');

const SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

/**
 * In-memory store for pipeline sessions. Each session tracks one loaded
 * dataset through every workflow stage (ingest -> discover -> normalize ->
 * detect -> rules -> test -> tune -> report). No persistence layer is
 * required for a single-analyst workspace tool; sessions expire after
 * SESSION_TTL_MS of inactivity to bound memory usage.
 */
const sessions = new Map();

function createSession(initialData) {
  const id = crypto.randomUUID();
  const session = {
    id,
    createdAt: Date.now(),
    lastAccessedAt: Date.now(),
    stage: 'ingested',
    rules: new Map(),
    mappings: null,
    normalizedEvents: null,
    normalizationSample: null,
    detections: null,
    logSource: null,
    fieldDiscovery: null,
    ...initialData,
  };
  sessions.set(id, session);
  return session;
}

function getSession(id) {
  const session = sessions.get(id);
  if (!session) return null;
  if (Date.now() - session.lastAccessedAt > SESSION_TTL_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastAccessedAt = Date.now();
  return session;
}

function deleteSession(id) {
  sessions.delete(id);
}

function sweepExpiredSessions() {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (now - session.lastAccessedAt > SESSION_TTL_MS) sessions.delete(id);
  }
}

module.exports = { createSession, getSession, deleteSession, sweepExpiredSessions };
