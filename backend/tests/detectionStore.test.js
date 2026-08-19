'use strict';

const db = require('../src/persistence/db');
const detectionStore = require('../src/persistence/detectionStore');
const { LifecycleTransitionError } = require('../src/detections/detectionLifecycle');

function makeRecord(overrides = {}) {
  return {
    name: 'SSH/Authentication Brute Force',
    description: 'Multiple failed authentication attempts.',
    dataSources: ['authentication'],
    severity: 'high',
    confidence: 0.87,
    ecsRequirements: ['source.ip', 'user.name'],
    ruleConditions: [{ field: 'event.outcome', value: 'failure' }],
    mitre: { tactic: { id: 'TA0006', name: 'Credential Access' }, technique: { id: 'T1110', name: 'Password Guessing' }, subTechnique: null, confidence: 0.9, certain: true },
    query: null,
    queryLanguage: null,
    evaluator: { id: 'authentication.brute_force', kind: 'structured' },
    ...overrides,
  };
}

beforeEach(() => {
  db.exec('DELETE FROM detection_history; DELETE FROM detection_definitions;');
});

describe('detectionStore.upsertFromDetectionRecord', () => {
  test('creates a new definition at version 1, status draft, with a history entry', () => {
    const persisted = detectionStore.upsertFromDetectionRecord(makeRecord(), { author: 'alice' });
    expect(persisted.status).toBe('draft');
    expect(persisted.version).toBe(1);
    expect(persisted.name).toBe('SSH/Authentication Brute Force');

    const hist = detectionStore.history('authentication.brute_force');
    expect(hist).toHaveLength(1);
    expect(hist[0]).toMatchObject({ status: 'draft', version: 1, author: 'alice' });
  });

  test('refreshes descriptive fields on a second call without touching status or version', () => {
    detectionStore.upsertFromDetectionRecord(makeRecord());
    const updated = detectionStore.upsertFromDetectionRecord(makeRecord({ description: 'Updated description', severity: 'critical' }));
    expect(updated.description).toBe('Updated description');
    expect(updated.severity).toBe('critical');
    expect(updated.status).toBe('draft');
    expect(updated.version).toBe(1);
    expect(detectionStore.history('authentication.brute_force')).toHaveLength(1); // no new history row from a plain refresh
  });
});

describe('detectionStore.transition', () => {
  test('moves status forward and records a history entry', () => {
    detectionStore.upsertFromDetectionRecord(makeRecord());
    const result = detectionStore.transition('authentication.brute_force', 'generated', { author: 'bob', note: 'KQL rule generated' });
    expect(result.status).toBe('generated');
    expect(result.version).toBe(1); // not a release boundary
    const hist = detectionStore.history('authentication.brute_force');
    expect(hist).toHaveLength(2);
    expect(hist[1]).toMatchObject({ status: 'generated', author: 'bob', note: 'KQL rule generated' });
  });

  test('rejects approving a detection that was never tested, and leaves state unchanged', () => {
    detectionStore.upsertFromDetectionRecord(makeRecord());
    expect(() => detectionStore.transition('authentication.brute_force', 'approved')).toThrow(LifecycleTransitionError);
    const record = detectionStore.get('authentication.brute_force');
    expect(record.status).toBe('draft');
    expect(detectionStore.history('authentication.brute_force')).toHaveLength(1); // no new row from the rejected attempt
  });

  test('bumps the version when promoting to approved, and again for production', () => {
    detectionStore.upsertFromDetectionRecord(makeRecord());
    detectionStore.transition('authentication.brute_force', 'generated');
    detectionStore.transition('authentication.brute_force', 'validated');
    detectionStore.transition('authentication.brute_force', 'tested');
    const approved = detectionStore.transition('authentication.brute_force', 'approved');
    expect(approved.version).toBe(2);
    const production = detectionStore.transition('authentication.brute_force', 'production');
    expect(production.version).toBe(3);
  });

  test('allows the tune -> re-test loop without bumping version', () => {
    detectionStore.upsertFromDetectionRecord(makeRecord());
    detectionStore.transition('authentication.brute_force', 'generated');
    detectionStore.transition('authentication.brute_force', 'validated');
    detectionStore.transition('authentication.brute_force', 'tested');
    detectionStore.transition('authentication.brute_force', 'tuned');
    const retested = detectionStore.transition('authentication.brute_force', 'tested');
    expect(retested.status).toBe('tested');
    expect(retested.version).toBe(1);
  });

  test('throws for an evaluator id that was never persisted', () => {
    expect(() => detectionStore.transition('does.not_exist', 'generated')).toThrow(/No persisted detection found/);
  });
});

describe('detectionStore.listAll and get', () => {
  test('lists every persisted detection', () => {
    detectionStore.upsertFromDetectionRecord(makeRecord());
    detectionStore.upsertFromDetectionRecord(makeRecord({ name: 'Direct Root Login', evaluator: { id: 'linux.valid_accounts', kind: 'structured' } }));
    const all = detectionStore.listAll();
    expect(all.map((d) => d.evaluatorId).sort()).toEqual(['authentication.brute_force', 'linux.valid_accounts']);
  });

  test('get returns null for an unknown evaluator id', () => {
    expect(detectionStore.get('does.not_exist')).toBeNull();
  });
});
