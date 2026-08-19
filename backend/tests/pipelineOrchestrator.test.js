'use strict';

const { normalizeAll } = require('../src/pipeline/pipelineOrchestrator');

describe('normalizeAll - coverage percentage denominator', () => {
  const events = [{ user: { name: 'admin' }, _id: 'abc', auth: { mfa_used: true }, weird_field: 'x' }];

  test('excludes both "excluded" (ES metadata) and "custom" (non-ECS) fields from the coverage denominator', () => {
    const mappings = [
      { rawField: 'user.name', ecsField: 'user.name', status: 'confident' },
      { rawField: '_id', ecsField: null, status: 'excluded' },
      { rawField: 'auth.mfa_used', ecsField: null, status: 'custom' },
    ];
    const { coveragePercent } = normalizeAll(events, mappings);
    // Only user.name is in the denominator, and it's mapped -> 100%, not 33%.
    expect(coveragePercent).toBe(100);
  });

  test('a genuinely unmapped field (not custom, not excluded) still counts against coverage', () => {
    const mappings = [
      { rawField: 'user.name', ecsField: 'user.name', status: 'confident' },
      { rawField: 'weird_field', ecsField: null, status: 'unmapped' },
    ];
    const { coveragePercent } = normalizeAll(events, mappings);
    expect(coveragePercent).toBe(50);
  });
});
