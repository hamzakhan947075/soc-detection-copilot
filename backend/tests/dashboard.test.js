'use strict';

const { buildDashboard } = require('../src/reporting/dashboard');

describe('buildDashboard - mapping coverage denominator', () => {
  test('excludes both "excluded" and "custom" fields from mappingCoveragePercent', () => {
    const session = {
      events: [{}],
      fieldDiscovery: { uniqueFieldCount: 3 },
      mappings: [
        { rawField: 'user.name', ecsField: 'user.name', status: 'confident' },
        { rawField: '_id', ecsField: null, status: 'excluded' },
        { rawField: 'auth.mfa_used', ecsField: null, status: 'custom' },
      ],
      detections: [],
      rules: new Map(),
    };
    const dashboard = buildDashboard(session);
    expect(dashboard.mappingCoveragePercent).toBe(100);
    expect(dashboard.ecsMappedFields).toBe(1);
  });
});
