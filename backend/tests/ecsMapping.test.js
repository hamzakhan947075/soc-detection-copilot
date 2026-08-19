'use strict';

const { suggestMapping } = require('../src/ecs-mapping/ecsMapper');
const { normalizeEvent } = require('../src/normalization/normalizer');
const { isKnownEcsField } = require('../src/ecs-mapping/ecsSchema');

describe('suggestMapping', () => {
  test('maps a raw field already matching ECS with very high confidence', () => {
    const result = suggestMapping('source.ip', ['10.10.10.15']);
    expect(result.ecsField).toBe('source.ip');
    expect(result.confidence).toBeGreaterThan(0.95);
    expect(result.status).toBe('confident');
  });

  test('maps src_ip -> source.ip with high confidence when values look like IPs', () => {
    const result = suggestMapping('src_ip', ['10.10.10.15', '8.8.8.8']);
    expect(result.ecsField).toBe('source.ip');
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
  });

  test('maps username -> user.name', () => {
    const result = suggestMapping('username', ['admin', 'root']);
    expect(result.ecsField).toBe('user.name');
  });

  test('lowers confidence when observed values do not match the expected type', () => {
    const result = suggestMapping('src_ip', ['not-an-ip-address']);
    expect(result.confidence).toBeLessThan(0.6);
    expect(result.status).toBe('uncertain');
  });

  test('returns unmapped status for unrecognized custom fields', () => {
    const result = suggestMapping('my_custom_widget_field', ['abc']);
    expect(result.status).toBe('unmapped');
    expect(result.ecsField).toBeNull();
  });

  test('never claims certainty for an ambiguous generic "ip" field', () => {
    const result = suggestMapping('ip', ['10.10.10.15']);
    expect(result.alternates.length).toBeGreaterThan(0);
  });
});

describe('ecsSchema', () => {
  test('recognizes canonical ECS fields', () => {
    expect(isKnownEcsField('source.ip')).toBe(true);
    expect(isKnownEcsField('totally.made.up')).toBe(false);
  });
});

describe('normalizeEvent', () => {
  test('builds a nested ECS object from flat mappings', () => {
    const raw = { src_ip: '10.10.10.15', username: 'admin', status: 'failure' };
    const mappings = [
      { rawField: 'src_ip', ecsField: 'source.ip', ecsType: 'ip' },
      { rawField: 'username', ecsField: 'user.name', ecsType: 'keyword' },
      { rawField: 'status', ecsField: 'event.outcome', ecsType: 'keyword' },
    ];
    const { normalized, changes } = normalizeEvent(raw, mappings);
    expect(normalized.source.ip).toBe('10.10.10.15');
    expect(normalized.user.name).toBe('admin');
    expect(normalized.event.outcome).toBe('failure');
    expect(changes).toHaveLength(3);
  });

  test('tracks unmapped fields without dropping data silently', () => {
    const raw = { weird_field: 'x' };
    const mappings = [{ rawField: 'weird_field', ecsField: null }];
    const { unmapped } = normalizeEvent(raw, mappings);
    expect(unmapped).toContain('weird_field');
  });

  test('coerces numeric string ports to numbers', () => {
    const raw = { dst_port: '443' };
    const mappings = [{ rawField: 'dst_port', ecsField: 'destination.port', ecsType: 'port' }];
    const { normalized } = normalizeEvent(raw, mappings);
    expect(normalized.destination.port).toBe(443);
  });
});
