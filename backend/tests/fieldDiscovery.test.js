'use strict';

const { discoverFields } = require('../src/field-discovery/fieldDiscovery');
const { flattenEvent } = require('../src/field-discovery/flatten');
const { inferValueType } = require('../src/field-discovery/valueTypes');

describe('flattenEvent', () => {
  test('flattens nested objects into dotted paths', () => {
    expect(flattenEvent({ host: { name: 'x' }, event: { dataset: 'sshd' } })).toEqual({
      'host.name': 'x',
      'event.dataset': 'sshd',
    });
  });

  test('keeps arrays of primitives intact', () => {
    expect(flattenEvent({ tags: ['a', 'b'] })).toEqual({ tags: ['a', 'b'] });
  });
});

describe('inferValueType', () => {
  test('recognizes IPv4 addresses', () => {
    expect(inferValueType('10.10.10.15')).toBe('ip');
  });

  test('recognizes ISO timestamps', () => {
    expect(inferValueType('2026-08-19T10:20:30Z')).toBe('date');
  });

  test('recognizes ports', () => {
    expect(inferValueType('8080')).toBe('port');
  });

  test('falls back to string for free text', () => {
    expect(inferValueType('Failed password for root')).toBe('string');
  });
});

describe('discoverFields', () => {
  const events = [
    { src_ip: '10.10.10.15', username: 'admin', action: 'denied' },
    { src_ip: '10.10.10.16', username: 'root', action: 'denied' },
    { src_ip: '10.10.10.15', username: null, action: 'allowed' },
  ];
  const result = discoverFields(events);

  test('discovers every unique field', () => {
    const fieldNames = result.fields.map((f) => f.field);
    expect(fieldNames).toEqual(expect.arrayContaining(['src_ip', 'username', 'action']));
  });

  test('computes null percentage correctly', () => {
    const username = result.fields.find((f) => f.field === 'username');
    expect(username.nullPercentage).toBeCloseTo(33.33, 1);
  });

  test('suggests an ECS candidate for a recognizable field name', () => {
    const srcIp = result.fields.find((f) => f.field === 'src_ip');
    expect(srcIp.ecsCandidate).toBe('source.ip');
    expect(srcIp.ecsConfidence).toBeGreaterThan(0.9);
  });

  test('flags security-relevant fields', () => {
    const srcIp = result.fields.find((f) => f.field === 'src_ip');
    expect(srcIp.securityRelevance).toBe('high');
  });
});
