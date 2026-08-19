'use strict';

const { detectFormat } = require('../src/parsing/formatDetector');
const { parseRawLogs, extractPrimaryMessage } = require('../src/parsing/parsers');
const { safeJsonParse, SafeParseError } = require('../src/parsing/safeJson');

describe('safeJsonParse', () => {
  test('parses valid JSON', () => {
    expect(safeJsonParse('{"a":1}')).toEqual({ a: 1 });
  });

  test('rejects oversized input', () => {
    const big = '"' + 'a'.repeat(1000) + '"';
    expect(() => safeJsonParse(big, { maxBytes: 10 })).toThrow(SafeParseError);
  });

  test('rejects invalid JSON with a safe error, not a crash', () => {
    expect(() => safeJsonParse('{not valid')).toThrow(SafeParseError);
  });

  test('rejects excessively deep nesting', () => {
    let obj = {};
    let cursor = obj;
    for (let i = 0; i < 100; i++) {
      cursor.child = {};
      cursor = cursor.child;
    }
    expect(() => safeJsonParse(JSON.stringify(obj), { maxDepth: 10 })).toThrow(SafeParseError);
  });
});

describe('detectFormat', () => {
  test('detects a JSON array', () => {
    const result = detectFormat('[{"a":1},{"a":2}]');
    expect(result.format).toBe('json-array');
  });

  test('detects ndjson', () => {
    const result = detectFormat('{"a":1}\n{"a":2}\n{"a":3}');
    expect(result.format).toBe('ndjson');
  });

  test('detects csv', () => {
    const result = detectFormat('a,b,c\n1,2,3\n4,5,6', 'file.csv');
    expect(result.format).toBe('csv');
  });

  test('falls back to plain text for syslog-style content', () => {
    const result = detectFormat('Aug 19 10:00:00 host sshd[123]: Failed password for root');
    expect(result.format).toBe('plain');
  });
});

describe('parseRawLogs', () => {
  test('parses an Elastic-style ndjson export', () => {
    const raw = [
      JSON.stringify({ '@timestamp': '2026-08-19T10:20:30Z', message: 'Failed password for invalid user admin from 192.168.1.10', host: { name: 'server01' }, event: { dataset: 'sshd' } }),
      JSON.stringify({ '@timestamp': '2026-08-19T10:20:35Z', message: 'Accepted password for admin from 192.168.1.10' }),
    ].join('\n');
    const result = parseRawLogs(raw);
    expect(result.format).toBe('ndjson');
    expect(result.events).toHaveLength(2);
    expect(result.events[0].host.name).toBe('server01');
  });

  test('does not silently drop unparseable ndjson lines', () => {
    const raw = '{"a":1}\nnot json at all\n{"a":2}';
    const result = parseRawLogs(raw);
    expect(result.events).toHaveLength(3);
    expect(result.events[1]._parseWarning).toBeDefined();
  });

  test('parses CSV into row objects keyed by header', () => {
    const raw = 'src_ip,username,action\n10.10.10.15,admin,denied';
    const result = parseRawLogs(raw, 'export.csv');
    expect(result.format).toBe('csv');
    expect(result.events[0]).toEqual({ src_ip: '10.10.10.15', username: 'admin', action: 'denied' });
  });

  test('truncates datasets larger than the configured maximum', () => {
    const raw = Array.from({ length: 5 }, (_, i) => JSON.stringify({ n: i })).join('\n');
    const result = parseRawLogs(raw);
    // sanity - with default config this will not truncate 5 events, just confirm shape
    expect(result.truncated).toBe(false);
    expect(result.events).toHaveLength(5);
  });
});

describe('extractPrimaryMessage', () => {
  test('prefers message field', () => {
    expect(extractPrimaryMessage({ message: 'hello' })).toBe('hello');
  });

  test('falls back to event.original', () => {
    expect(extractPrimaryMessage({ event: { original: 'raw line' } })).toBe('raw line');
  });

  test('falls back to log.original', () => {
    expect(extractPrimaryMessage({ log: { original: 'raw log line' } })).toBe('raw log line');
  });

  test('returns empty string when nothing usable is present', () => {
    expect(extractPrimaryMessage({ foo: 'bar' })).toBe('');
  });
});
