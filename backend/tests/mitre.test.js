'use strict';

const { mapToMitre } = require('../src/mitre/mitreMap');

describe('mapToMitre', () => {
  test('maps brute_force to T1110.001 with high confidence', () => {
    const result = mapToMitre('brute_force');
    expect(result.techniqueId).toBe('T1110.001');
    expect(result.tacticName).toBe('Credential Access');
    expect(result.certain).toBe(true);
  });

  test('marks a low-confidence mapping as uncertain rather than definitive', () => {
    const result = mapToMitre('xss');
    expect(result.certain).toBe(false);
    expect(result.note).toMatch(/review required/i);
  });

  test('never fabricates a mapping for an unknown hint', () => {
    const result = mapToMitre('totally_unknown_behavior');
    expect(result.techniqueId).toBeNull();
    expect(result.certain).toBe(false);
  });
});
