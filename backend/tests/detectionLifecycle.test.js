'use strict';

const { assertValidTransition, canTransition, LifecycleTransitionError, STATUSES } = require('../src/detections/detectionLifecycle');

describe('detectionLifecycle', () => {
  test('allows the normal forward path from draft through production', () => {
    expect(() => assertValidTransition('draft', 'generated')).not.toThrow();
    expect(() => assertValidTransition('generated', 'validated')).not.toThrow();
    expect(() => assertValidTransition('validated', 'tested')).not.toThrow();
    expect(() => assertValidTransition('tested', 'tuned')).not.toThrow();
    expect(() => assertValidTransition('tuned', 'approved')).not.toThrow();
    expect(() => assertValidTransition('approved', 'production')).not.toThrow();
  });

  test('allows testing directly after validation without tuning first', () => {
    expect(() => assertValidTransition('validated', 'tested')).not.toThrow();
  });

  test('allows re-testing after tuning (the tune -> re-test loop is normal)', () => {
    expect(() => assertValidTransition('tuned', 'tested')).not.toThrow();
  });

  test('rejects approving a detection that has never been tested', () => {
    expect(() => assertValidTransition('draft', 'approved')).toThrow(LifecycleTransitionError);
    expect(() => assertValidTransition('generated', 'approved')).toThrow(LifecycleTransitionError);
    expect(() => assertValidTransition('validated', 'approved')).toThrow(LifecycleTransitionError);
  });

  test('rejects promoting to production without prior approval', () => {
    expect(() => assertValidTransition('tested', 'production')).toThrow(LifecycleTransitionError);
    expect(() => assertValidTransition('tuned', 'production')).toThrow(LifecycleTransitionError);
  });

  test('rejects transitioning back to draft', () => {
    expect(() => assertValidTransition('generated', 'draft')).toThrow(LifecycleTransitionError);
  });

  test('rejects an unknown status', () => {
    expect(() => assertValidTransition('draft', 'not-a-real-status')).toThrow(LifecycleTransitionError);
  });

  test('allows deprecating from any status', () => {
    for (const status of STATUSES) {
      expect(() => assertValidTransition(status, 'deprecated')).not.toThrow();
    }
  });

  test('canTransition mirrors assertValidTransition without throwing', () => {
    expect(canTransition('draft', 'generated')).toBe(true);
    expect(canTransition('draft', 'approved')).toBe(false);
    expect(canTransition('production', 'deprecated')).toBe(true);
  });
});
