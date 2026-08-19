'use strict';

/**
 * The detection rule lifecycle state machine. Pure and DB-agnostic - this
 * module only knows the rules of what transition is allowed from what,
 * not how/where a detection's current state is stored (see
 * persistence/detectionStore.js for that).
 *
 * Deliberately not a strict linear sequence: re-testing after tuning, or
 * re-tuning after a further test, are normal parts of real detection
 * engineering and are allowed. What's NOT allowed is skipping the work a
 * status is supposed to represent - most importantly, you cannot approve a
 * detection that has never been tested, and cannot promote to production
 * without having gone through approval.
 */

const STATUSES = ['draft', 'generated', 'validated', 'tested', 'tuned', 'approved', 'production', 'deprecated'];

// For each status, the set of *current* statuses a detection may transition
// from to reach it. "deprecated" is reachable from anywhere - retiring a
// detection should never be blocked by where it happens to be in the cycle.
const ALLOWED_FROM = {
  generated: ['draft', 'generated'],
  validated: ['generated', 'validated'],
  tested: ['generated', 'validated', 'tested', 'tuned'],
  tuned: ['tested', 'tuned'],
  approved: ['tested', 'tuned', 'approved'],
  production: ['approved', 'production'],
  deprecated: STATUSES,
};

class LifecycleTransitionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LifecycleTransitionError';
  }
}

/** Throws LifecycleTransitionError if moving from `currentStatus` to `nextStatus` isn't allowed. */
function assertValidTransition(currentStatus, nextStatus) {
  if (!STATUSES.includes(nextStatus)) {
    throw new LifecycleTransitionError(`Unknown status "${nextStatus}". Valid statuses: ${STATUSES.join(', ')}`);
  }
  if (nextStatus === 'draft') {
    throw new LifecycleTransitionError('Cannot transition to "draft" - it is only the initial state a detection is created in.');
  }
  const allowedFrom = ALLOWED_FROM[nextStatus] || [];
  if (!allowedFrom.includes(currentStatus)) {
    throw new LifecycleTransitionError(
      `Cannot move from "${currentStatus}" to "${nextStatus}" - "${nextStatus}" requires the detection to currently be in one of: ${allowedFrom.join(', ')}.`
    );
  }
}

/** True/false version of assertValidTransition, for callers that want to decide UI affordances rather than catch. */
function canTransition(currentStatus, nextStatus) {
  try {
    assertValidTransition(currentStatus, nextStatus);
    return true;
  } catch (_err) {
    return false;
  }
}

module.exports = { STATUSES, assertValidTransition, canTransition, LifecycleTransitionError };
