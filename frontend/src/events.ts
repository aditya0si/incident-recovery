import type { LiveEvent } from './types'

export type { LiveEvent }

/**
 * Workflow events that can change the authoritative incident detail. When one
 * arrives the console refetches `GET /incidents/{id}` rather than trying to
 * derive proposal/approval/verification state from the stream payload alone.
 */
export const DETAIL_REFRESH_KINDS: ReadonlySet<string> = new Set([
  'state_changed',
  'proposal_created',
  'approval_requested',
  'approved',
  'rejected',
  'recovery_started',
  'recovery_executed',
  'recovery_verified',
  'recovery_failed',
  'escalated',
  'investigation_started',
  'diagnosis',
])

/**
 * Merge event batches by id. The persisted event id is a global monotonic
 * BIGSERIAL, so id order is causal order. Merging (rather than replacing) means
 * a staler REST snapshot can backfill older events without dropping events that
 * already arrived over the stream, and duplicate deliveries collapse to one.
 */
export function mergeEvents(existing: LiveEvent[], incoming: LiveEvent[]): LiveEvent[] {
  const byId = new Map<number, LiveEvent>()
  for (const event of existing) byId.set(event.id, event)
  for (const event of incoming) byId.set(event.id, event)
  return [...byId.values()].sort((a, b) => a.id - b.id)
}

export function highestEventId(events: LiveEvent[]): number {
  return events.reduce((max, event) => (event.id > max ? event.id : max), 0)
}

export function shouldRefreshDetail(events: LiveEvent[]): boolean {
  return events.some((event) => DETAIL_REFRESH_KINDS.has(event.kind))
}
