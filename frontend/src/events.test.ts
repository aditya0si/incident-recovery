import { describe, expect, it } from 'vitest'
import { mergeEvents, shouldRefreshDetail, type LiveEvent } from './events'

function event(id: number, kind = 'state_changed'): LiveEvent {
  return {
    id,
    incident_id: 'incident-1',
    kind,
    payload: { id },
    created_at: new Date(id * 1000).toISOString(),
  }
}

describe('event merging', () => {
  it('orders and dedupes events by id', () => {
    const merged = mergeEvents([event(3), event(1)], [event(2), event(2), event(1)])
    expect(merged.map((e) => e.id)).toEqual([1, 2, 3])
    expect(merged).toHaveLength(3)
  })

  it('does not lose stream events when a staler snapshot backfills older events', () => {
    const afterStream = mergeEvents([], [event(5), event(6)])
    const snapshotEvents = [event(1), event(2), event(3), event(4)]
    const merged = mergeEvents(afterStream, snapshotEvents)
    expect(merged.map((e) => e.id)).toEqual([1, 2, 3, 4, 5, 6])
  })

  it('keeps the newest payload when the same id arrives twice', () => {
    const merged = mergeEvents(
      [event(1)],
      [{ ...event(1), payload: { updated: true } }],
    )
    expect(merged).toHaveLength(1)
    expect(merged[0].payload).toEqual({ updated: true })
  })
})

describe('detail refresh triggers', () => {
  it('refreshes on workflow-relevant events', () => {
    for (const kind of [
      'state_changed',
      'proposal_created',
      'approved',
      'rejected',
      'recovery_started',
      'recovery_executed',
      'recovery_verified',
      'recovery_failed',
      'escalated',
      'investigation_started',
      'diagnosis',
    ]) {
      expect(shouldRefreshDetail([event(1, kind)])).toBe(true)
    }
  })

  it('does not refresh on purely observational evidence events', () => {
    expect(shouldRefreshDetail([event(1, 'evidence_recorded')])).toBe(false)
    expect(shouldRefreshDetail([])).toBe(false)
  })
})
