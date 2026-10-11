import { formatTime } from '../format'
import type { ApprovalView, IncidentState, ProposalView } from '../types'

export interface ApprovalEligibilityInput {
  state: IncidentState
  proposal: ProposalView | null
  approval: ApprovalView | null
  currentGeneration: number | null
  now: number
}

export interface ApprovalEligibility {
  canApprove: boolean
  reason: string | null
  expired: boolean
  stale: boolean
  consumed: boolean
}

const REASON_TEXT: Record<string, string> = {
  no_proposal: 'No proposal is available to approve.',
  already_approved: 'This proposal has already been approved and consumed.',
  approval_expired: 'The approval window for this proposal has expired.',
  stale_proposal: 'The deployment changed since this proposal; it is stale.',
}

export function approvalEligibility(input: ApprovalEligibilityInput): ApprovalEligibility {
  const { state, proposal, approval, currentGeneration, now } = input
  if (!proposal) {
    return { canApprove: false, reason: 'no_proposal', expired: false, stale: false, consumed: false }
  }
  const consumed = Boolean(approval?.consumed_by_operation)
  const expired = Boolean(approval && Date.parse(approval.expires_at) <= now)
  const stale = currentGeneration !== null && proposal.expected_generation !== currentGeneration
  if (state !== 'awaiting_approval') {
    return { canApprove: false, reason: `state_${state}`, expired, stale, consumed }
  }
  if (consumed) return { canApprove: false, reason: 'already_approved', expired, stale, consumed }
  if (expired) return { canApprove: false, reason: 'approval_expired', expired, stale, consumed }
  if (stale) return { canApprove: false, reason: 'stale_proposal', expired, stale, consumed }
  return { canApprove: true, reason: null, expired, stale, consumed }
}

export interface ApprovalPanelProps extends ApprovalEligibilityInput {
  actor: string
  onActorChange: (value: string) => void
  onApprove: () => void
  onReject: () => void
  busy: boolean
  error: string | null
}

export function ApprovalPanel({
  state,
  proposal,
  approval,
  currentGeneration,
  now,
  actor,
  onActorChange,
  onApprove,
  onReject,
  busy,
  error,
}: ApprovalPanelProps) {
  const eligibility = approvalEligibility({ state, proposal, approval, currentGeneration, now })
  const reasonText =
    eligibility.reason && REASON_TEXT[eligibility.reason]
      ? REASON_TEXT[eligibility.reason]
      : eligibility.reason && !eligibility.canApprove
        ? `Approval is unavailable (${eligibility.reason}).`
        : null

  return (
    <section className="panel approval" aria-label="Approval">
      <h2>Approval</h2>
      <label htmlFor="approver">Approver</label>
      <input
        id="approver"
        aria-label="Approver"
        type="text"
        value={actor}
        placeholder="operator name"
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => onActorChange(event.target.value)}
        disabled={busy}
      />
      {approval && (
        <p className="muted">
          Approval {approval.status} · expires {formatTime(approval.expires_at)}
          {eligibility.expired && <span className="warn"> · expired</span>}
        </p>
      )}
      <div className="actions">
        <button
          type="button"
          onClick={onApprove}
          disabled={!eligibility.canApprove || busy || actor.trim() === ''}
        >
          {busy ? 'Approving…' : 'Approve'}
        </button>
        <button
          type="button"
          className="secondary"
          onClick={onReject}
          disabled={!proposal || busy || actor.trim() === ''}
        >
          Reject
        </button>
      </div>
      {reasonText && <p className="warn">{reasonText}</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <p className="muted">
        Approval binds the exact proposal digest; the server re-validates the generation and the
        five-minute TTL.
      </p>
    </section>
  )
}
