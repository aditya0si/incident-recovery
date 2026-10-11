import { formatTime } from '../format'
import type { OperationView, VerificationView } from '../types'

export interface OperationPanelProps {
  operation: OperationView | null
  verification: VerificationView | null
}

export function OperationPanel({ operation, verification }: OperationPanelProps) {
  return (
    <section className="panel" aria-label="Recovery operation">
      <h2>Recovery operation</h2>
      {!operation ? (
        <p className="muted">No recovery operation yet.</p>
      ) : (
        <>
          <dl className="kv">
            <dt>Status</dt>
            <dd>{operation.status}</dd>
            <dt>Target revision</dt>
            <dd>{operation.target_revision}</dd>
            <dt>Attempts</dt>
            <dd>{operation.attempts}</dd>
            <dt>Updated</dt>
            <dd>{formatTime(operation.updated_at)}</dd>
            {operation.verified_at && (
              <>
                <dt>Verified at</dt>
                <dd>{formatTime(operation.verified_at)}</dd>
              </>
            )}
            {operation.last_error && (
              <>
                <dt>Last error</dt>
                <dd className="warn">{operation.last_error}</dd>
              </>
            )}
          </dl>
          <p className="muted">
            <strong>Executed</strong> means the gateway switch was applied; <strong>Verified</strong>{' '}
            requires independent, sustained functional checks — an executor success alone never
            resolves the incident.
          </p>
        </>
      )}
      {verification ? (
        <div className="verification">
          <h3>Verification</h3>
          <p>
            {verification.status} · {verification.consecutive_successes}/{verification.required_streak}{' '}
            consecutive · {verification.checks} checks
          </p>
          {verification.detail && <p className="muted">{verification.detail}</p>}
        </div>
      ) : (
        operation && <p className="muted">Not yet independently verified.</p>
      )}
    </section>
  )
}
