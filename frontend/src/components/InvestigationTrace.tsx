import { formatTime } from '../format'
import type { DiagnosisView, InvestigationView } from '../types'
import { AdapterBadge } from './AdapterBadge'

export function diagnosisFrom(investigation: InvestigationView | null): DiagnosisView | null {
  if (!investigation) return null
  for (let i = investigation.steps.length - 1; i >= 0; i -= 1) {
    const step = investigation.steps[i]
    if (step.kind === 'diagnosis') return step.payload as unknown as DiagnosisView
  }
  return null
}

export function InvestigationTrace({ investigation }: { investigation: InvestigationView | null }) {
  if (!investigation || !investigation.run) {
    return (
      <section className="panel" aria-label="Investigation">
        <h2>Investigation</h2>
        <p className="muted">No investigation recorded.</p>
      </section>
    )
  }
  const run = investigation.run
  return (
    <section className="panel" aria-label="Investigation">
      <h2>Investigation</h2>
      <AdapterBadge adapter={run.adapter} />
      <p className="muted">
        epoch {run.epoch} · {run.tool_calls} tool calls · run state {run.state}
        {run.last_error ? ` · last error ${run.last_error}` : ''}
      </p>
      <p className="muted">
        started {formatTime(run.started_at)} · deadline {formatTime(run.deadline_at)}
      </p>
      {investigation.steps.length === 0 ? (
        <p className="muted">No bounded steps recorded.</p>
      ) : (
        <ol className="steps">
          {investigation.steps.map((step) => (
            <li key={step.id} className="step">
              <span className="step-kind">{step.kind}</span>
              <span className="muted"> {formatTime(step.created_at)}</span>
              <pre className="payload" tabIndex={0}>
                {JSON.stringify(step.payload)}
              </pre>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}
