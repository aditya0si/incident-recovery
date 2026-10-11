import { formatTime } from '../format'
import type { DeploymentSnapshot } from '../types'

export function DeploymentPanel({ deployment }: { deployment: DeploymentSnapshot | null }) {
  return (
    <section className="panel deployment" aria-label="Deployment">
      <h2>Active deployment</h2>
      {deployment ? (
        <dl className="kv">
          <dt>Service</dt>
          <dd>{deployment.service_id}</dd>
          <dt>Revision</dt>
          <dd>
            <span className="revision">{deployment.revision}</span>
          </dd>
          <dt>Generation</dt>
          <dd>{deployment.generation}</dd>
          <dt>Predecessor</dt>
          <dd>{deployment.predecessor ?? '—'}</dd>
          <dt>Activated</dt>
          <dd>{formatTime(deployment.activated_at)}</dd>
        </dl>
      ) : (
        <p className="muted">Deployment state unavailable.</p>
      )}
    </section>
  )
}
