import { formatTime } from '../format'
import type { IncidentSummary } from '../types'
import { StatusBadge } from './StatusBadge'

export interface IncidentQueueProps {
  incidents: IncidentSummary[]
  selectedId: string | null
  onSelect: (id: string) => void
  loading: boolean
  error: string | null
  onRetry: () => void
}

export function IncidentQueue({
  incidents,
  selectedId,
  onSelect,
  loading,
  error,
  onRetry,
}: IncidentQueueProps) {
  return (
    <section className="panel queue" aria-label="Incident queue">
      <div className="panel-head">
        <h2>Incidents</h2>
        <button type="button" onClick={onRetry} disabled={loading}>
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>
      {error && (
        <div role="alert" className="error">
          {error}
          <button type="button" onClick={onRetry}>
            Retry
          </button>
        </div>
      )}
      {incidents.length === 0 && !loading && !error && (
        <p className="muted empty">No incidents yet.</p>
      )}
      <ul className="queue-list">
        {incidents.map((incident) => (
          <li key={incident.id}>
            <button
              type="button"
              className={incident.id === selectedId ? 'incident selected' : 'incident'}
              aria-current={incident.id === selectedId}
              onClick={() => onSelect(incident.id)}
            >
              <span className="incident-id">{incident.id}</span>
              <StatusBadge state={incident.state} />
              <span className="muted incident-updated">
                updated {formatTime(incident.updated_at)}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  )
}
