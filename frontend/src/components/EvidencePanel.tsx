import { formatTime } from '../format'
import type { EvidenceView } from '../types'

export interface EvidencePanelProps {
  evidence: EvidenceView[]
  highlightIds?: string[]
}

export function EvidencePanel({ evidence, highlightIds = [] }: EvidencePanelProps) {
  if (evidence.length === 0) {
    return <p className="muted">No evidence recorded yet.</p>
  }
  return (
    <ul className="evidence-list">
      {evidence.map((item) => (
        <li
          key={item.id}
          id={`evidence-${item.id}`}
          className={highlightIds.includes(item.id) ? 'evidence highlight' : 'evidence'}
        >
          <div className="evidence-head">
            <span className="source">{item.source}</span>
            <span className="muted">
              {item.evidence_type} · {formatTime(item.observed_at)}
            </span>
          </div>
          <code className="evidence-id">{item.id}</code>
          <pre className="payload" tabIndex={0}>
            {JSON.stringify(item.payload, null, 2)}
          </pre>
        </li>
      ))}
    </ul>
  )
}
