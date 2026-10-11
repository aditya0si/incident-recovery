import type { EvidenceView, ProposalView } from '../types'

export interface ProposalPanelProps {
  proposal: ProposalView | null
  evidence: EvidenceView[]
}

export function ProposalPanel({ proposal, evidence }: ProposalPanelProps) {
  if (!proposal) {
    return (
      <section className="panel" aria-label="Recovery proposal">
        <h2>Recovery proposal</h2>
        <p className="muted">No recovery proposal yet.</p>
      </section>
    )
  }
  const known = new Set(evidence.map((item) => item.id))
  return (
    <section className="panel" aria-label="Recovery proposal">
      <h2>Recovery proposal</h2>
      <dl className="kv">
        <dt>Current revision</dt>
        <dd>{proposal.current_revision}</dd>
        <dt>Target revision</dt>
        <dd>{proposal.target_revision}</dd>
        <dt>Expected generation</dt>
        <dd>{proposal.expected_generation}</dd>
        <dt>Digest</dt>
        <dd>
          <code>{proposal.digest}</code>
        </dd>
      </dl>
      <h3>Cited evidence</h3>
      {proposal.evidence_ids.length === 0 ? (
        <p className="muted">No evidence cited.</p>
      ) : (
        <ul className="evidence-links">
          {proposal.evidence_ids.map((id) => (
            <li key={id}>
              <a href={`#evidence-${id}`}>{id}</a>
              {!known.has(id) && <span className="warn"> (not found)</span>}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
