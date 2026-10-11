import type { DiagnosisView } from '../types'

export function DiagnosisPanel({ diagnosis }: { diagnosis: DiagnosisView | null }) {
  return (
    <section className="panel" aria-label="Diagnosis">
      <h2>Diagnosis</h2>
      {!diagnosis ? (
        <p className="muted">No diagnosis recorded.</p>
      ) : (
        <>
          <h3>Symptoms</h3>
          <ul className="symptoms">
            {diagnosis.symptoms.map((symptom) => (
              <li key={symptom}>{symptom}</li>
            ))}
          </ul>
          <dl className="kv">
            <dt>Candidate cause</dt>
            <dd>{diagnosis.candidate_cause}</dd>
            <dt>Uncertainty</dt>
            <dd>{diagnosis.uncertainty}</dd>
            <dt>Proposed rollback</dt>
            <dd>{diagnosis.proposed_rollback ? 'yes' : 'no'}</dd>
          </dl>
          <h3>Evidence cited</h3>
          {diagnosis.evidence_ids.length === 0 ? (
            <p className="muted">No evidence cited.</p>
          ) : (
            <ul className="evidence-links">
              {diagnosis.evidence_ids.map((id) => (
                <li key={id}>
                  <a href={`#evidence-${id}`}>{id}</a>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  )
}
