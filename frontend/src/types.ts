export type IncidentState =
  | 'detected'
  | 'investigating'
  | 'awaiting_approval'
  | 'recovering'
  | 'verifying'
  | 'resolved'
  | 'escalated'
  | 'rejected'
  | 'recovery_failed'

export interface IncidentSummary {
  id: string
  service_id: string
  state: IncidentState
  summary: string | null
  detected_at: string
  updated_at: string
  version: number
}

export interface EvidenceView {
  id: string
  incident_id: string
  source: string
  evidence_type: string
  observed_at: string
  payload: Record<string, unknown>
}

export interface LiveEvent {
  id: number
  incident_id: string
  kind: string
  payload: Record<string, unknown>
  created_at: string
}

export interface ProposalView {
  id: string
  incident_id: string
  service_id: string
  expected_generation: number
  current_revision: string
  target_revision: string
  evidence_ids: string[]
  digest: string
  created_at: string
}

export interface ApprovalView {
  id: string
  incident_id: string
  proposal_id: string
  proposal_digest: string
  service_id: string
  expected_revision: string
  target_revision: string
  actor: string
  status: string
  created_at: string
  expires_at: string
  consumed_by_operation: string | null
}

export interface OperationView {
  id: string
  incident_id: string
  approval_id: string | null
  status: string
  target_revision: string
  result: Record<string, unknown> | null
  created_at: string
  updated_at: string
  service_id: string | null
  expected_generation: number | null
  attempts: number
  last_error: string | null
  verified_at: string | null
}

export interface VerificationView {
  status: string
  target_revision: string
  checks: number
  consecutive_successes: number
  required_streak: number
  started_at: string | null
  finished_at: string | null
  detail: string | null
}

export interface InvestigationRunView {
  incident_id: string
  epoch: number
  adapter: string
  state: string
  tool_calls: number
  started_at: string
  deadline_at: string
  updated_at: string
  last_error: string | null
}

export interface InvestigationStepView {
  id: number
  epoch: number
  step_index: number
  kind: string
  payload: Record<string, unknown>
  created_at: string
}

export interface InvestigationView {
  run: InvestigationRunView | null
  steps: InvestigationStepView[]
}

export interface IncidentDetail extends IncidentSummary {
  evidence: EvidenceView[]
  events: LiveEvent[]
  proposal: ProposalView | null
  approval: ApprovalView | null
  operation: OperationView | null
  verification: VerificationView | null
  investigation: InvestigationView | null
}

export interface DeploymentSnapshot {
  service_id: string
  revision: string
  generation: number
  activated_at: string
  predecessor: string | null
}

export interface AlertAccepted {
  id: string
  state: string
  service_id: string
  deduplicated: boolean
}

export interface FaultResult {
  status: string
  snapshot: DeploymentSnapshot
  reconciled: boolean
}

export interface ApprovalResult {
  approval: ApprovalView
  operation: OperationView
  created: boolean
}

export interface RejectionResult {
  incident_id: string
  state: string
  actor: string
}

export interface DiagnosisView {
  symptoms: string[]
  candidate_cause: string
  uncertainty: string
  evidence_ids: string[]
  proposed_rollback: boolean
}
