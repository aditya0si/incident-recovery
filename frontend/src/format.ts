import { ApiError } from './api'

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return String(iso)
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
}

export function stateLabel(state: string): string {
  const words = state.split('_').join(' ')
  return words.charAt(0).toUpperCase() + words.slice(1)
}

const REFUSAL_MESSAGES: Record<string, string> = {
  stale_approval: 'Refused: the deployment changed since this proposal (stale_approval).',
  deployment_reserved: 'Refused: a recovery already owns the deployment.',
  invalid_state: 'Refused: the incident is no longer awaiting approval.',
  proposal_not_found: 'Refused: the proposal no longer exists.',
  unauthorized: 'Refused: missing or invalid operator token.',
  origin_not_allowed: 'Refused: request origin is not allowed.',
  pending_recovery: 'Refused: a recovery is pending.',
  switch_stale: 'Refused: the deployment generation changed.',
  switch_conflict: 'Refused: conflicting deployment operation.',
  switch_unauthorized: 'Refused: switch not authorized.',
}

export function messageFromError(error: unknown): string {
  if (error instanceof ApiError) {
    return REFUSAL_MESSAGES[error.code] ?? `Request failed (${error.status} ${error.code}).`
  }
  return error instanceof Error ? error.message : 'Unexpected error.'
}
