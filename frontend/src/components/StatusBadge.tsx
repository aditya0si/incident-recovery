import { stateLabel } from '../format'

export function StatusBadge({ state }: { state: string }) {
  return <span className={`badge status status-${state}`}>{stateLabel(state)}</span>
}
