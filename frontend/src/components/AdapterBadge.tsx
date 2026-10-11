export type AdapterTone = 'scripted' | 'missing' | 'live' | 'none'

export interface AdapterIdentity {
  label: string
  tone: AdapterTone
  detail: string
}

/**
 * Surface the recorded adapter identity verbatim. A scripted run is never shown
 * as live inference, and a missing runtime model is never disguised.
 */
export function adapterLabel(adapter: string | null | undefined): AdapterIdentity {
  if (!adapter) {
    return {
      label: 'No investigation run',
      tone: 'none',
      detail: 'No investigation has been recorded for this incident.',
    }
  }
  if (adapter.startsWith('scripted')) {
    return {
      label: 'Scripted demo adapter',
      tone: 'scripted',
      detail: `${adapter} — deterministic script, not live model inference.`,
    }
  }
  if (adapter === 'missing-credentials' || adapter.startsWith('missing')) {
    return {
      label: 'Runtime model unavailable',
      tone: 'missing',
      detail: `${adapter} — the investigation escalated instead of substituting a script.`,
    }
  }
  return {
    label: 'Live model adapter',
    tone: 'live',
    detail: `${adapter} — live model inference.`,
  }
}

export function AdapterBadge({ adapter }: { adapter: string | null | undefined }) {
  const identity = adapterLabel(adapter)
  return (
    <span className={`badge adapter adapter-${identity.tone}`} title={identity.detail}>
      {identity.label}
      <span className="adapter-raw"> ({adapter ?? 'none'})</span>
    </span>
  )
}
