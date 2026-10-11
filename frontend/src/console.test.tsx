import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AdapterBadge, adapterLabel } from './components/AdapterBadge'
import { EvidencePanel } from './components/EvidencePanel'
import { ProposalPanel } from './components/ProposalPanel'
import { approvalEligibility } from './components/ApprovalPanel'
import { App } from './App'
import { createTokenStore } from './token'
import type { ApiClient } from './api'
import type { OpenStreamOptions } from './sse'
import type {
  ApprovalView,
  EvidenceView,
  IncidentDetail,
  IncidentSummary,
  OperationView,
  ProposalView,
} from './types'

const NOW = Date.parse('2026-10-11T12:00:00Z')

function summary(overrides: Partial<IncidentSummary> = {}): IncidentSummary {
  return {
    id: 'incident-1',
    service_id: 'demo-api',
    state: 'awaiting_approval',
    summary: 'functional failure',
    detected_at: '2026-10-11T11:50:00Z',
    updated_at: '2026-10-11T11:55:00Z',
    version: 3,
    ...overrides,
  }
}

const proposal: ProposalView = {
  id: 'proposal-1',
  incident_id: 'incident-1',
  service_id: 'demo-api',
  expected_generation: 2,
  current_revision: 'broken-v2',
  target_revision: 'healthy-v1',
  evidence_ids: ['e1', 'e2'],
  digest: 'digest-abc',
  created_at: '2026-10-11T11:55:00Z',
}

function evidence(id: string): EvidenceView {
  return {
    id,
    incident_id: 'incident-1',
    source: 'tool:health',
    evidence_type: 'health_check',
    observed_at: '2026-10-11T11:54:00Z',
    payload: { functional_ok: false },
  }
}

function detail(overrides: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    ...summary(),
    evidence: [evidence('e1'), evidence('e2')],
    events: [],
    proposal,
    approval: null,
    operation: null,
    verification: null,
    investigation: {
      run: {
        incident_id: 'incident-1',
        epoch: 1,
        adapter: 'scripted:demo',
        state: 'decided',
        tool_calls: 2,
        started_at: '2026-10-11T11:52:00Z',
        deadline_at: '2026-10-11T11:54:00Z',
        updated_at: '2026-10-11T11:54:00Z',
        last_error: null,
      },
      steps: [
        {
          id: 1,
          epoch: 1,
          step_index: 1,
          kind: 'diagnosis',
          payload: {
            symptoms: ['5xx from demo-api'],
            candidate_cause: 'broken-v2 fault',
            uncertainty: 'low',
            evidence_ids: ['e1', 'e2'],
            proposed_rollback: true,
          },
          created_at: '2026-10-11T11:54:00Z',
        },
      ],
    },
    ...overrides,
  }
}

describe('adapter identity labels', () => {
  it('labels scripted and missing-credential adapters prominently', () => {
    expect(adapterLabel('scripted:demo').tone).toBe('scripted')
    expect(adapterLabel('scripted:demo').label).toMatch(/scripted/i)
    expect(adapterLabel('missing-credentials').tone).toBe('missing')
    expect(adapterLabel('missing-credentials').label).toMatch(/unavailable|missing/i)
    expect(adapterLabel('openai:gpt-4o').tone).toBe('live')
    expect(adapterLabel(null).tone).toBe('none')
  })

  it('renders the scripted identity and never claims it is live', () => {
    const { container } = render(<AdapterBadge adapter="scripted:demo" />)
    expect(screen.getAllByText(/scripted/i).length).toBeGreaterThan(0)
    expect(screen.queryByText(/live model adapter/i)).not.toBeInTheDocument()
    expect(container.textContent).toContain('scripted:demo')
  })
})

describe('evidence rendering', () => {
  it('renders untrusted payload as inert text', () => {
    const malicious: EvidenceView = {
      id: 'e9',
      incident_id: 'incident-1',
      source: 'tool:logs',
      evidence_type: 'log_excerpt',
      observed_at: '2026-10-11T11:54:00Z',
      payload: {
        lines: [{ message: '<img src=x onerror="window.__pwned=1">' }],
      },
    }
    const { container } = render(<EvidencePanel evidence={[malicious]} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
    expect(container.textContent).toContain('<img src=x onerror=')
    expect(container.querySelector('#evidence-e9')).not.toBeNull()
  })
})

describe('proposal evidence linking', () => {
  it('links every cited evidence id to its evidence record', () => {
    const { container } = render(
      <ProposalPanel proposal={proposal} evidence={[evidence('e1'), evidence('e2')]} />,
    )
    expect(container.querySelector('a[href="#evidence-e1"]')).not.toBeNull()
    expect(container.querySelector('a[href="#evidence-e2"]')).not.toBeNull()
    expect(screen.getByText('digest-abc')).toBeInTheDocument()
  })
})

describe('approval eligibility', () => {
  const base = {
    state: 'awaiting_approval' as const,
    proposal,
    approval: null,
    currentGeneration: 2,
    now: NOW,
  }

  it('allows approval for a current proposal', () => {
    expect(approvalEligibility(base).canApprove).toBe(true)
  })

  it('blocks a proposal whose generation is stale', () => {
    const result = approvalEligibility({ ...base, currentGeneration: 3 })
    expect(result.canApprove).toBe(false)
    expect(result.stale).toBe(true)
    expect(result.reason).toBe('stale_proposal')
  })

  it('blocks an expired approval TTL', () => {
    const expired: ApprovalView = {
      id: 'approval-1',
      incident_id: 'incident-1',
      proposal_id: 'proposal-1',
      proposal_digest: 'digest-abc',
      service_id: 'demo-api',
      expected_revision: 'broken-v2',
      target_revision: 'healthy-v1',
      actor: 'op',
      status: 'approved',
      created_at: '2026-10-11T11:50:00Z',
      expires_at: '2026-10-11T11:55:00Z',
      consumed_by_operation: null,
    }
    const result = approvalEligibility({ ...base, approval: expired })
    expect(result.canApprove).toBe(false)
    expect(result.expired).toBe(true)
  })

  it('blocks when the incident is not awaiting approval', () => {
    expect(approvalEligibility({ ...base, state: 'resolved' }).canApprove).toBe(false)
  })
})

function fakeClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    listIncidents: vi.fn(async () => [summary()]),
    getIncident: vi.fn(async () => detail()),
    getDeployment: vi.fn(async () => ({
      service_id: 'demo-api',
      revision: 'broken-v2',
      generation: 2,
      activated_at: '2026-10-11T11:40:00Z',
      predecessor: 'healthy-v1',
    })),
    createAlert: vi.fn(async () => ({
      id: 'incident-1',
      state: 'detected',
      service_id: 'demo-api',
      deduplicated: false,
    })),
    injectFault: vi.fn(async () => ({
      status: 'applied',
      snapshot: {
        service_id: 'demo-api',
        revision: 'broken-v2',
        generation: 2,
        activated_at: '2026-10-11T11:40:00Z',
        predecessor: 'healthy-v1',
      },
      reconciled: false,
    })),
    approve: vi.fn(async () => ({
      approval: {} as ApprovalView,
      operation: {} as OperationView,
      created: true,
    })),
    reject: vi.fn(async () => ({
      incident_id: 'incident-1',
      state: 'rejected',
      actor: 'op',
    })),
    ...overrides,
  } as ApiClient
}

function renderApp(
  client: ApiClient,
  streamFactory: (options: OpenStreamOptions) => { close: () => void } = () => ({
    close: () => {},
  }),
) {
  const tokenStore = createTokenStore()
  render(
    <App
      client={client}
      tokenStore={tokenStore}
      now={() => NOW}
      streamFactory={streamFactory}
    />,
  )
  return tokenStore
}

describe('console app', () => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  it('shows an empty state when there are no incidents', async () => {
    renderApp(fakeClient({ listIncidents: vi.fn(async () => []) }))
    expect(await screen.findByText(/no incidents yet/i)).toBeInTheDocument()
  })

  it('shows the incident queue with status and updated time, and deployment state', async () => {
    renderApp(fakeClient())
    expect(await screen.findByRole('button', { name: /incident-1/i })).toBeInTheDocument()
    expect(screen.getByText(/awaiting approval/i)).toBeInTheDocument()
    expect((await screen.findAllByText(/broken-v2/)).length).toBeGreaterThan(0)
  })

  it('keeps the operator token in memory only', async () => {
    const tokenStore = renderApp(fakeClient())
    const input = await screen.findByLabelText(/operator token/i)
    await userEvent.type(input, 'top-secret-token')
    expect(tokenStore.get()).toBe('top-secret-token')
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
    expect(document.body.textContent).not.toContain('top-secret-token')
  })

  it('approves the exact proposal digest and disables while in flight', async () => {
    let release: (() => void) | undefined
    const approve = vi.fn(
      () =>
        new Promise<never>((_resolve, _reject) => {
          release = () => {}
        }),
    )
    const client = fakeClient({ approve: approve as unknown as ApiClient['approve'] })
    renderApp(client)

    await userEvent.click(await screen.findByRole('button', { name: /incident-1/i }))
    await userEvent.type(await screen.findByLabelText(/approver/i), 'local-operator')

    const approveButton = await screen.findByRole('button', { name: /^approve$/i })
    await userEvent.click(approveButton)

    expect(approve).toHaveBeenCalledWith('incident-1', 'digest-abc', 'local-operator')
    await waitFor(() => expect(approveButton).toBeDisabled())
    release?.()
  })

  it('refreshes the detail when a relevant event arrives', async () => {
    let onEvent: OpenStreamOptions['onEvent'] | null = null
    const getIncident = vi.fn(async () => detail())
    const client = fakeClient({ getIncident })
    renderApp(client, (options) => {
      onEvent = options.onEvent
      return { close: () => {} }
    })

    await userEvent.click(await screen.findByRole('button', { name: /incident-1/i }))
    await waitFor(() => expect(getIncident).toHaveBeenCalledTimes(1))

    await act(async () => {
      onEvent?.({
        id: 10,
        incident_id: 'incident-1',
        kind: 'approved',
        payload: {},
        created_at: '2026-10-11T11:56:00Z',
      })
    })
    await waitFor(() => expect(getIncident).toHaveBeenCalledTimes(2))
  })

  it('shows an escalated, model-unavailable state', async () => {
    const escalated = detail({
      state: 'escalated',
      proposal: null,
      investigation: {
        run: {
          incident_id: 'incident-1',
          epoch: 1,
          adapter: 'missing-credentials',
          state: 'escalated',
          tool_calls: 0,
          started_at: '2026-10-11T11:52:00Z',
          deadline_at: '2026-10-11T11:54:00Z',
          updated_at: '2026-10-11T11:52:01Z',
          last_error: 'model_unavailable',
        },
        steps: [],
      },
    })
    const client = fakeClient({
      listIncidents: vi.fn(async () => [summary({ state: 'escalated' })]),
      getIncident: vi.fn(async () => escalated),
    })
    renderApp(client)
    await userEvent.click(await screen.findByRole('button', { name: /incident-1/i }))
    expect((await screen.findAllByText(/escalated/i)).length).toBeGreaterThan(0)
    expect(await screen.findByText(/model_unavailable/)).toBeInTheDocument()
  })
})
