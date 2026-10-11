import { useCallback, useEffect, useRef, useState } from 'react'
import type { ApiClient } from './api'
import { mergeEvents, shouldRefreshDetail } from './events'
import { formatTime, messageFromError } from './format'
import { openIncidentStream, type OpenStreamOptions, type StreamHandle } from './sse'
import type { TokenStore } from './token'
import type { DeploymentSnapshot, IncidentDetail, IncidentSummary, LiveEvent } from './types'
import { ApprovalPanel } from './components/ApprovalPanel'
import { DeploymentPanel } from './components/DeploymentPanel'
import { DiagnosisPanel } from './components/DiagnosisPanel'
import { EventTimeline } from './components/EventTimeline'
import { EvidencePanel } from './components/EvidencePanel'
import { IncidentQueue } from './components/IncidentQueue'
import { InvestigationTrace, diagnosisFrom } from './components/InvestigationTrace'
import { OperationPanel } from './components/OperationPanel'
import { ProposalPanel } from './components/ProposalPanel'
import { StatusBadge } from './components/StatusBadge'

export interface AppProps {
  client: ApiClient
  tokenStore: TokenStore
  now?: () => number
  streamFactory?: (options: OpenStreamOptions) => StreamHandle
}

export function App({
  client,
  tokenStore,
  now = Date.now,
  streamFactory = openIncidentStream,
}: AppProps) {
  const [token, setToken] = useState(tokenStore.get())
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [deployment, setDeployment] = useState<DeploymentSnapshot | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<IncidentDetail | null>(null)
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [queueLoading, setQueueLoading] = useState(false)
  const [queueError, setQueueError] = useState<string | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [actor, setActor] = useState('')
  const [alertSummary, setAlertSummary] = useState('')

  const liveDetailRef = useRef<IncidentDetail | null>(null)
  liveDetailRef.current = detail

  useEffect(() => tokenStore.subscribe(() => setToken(tokenStore.get())), [tokenStore])

  const loadDeployment = useCallback(async () => {
    try {
      setDeployment(await client.getDeployment())
    } catch {
      setDeployment(null)
    }
  }, [client])

  const loadQueue = useCallback(async () => {
    setQueueLoading(true)
    try {
      setIncidents(await client.listIncidents())
      setQueueError(null)
    } catch (error) {
      setQueueError(messageFromError(error))
    } finally {
      setQueueLoading(false)
    }
  }, [client])

  const loadDetail = useCallback(
    async (id: string) => {
      setDetailLoading(true)
      try {
        const next = await client.getIncident(id)
        setDetail(next)
        setEvents((prev) => mergeEvents(prev, next.events))
        setDetailError(null)
      } catch (error) {
        setDetailError(messageFromError(error))
      } finally {
        setDetailLoading(false)
      }
    },
    [client],
  )

  const refreshAll = useCallback(
    async (id: string) => {
      await Promise.all([loadDetail(id), loadQueue(), loadDeployment()])
    },
    [loadDetail, loadQueue, loadDeployment],
  )

  const handleEvent = useCallback(
    (id: string, event: LiveEvent) => {
      setEvents((prev) => mergeEvents(prev, [event]))
      if (shouldRefreshDetail([event])) {
        void refreshAll(id)
      }
    },
    [refreshAll],
  )

  useEffect(() => {
    void loadDeployment()
    void loadQueue()
  }, [loadDeployment, loadQueue])

  useEffect(() => {
    if (!selectedId) return
    setDetail(null)
    setEvents([])
    setDetailError(null)
    setActionError(null)
    setNotice(null)
    void loadDetail(selectedId)
    const handle = streamFactory({
      incidentId: selectedId,
      lastEventId: 0,
      onEvent: (event) => handleEvent(selectedId, event),
    })
    return () => handle.close()
  }, [selectedId, streamFactory, loadDetail, handleEvent])

  async function onApprove() {
    const current = liveDetailRef.current
    if (!current?.proposal) return
    setBusy(true)
    setActionError(null)
    try {
      await client.approve(current.id, current.proposal.digest, actor)
      await refreshAll(current.id)
      setNotice('Approval accepted; the worker will execute and verify the recovery.')
    } catch (error) {
      setActionError(messageFromError(error))
    } finally {
      setBusy(false)
    }
  }

  async function onReject() {
    const current = liveDetailRef.current
    if (!current) return
    setBusy(true)
    setActionError(null)
    try {
      await client.reject(current.id, {
        actor,
        proposal_digest: current.proposal?.digest,
      })
      await refreshAll(current.id)
      setNotice('Proposal rejected. No recovery action was executed.')
    } catch (error) {
      setActionError(messageFromError(error))
    } finally {
      setBusy(false)
    }
  }

  async function onInjectFault() {
    setBusy(true)
    setActionError(null)
    setNotice(null)
    try {
      const result = await client.injectFault()
      setNotice(`Demo fault injection: ${result.status}.`)
      await Promise.all([loadDeployment(), loadQueue()])
    } catch (error) {
      setActionError(messageFromError(error))
    } finally {
      setBusy(false)
    }
  }

  async function onCreateAlert() {
    if (!alertSummary.trim()) return
    setBusy(true)
    setActionError(null)
    setNotice(null)
    try {
      await client.createAlert({
        dedupe_key: `console-${Date.now()}`,
        summary: alertSummary.trim(),
      })
      setAlertSummary('')
      setNotice('Alert ingested and persisted; the worker will investigate.')
      await loadQueue()
    } catch (error) {
      setActionError(messageFromError(error))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>Incident Recovery Console</h1>
        <div className="token-control">
          <label htmlFor="operator-token">Operator token</label>
          <input
            id="operator-token"
            aria-label="Operator token"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={token}
            placeholder="paste operator token"
            onChange={(event) => tokenStore.set(event.target.value)}
          />
          <span className="muted">held in memory for this tab only — never stored</span>
        </div>
      </header>

      <main className="layout">
        <div className="col-left">
          <DeploymentPanel deployment={deployment} />
          <IncidentQueue
            incidents={incidents}
            selectedId={selectedId}
            onSelect={setSelectedId}
            loading={queueLoading}
            error={queueError}
            onRetry={() => void loadQueue()}
          />
          <section className="panel demo-controls" aria-label="Demo controls">
            <h2>Demo controls</h2>
            <p className="muted">
              Explicit demo fault injection and alert ingestion. There is no proposal-injection
              endpoint.
            </p>
            <div className="actions">
              <button type="button" onClick={onInjectFault} disabled={busy || !token}>
                Inject demo fault (broken-v2)
              </button>
            </div>
            <label htmlFor="alert-summary">New alert summary</label>
            <input
              id="alert-summary"
              value={alertSummary}
              onChange={(event) => setAlertSummary(event.target.value)}
              disabled={busy}
              placeholder="functional failure on demo-api"
            />
            <button
              type="button"
              onClick={onCreateAlert}
              disabled={busy || !token || alertSummary.trim() === ''}
            >
              Submit alert
            </button>
          </section>
        </div>

        <div className="col-right">
          {notice && (
            <p role="status" className="notice">
              {notice}
            </p>
          )}
          {actionError && !detail && (
            <p role="alert" className="error">
              {actionError}
            </p>
          )}
          {!selectedId && (
            <p className="muted">
              Select an incident to inspect its diagnosis, evidence, actual tool trace, recovery
              proposal, and verification.
            </p>
          )}
          {selectedId && detailLoading && !detail && <p className="muted">Loading incident…</p>}
          {selectedId && detailError && !detail && (
            <div role="alert" className="error">
              {detailError}
              <button type="button" onClick={() => void loadDetail(selectedId)}>
                Retry
              </button>
            </div>
          )}
          {detail && (
            <>
              <section className="panel incident-head" aria-label="Selected incident">
                <div className="panel-head">
                  <h2>{detail.id}</h2>
                  <StatusBadge state={detail.state} />
                </div>
                <p>{detail.summary ?? 'No summary.'}</p>
                <dl className="kv">
                  <dt>Service</dt>
                  <dd>{detail.service_id}</dd>
                  <dt>Detected</dt>
                  <dd>{formatTime(detail.detected_at)}</dd>
                  <dt>Updated</dt>
                  <dd>{formatTime(detail.updated_at)}</dd>
                </dl>
              </section>
              <InvestigationTrace investigation={detail.investigation} />
              <DiagnosisPanel diagnosis={diagnosisFrom(detail.investigation)} />
              <ProposalPanel proposal={detail.proposal} evidence={detail.evidence} />
              <ApprovalPanel
                state={detail.state}
                proposal={detail.proposal}
                approval={detail.approval}
                currentGeneration={deployment?.generation ?? null}
                now={now()}
                actor={actor}
                onActorChange={setActor}
                onApprove={onApprove}
                onReject={onReject}
                busy={busy}
                error={actionError}
              />
              <OperationPanel operation={detail.operation} verification={detail.verification} />
              <section className="panel" aria-label="Evidence">
                <h2>Evidence</h2>
                <EvidencePanel
                  evidence={detail.evidence}
                  highlightIds={detail.proposal?.evidence_ids ?? []}
                />
              </section>
              <section className="panel" aria-label="Timeline">
                <h2>Timeline</h2>
                <EventTimeline events={events} />
              </section>
            </>
          )}
        </div>
      </main>
    </div>
  )
}
