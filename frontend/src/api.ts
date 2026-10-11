import type {
  AlertAccepted,
  ApprovalResult,
  DeploymentSnapshot,
  FaultResult,
  IncidentDetail,
  IncidentSummary,
  RejectionResult,
} from './types'

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly detail: unknown

  constructor(status: number, code: string, detail: unknown) {
    super(`api_error_${status}:${code}`)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.detail = detail
  }
}

export interface ApiClient {
  listIncidents(): Promise<IncidentSummary[]>
  getIncident(id: string): Promise<IncidentDetail>
  getDeployment(): Promise<DeploymentSnapshot>
  createAlert(input: { dedupe_key: string; summary?: string }): Promise<AlertAccepted>
  injectFault(): Promise<FaultResult>
  approve(id: string, proposalDigest: string, actor: string): Promise<ApprovalResult>
  reject(
    id: string,
    input: { actor: string; reason?: string; proposal_digest?: string },
  ): Promise<RejectionResult>
}

export interface ClientOptions {
  baseUrl?: string
  token: () => string
  fetchFn?: typeof fetch
}

interface RequestOptions {
  method?: string
  body?: unknown
}

export function createClient(options: ClientOptions): ApiClient {
  const baseUrl = options.baseUrl ?? ''
  const tokenProvider = options.token
  const fetchFn = options.fetchFn ?? fetch

  async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
    const token = tokenProvider()
    if (token) headers.Authorization = `Bearer ${token}`

    const response = await fetchFn(`${baseUrl}${path}`, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    })

    if (!response.ok) {
      let detail: unknown = null
      try {
        const parsed = (await response.json()) as { detail?: unknown }
        detail = parsed.detail ?? parsed
      } catch {
        detail = null
      }
      const code =
        typeof detail === 'string'
          ? detail
          : detail && typeof detail === 'object' && 'error' in detail
            ? String((detail as { error: unknown }).error)
            : `http_${response.status}`
      throw new ApiError(response.status, code, detail)
    }
    return (await response.json()) as T
  }

  return {
    listIncidents: () => request<IncidentSummary[]>('/incidents'),
    getIncident: (id) => request<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`),
    getDeployment: () => request<DeploymentSnapshot>('/deployment'),
    createAlert: (input) =>
      request<AlertAccepted>('/alerts', {
        method: 'POST',
        body: { dedupe_key: input.dedupe_key, service_id: 'demo-api', summary: input.summary },
      }),
    injectFault: () =>
      request<FaultResult>('/demo/faults', {
        method: 'POST',
        body: { target_revision: 'broken-v2' },
      }),
    approve: (id, proposalDigest, actor) =>
      request<ApprovalResult>(`/incidents/${encodeURIComponent(id)}/approve`, {
        method: 'POST',
        body: { proposal_digest: proposalDigest, actor },
      }),
    reject: (id, input) =>
      request<RejectionResult>(`/incidents/${encodeURIComponent(id)}/reject`, {
        method: 'POST',
        body: {
          actor: input.actor,
          reason: input.reason,
          proposal_digest: input.proposal_digest,
        },
      }),
  }
}
