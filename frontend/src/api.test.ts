import { describe, expect, it, vi } from 'vitest'
import { ApiError, createClient } from './api'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('api client', () => {
  it('reads incidents without a token when none is set', async () => {
    const fetchFn = vi.fn(async () => jsonResponse([])) as unknown as typeof fetch
    const client = createClient({ token: () => '', fetchFn })
    await client.listIncidents()
    const [url, init] = (fetchFn as unknown as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(url).toBe('/incidents')
    expect((init.headers as Record<string, string>)?.Authorization).toBeUndefined()
  })

  it('binds approval to the exact digest and sends the bearer token', async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({ approval: {}, operation: {}, created: true }),
    ) as unknown as typeof fetch
    const client = createClient({ token: () => 'tok-123', fetchFn })
    await client.approve('incident-9', 'digest-abc', 'local-operator')
    const [url, init] = (fetchFn as unknown as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(url).toBe('/incidents/incident-9/approve')
    expect(init.method).toBe('POST')
    const body = JSON.parse(init.body as string)
    expect(body).toEqual({ proposal_digest: 'digest-abc', actor: 'local-operator' })
    expect(init.headers.Authorization).toBe('Bearer tok-123')
    expect(String(url)).not.toContain('tok-123')
  })

  it('maps a server refusal to a typed error code', async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({ detail: 'stale_approval' }, 409),
    ) as unknown as typeof fetch
    const client = createClient({ token: () => 'tok', fetchFn })
    await expect(client.approve('incident-9', 'old-digest', 'op')).rejects.toMatchObject({
      status: 409,
      code: 'stale_approval',
    })
    const error = await client.approve('incident-9', 'old-digest', 'op').catch((e) => e)
    expect(error).toBeInstanceOf(ApiError)
  })

  it('injects the fixed demo fault only', async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({ status: 'applied', snapshot: {}, reconciled: false }),
    ) as unknown as typeof fetch
    const client = createClient({ token: () => 'tok', fetchFn })
    await client.injectFault()
    const [, init] = (fetchFn as unknown as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(JSON.parse(init.body as string)).toEqual({ target_revision: 'broken-v2' })
  })
})
