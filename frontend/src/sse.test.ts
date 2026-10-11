import { describe, expect, it, vi } from 'vitest'
import { buildStreamUrl, createSseParser, openIncidentStream } from './sse'
import type { LiveEvent } from './events'

describe('SSE frame parser', () => {
  it('parses frames split across arbitrary chunk boundaries', () => {
    const parser = createSseParser()
    expect(parser.push('id: 1\nda')).toEqual([])
    const frames = parser.push('ta: {"kind":"a"}\n\nid: 2\ndata: {"kind":"b"}\n\n')
    expect(frames).toEqual([
      { id: 1, data: '{"kind":"a"}' },
      { id: 2, data: '{"kind":"b"}' },
    ])
  })

  it('joins multi-line data and ignores comments', () => {
    const parser = createSseParser()
    const frames = parser.push(': keep-alive\nid: 7\ndata: line1\ndata: line2\n\n')
    expect(frames).toEqual([{ id: 7, data: 'line1\nline2' }])
  })

  it('handles CRLF and missing ids', () => {
    const parser = createSseParser()
    const frames = parser.push('data: {"kind":"x"}\r\n\r\n')
    expect(frames).toEqual([{ id: null, data: '{"kind":"x"}' }])
  })
})

describe('stream url', () => {
  it('carries the last event id and never a token', () => {
    expect(buildStreamUrl('/incidents/abc/events', 42)).toBe(
      '/incidents/abc/events?last_event_id=42',
    )
    expect(buildStreamUrl('/x/events', 0)).toBe('/x/events?last_event_id=0')
    expect(buildStreamUrl('/x/events', 0)).not.toContain('token')
  })
})

function frame(event: LiveEvent): string {
  return `id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`
}

function streamOf(...chunks: string[]) {
  const encoder = new TextEncoder()
  let index = 0
  return {
    getReader() {
      return {
        async read() {
          if (index >= chunks.length) return { done: true, value: undefined }
          const value = encoder.encode(chunks[index++])
          return { done: false, value }
        },
        async cancel() {},
      }
    },
  }
}

function makeEvent(id: number): LiveEvent {
  return {
    id,
    incident_id: 'incident-1',
    kind: 'state_changed',
    payload: {},
    created_at: new Date(id).toISOString(),
  }
}

describe('reconnecting incident stream', () => {
  it('backfills from the last seen id after the connection ends', async () => {
    const urls: string[] = []
    const received: number[] = []
    let handle: { close: () => void } | null = null

    const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
      urls.push(String(input))
      if (urls.length === 1) {
        return { ok: true, body: streamOf(frame(makeEvent(1))) } as unknown as Response
      }
      return {
        ok: true,
        body: streamOf(frame(makeEvent(2))),
      } as unknown as Response
    }) as unknown as typeof fetch

    await new Promise<void>((resolve) => {
      handle = openIncidentStream({
        incidentId: 'incident-1',
        lastEventId: 0,
        fetchFn,
        reconnectDelayMs: 1,
        onEvent: (event) => {
          received.push(event.id)
          if (event.id === 2) {
            handle?.close()
            resolve()
          }
        },
      })
    })

    expect(received).toEqual([1, 2])
    expect(urls[0]).toContain('last_event_id=0')
    expect(urls[1]).toContain('last_event_id=1')
  })
})
