import type { LiveEvent } from './events'

export interface SseFrame {
  id: number | null
  data: string
}

export interface SseParser {
  push(chunk: string): SseFrame[]
}

/**
 * Minimal SSE parser. It tolerates arbitrary chunk boundaries (including CRLF
 * split across chunks), joins multi-line `data:` fields, ignores comments, and
 * never lets a malformed frame throw into the reader loop.
 */
export function createSseParser(): SseParser {
  let buffer = ''
  return {
    push(chunk: string): SseFrame[] {
      buffer += chunk
      const parts = buffer.split(/\r?\n\r?\n/)
      buffer = parts.pop() ?? ''
      const frames: SseFrame[] = []
      for (const part of parts) {
        let id: number | null = null
        const dataLines: string[] = []
        for (const line of part.split(/\r?\n/)) {
          if (line === '' || line.startsWith(':')) continue
          const colon = line.indexOf(':')
          const field = colon === -1 ? line : line.slice(0, colon)
          let value = colon === -1 ? '' : line.slice(colon + 1)
          if (value.startsWith(' ')) value = value.slice(1)
          if (field === 'id') {
            const parsed = Number.parseInt(value, 10)
            if (!Number.isNaN(parsed)) id = parsed
          } else if (field === 'data') {
            dataLines.push(value)
          }
        }
        if (dataLines.length > 0) frames.push({ id, data: dataLines.join('\n') })
      }
      return frames
    },
  }
}

export function buildStreamUrl(eventsPath: string, lastEventId: number): string {
  const separator = eventsPath.includes('?') ? '&' : '?'
  return `${eventsPath}${separator}last_event_id=${lastEventId}`
}

export interface StreamHandle {
  close(): void
}

export interface OpenStreamOptions {
  incidentId: string
  lastEventId?: number
  fetchFn?: typeof fetch
  reconnectDelayMs?: number
  onEvent: (event: LiveEvent) => void
  onError?: (error: unknown) => void
}

/**
 * Stream an incident's events, reconnecting with the last seen id so a dropped
 * connection resumes without gaps. The token is never placed in the URL; the SSE
 * read endpoint is read-only and anonymous, and writes carry the token in an
 * Authorization header elsewhere.
 */
export function openIncidentStream(options: OpenStreamOptions): StreamHandle {
  const {
    incidentId,
    lastEventId = 0,
    fetchFn = fetch,
    reconnectDelayMs = 1000,
    onEvent,
    onError,
  } = options
  const eventsPath = incidentId.startsWith('/') ? incidentId : `/incidents/${incidentId}/events`

  let closed = false
  let currentId = lastEventId
  let controller: AbortController | null = null

  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

  async function connect(): Promise<void> {
    while (!closed) {
      controller = new AbortController()
      try {
        const response = await fetchFn(buildStreamUrl(eventsPath, currentId), {
          signal: controller.signal,
          headers: { Accept: 'text/event-stream' },
        })
        if (!response.ok || !response.body) {
          throw new Error(`sse_status_${response.status}`)
        }
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        const parser = createSseParser()
        while (!closed) {
          const { done, value } = await reader.read()
          if (done) break
          const frames = parser.push(decoder.decode(value, { stream: true }))
          for (const frame of frames) {
            if (frame.id !== null && frame.id > currentId) currentId = frame.id
            try {
              onEvent(JSON.parse(frame.data) as LiveEvent)
            } catch (error) {
              onError?.(error)
            }
            if (closed) break
          }
        }
      } catch (error) {
        if (!closed) onError?.(error)
      }
      if (closed) break
      await sleep(reconnectDelayMs)
    }
  }

  void connect()

  return {
    close() {
      closed = true
      controller?.abort()
    },
  }
}
