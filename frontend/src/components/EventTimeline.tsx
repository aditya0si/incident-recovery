import { formatTime } from '../format'
import type { LiveEvent } from '../types'

export function EventTimeline({ events }: { events: LiveEvent[] }) {
  if (events.length === 0) {
    return <p className="muted">No events yet.</p>
  }
  return (
    <ol className="events">
      {events.map((event) => (
        <li key={event.id} className="event">
          <span className="event-kind">{event.kind}</span>{' '}
          <span className="muted">
            #{event.id} · {formatTime(event.created_at)}
          </span>
        </li>
      ))}
    </ol>
  )
}
