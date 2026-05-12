import { useEffect, useRef, useState } from "react";
import { eventStreamURL } from "../api";
import type { AuditEvent } from "../types";

interface State {
  events: AuditEvent[];
  connected: boolean;
  error: string | null;
}

const MAX_EVENTS = 500;

// useAuditStream subscribes to /v1/audit/events and accumulates the
// last MAX_EVENTS records (oldest dropped first). Reconnects with
// `since=lastSeq+1` so a brief network blip doesn't lose history.
export function useAuditStream(): State {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastSeqRef = useRef<number>(-1);

  useEffect(() => {
    let cancelled = false;
    let es: EventSource | null = null;
    let backoffMs = 500;

    const connect = () => {
      if (cancelled) return;
      const since = lastSeqRef.current >= 0 ? lastSeqRef.current + 1 : 0;
      es = new EventSource(eventStreamURL(since));
      es.onopen = () => {
        if (cancelled) return;
        setConnected(true);
        setError(null);
        backoffMs = 500;
      };
      es.onmessage = (msg) => {
        if (cancelled) return;
        try {
          const ev = JSON.parse(msg.data) as AuditEvent;
          if (ev.seq <= lastSeqRef.current) return; // dedup on reconnect
          lastSeqRef.current = ev.seq;
          setError(null);
          setEvents((prev) => {
            const next = prev.length >= MAX_EVENTS ? prev.slice(prev.length - MAX_EVENTS + 1) : prev.slice();
            next.push(ev);
            return next;
          });
        } catch (e) {
          setError(`parse: ${(e as Error).message}`);
        }
      };
      es.onerror = () => {
        if (cancelled) return;
        setConnected(false);
        setError("event stream connection lost");
        es?.close();
        const wait = backoffMs;
        backoffMs = Math.min(backoffMs * 2, 8000);
        setTimeout(connect, wait);
      };
    };

    connect();
    return () => {
      cancelled = true;
      es?.close();
    };
  }, []);

  return { events, connected, error };
}
