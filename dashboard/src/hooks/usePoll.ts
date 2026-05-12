import { useEffect, useRef, useState } from "react";

interface State<T> {
  data: T | null;
  error: string | null;
}

// usePoll fetches once on mount and then every `intervalMs`. Errors are
// surfaced but do not clear the last successful value, so the dashboard
// keeps showing stale data with an indicator instead of going blank.
export function usePoll<T>(fetcher: () => Promise<T>, intervalMs: number): State<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fetcherRef = useRef(fetcher);

  useEffect(() => {
    fetcherRef.current = fetcher;
  }, [fetcher]);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const v = await fetcherRef.current();
        if (!cancelled) {
          setData(v);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    };
    tick();
    const id = window.setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [intervalMs]);

  return { data, error };
}
