import type { AnchorLatest, KeyList, MerkleHead } from "./types";

export const API_BASE =
  (import.meta as ImportMeta & { env: { VITE_API_BASE?: string } }).env.VITE_API_BASE ?? "http://localhost:8080";

const REQUEST_TIMEOUT_MS = 10_000;

async function fetchWithTimeout(url: string, errorPrefix: string): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { signal: controller.signal });
  } catch (e) {
    if (e instanceof Error && e.name === "AbortError") {
      throw new Error(`${errorPrefix}: request timeout`);
    }
    throw e;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

async function parseJSON<T>(res: Response, errorPrefix: string): Promise<T> {
  try {
    return (await res.json()) as T;
  } catch {
    throw new Error(`${errorPrefix}: invalid JSON response`);
  }
}

async function fetchJSON<T>(url: string, errorPrefix: string): Promise<T> {
  const res = await fetchWithTimeout(url, errorPrefix);
  if (!res.ok) throw new Error(`${errorPrefix}: ${res.status}`);
  return parseJSON<T>(res, errorPrefix);
}

export async function fetchMerkleHead(): Promise<MerkleHead> {
  return fetchJSON<MerkleHead>(`${API_BASE}/v1/merkle/head`, "merkle/head");
}

export async function fetchAnchorLatest(): Promise<AnchorLatest | null> {
  const res = await fetchWithTimeout(`${API_BASE}/v1/anchor/latest`, "anchor/latest");
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`anchor/latest: ${res.status}`);
  return parseJSON<AnchorLatest>(res, "anchor/latest");
}

export async function fetchAgents(): Promise<KeyList> {
  return fetchJSON<KeyList>(`${API_BASE}/v1/keys`, "keys");
}

export function eventStreamURL(since = 0): string {
  const params = new URLSearchParams({ since: String(since) });
  return `${API_BASE}/v1/audit/events?${params}`;
}
