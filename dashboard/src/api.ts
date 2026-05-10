import type { AnchorLatest, KeyList, MerkleHead } from "./types";

export const API_BASE =
  (import.meta as ImportMeta & { env: { VITE_API_BASE?: string } }).env.VITE_API_BASE ?? "http://localhost:8080";

export async function fetchMerkleHead(): Promise<MerkleHead> {
  const res = await fetch(`${API_BASE}/v1/merkle/head`);
  if (!res.ok) throw new Error(`merkle/head: ${res.status}`);
  return res.json();
}

export async function fetchAnchorLatest(): Promise<AnchorLatest | null> {
  const res = await fetch(`${API_BASE}/v1/anchor/latest`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`anchor/latest: ${res.status}`);
  return res.json();
}

export async function fetchAgents(): Promise<KeyList> {
  const res = await fetch(`${API_BASE}/v1/keys`);
  if (!res.ok) throw new Error(`keys: ${res.status}`);
  return res.json();
}

export function eventStreamURL(since = 0): string {
  return `${API_BASE}/v1/audit/events?since=${since}`;
}
