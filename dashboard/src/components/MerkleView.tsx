import type { AnchorLatest, AppendedEvent, AuditEvent, MerkleHead } from "../types";

interface Props {
  head: MerkleHead | null;
  anchor: AnchorLatest | null;
  events: AuditEvent[];
}

// Truncates 0xabc...def from a hex string. Works on both raw hex
// (64 chars) and 0x-prefixed (66 chars).
function truncHash(h: string, head = 6, tail = 4): string {
  if (h.length <= head + tail + 1) return h;
  return `${h.slice(0, head)}…${h.slice(-tail)}`;
}

function formatRelative(ms: number): string {
  if (!Number.isFinite(ms)) return "unknown";
  const dt = Date.now() - ms;
  if (dt < 0) return "in the future";
  if (dt < 1000) return "just now";
  if (dt < 60_000) return `${Math.floor(dt / 1000)}s ago`;
  if (dt < 3_600_000) return `${Math.floor(dt / 60_000)}m ago`;
  if (dt < 86_400_000) return `${Math.floor(dt / 3_600_000)}h ago`;
  return `${Math.floor(dt / 86_400_000)}d ago`;
}

export function MerkleView({ head, anchor, events }: Props) {
  const appended = events.filter((e): e is AppendedEvent => e.kind === "appended");
  const lastLeaves = appended.slice(-16).reverse();

  return (
    <div className="flex h-full flex-col gap-3 overflow-hidden p-4">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Merkle audit log</h2>

      <div className="grid grid-cols-2 gap-3">
        <Tile label="Live root" mono>
          {head ? truncHash(head.root_hex, 10, 8) : "—"}
        </Tile>
        <Tile label="Tree size">{head?.size.toLocaleString() ?? "—"}</Tile>
        <Tile label="Last anchor" mono>
          {anchor ? truncHash(anchor.root_hex, 10, 8) : "no anchor yet"}
        </Tile>
        <Tile label="Anchor block">
          {anchor?.block_number != null ? `#${anchor.block_number.toLocaleString()}` : anchor ? "dry-run" : "—"}
          {anchor && (
            <span className="ml-2 text-xs text-slate-400">
              size {anchor.tree_size} · {formatRelative(anchor.timestamp_ms)}
            </span>
          )}
        </Tile>
      </div>

      <div className="flex flex-1 flex-col overflow-hidden rounded border border-slate-800 bg-slate-900/40">
        <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
          Last {lastLeaves.length} leaves
        </div>
        <div className="scrollbar-thin flex-1 overflow-auto">
          {lastLeaves.length === 0 ? (
            <div className="p-4 text-sm text-slate-500">No leaves yet — submit a signed action to populate.</div>
          ) : (
            <ul className="divide-y divide-slate-800">
              {lastLeaves.map((ev) => (
                <li key={ev.seq} className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
                  <span className="font-mono text-slate-500">#{ev.leaf_index}</span>
                  <span className="font-mono text-slate-300">{truncHash(ev.leaf_hash, 8, 6)}</span>
                  <span className="flex-1 truncate text-slate-400">
                    {ev.action.agent_id} → {ev.action.action_type}
                  </span>
                  <span className="text-slate-500">{formatRelative(Date.parse(ev.recorded_at))}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

function Tile({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-900/40 px-3 py-2">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-1 truncate text-sm text-slate-100 ${mono ? "font-mono" : ""}`}>{children}</div>
    </div>
  );
}
