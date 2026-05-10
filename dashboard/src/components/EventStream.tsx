import type { AnchorLatest, AuditEvent } from "../types";

interface Props {
  events: AuditEvent[];
  anchor: AnchorLatest | null;
  connected: boolean;
}

const REASON_LABELS: Record<string, string> = {
  invalid_signature: "Invalid signature",
  unknown_agent: "Unknown agent",
  timestamp_skew: "Timestamp skew",
  schema_version: "Bad schema version",
  invalid_action: "Invalid action",
  invalid_nonce: "Invalid nonce",
  malformed_token: "Malformed token",
  expired: "Token expired",
  revoked: "Token revoked",
  agent_mismatch: "Agent mismatch",
  action_type_not_allowed: "ACL: action denied",
  target_not_allowed: "ACL: target denied",
};

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function isACLDenial(reason: string): boolean {
  return reason === "action_type_not_allowed" || reason === "target_not_allowed" || reason === "agent_mismatch";
}

export function EventStream({ events, anchor, connected }: Props) {
  const ordered = events.slice().reverse();

  return (
    <div className="flex h-full flex-col overflow-hidden p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Live event stream</h2>
        <div className="flex items-center gap-3 text-xs">
          {anchor && (
            <span
              className="rounded bg-emerald-900/40 px-2 py-0.5 font-mono text-emerald-300"
              title={`Anchor #${anchor.id}, root ${anchor.root_hex}`}
            >
              ⚓ anchor #{anchor.id}
              {anchor.block_number ? ` · block ${anchor.block_number}` : " · dry-run"}
            </span>
          )}
          <span
            className={`flex items-center gap-1 ${connected ? "text-emerald-400" : "text-amber-400"}`}
            title={connected ? "SSE connected" : "Reconnecting…"}
          >
            <span
              className={`inline-block h-2 w-2 rounded-full ${connected ? "bg-emerald-400" : "bg-amber-400 animate-pulse"}`}
            />
            {connected ? "live" : "reconnecting"}
          </span>
        </div>
      </div>
      <div className="scrollbar-thin flex-1 overflow-auto rounded border border-slate-800 bg-slate-900/40">
        {ordered.length === 0 ? (
          <div className="p-4 text-sm text-slate-500">Waiting for events…</div>
        ) : (
          <ul className="divide-y divide-slate-800">
            {ordered.map((ev) => (
              <li key={ev.seq}>
                <EventRow ev={ev} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function EventRow({ ev }: { ev: AuditEvent }) {
  if (ev.kind === "appended") {
    return (
      <div className="grid grid-cols-[auto_auto_1fr_auto] items-center gap-3 border-l-2 border-emerald-500/60 px-3 py-1.5 text-xs">
        <span className="font-mono text-slate-500">{fmtTime(ev.recorded_at)}</span>
        <span className="rounded bg-emerald-900/40 px-1.5 py-0.5 font-mono text-emerald-300">#{ev.leaf_index}</span>
        <span className="truncate">
          <span className="font-semibold text-slate-200">{ev.action.agent_id}</span>
          <span className="text-slate-500"> → </span>
          <span className="text-slate-300">{ev.action.action_type}</span>
          <span className="text-slate-500">/{ev.action.target}</span>
        </span>
        <span className="font-mono text-slate-500">{ev.leaf_hash.slice(0, 8)}…</span>
      </div>
    );
  }
  const acl = isACLDenial(ev.reason);
  const label = REASON_LABELS[ev.reason] ?? ev.reason;
  const agent = ev.agent_id ?? ev.action?.agent_id ?? "—";
  const actionType = ev.action_type ?? ev.action?.action_type;
  const target = ev.target ?? ev.action?.target;
  return (
    <div
      className={`grid grid-cols-[auto_auto_1fr_auto] items-center gap-3 border-l-2 px-3 py-1.5 text-xs ${
        acl ? "border-amber-500/70 bg-amber-900/10" : "border-rose-500/70 bg-rose-900/10"
      }`}
    >
      <span className="font-mono text-slate-500">{fmtTime(ev.recorded_at)}</span>
      <span
        className={`rounded px-1.5 py-0.5 font-mono ${
          acl ? "bg-amber-900/40 text-amber-300" : "bg-rose-900/40 text-rose-300"
        }`}
      >
        {acl ? "ACL" : "REJECT"}
      </span>
      <span className="truncate">
        <span className="font-semibold text-slate-200">{agent}</span>
        {actionType && (
          <>
            <span className="text-slate-500"> → </span>
            <span className="text-slate-300">{actionType}</span>
          </>
        )}
        {target && <span className="text-slate-500">/{target}</span>}
      </span>
      <span className={acl ? "text-amber-300" : "text-rose-300"}>{label}</span>
    </div>
  );
}
