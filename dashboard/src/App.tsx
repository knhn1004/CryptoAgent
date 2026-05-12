import { useCallback } from "react";
import { fetchAgents, fetchAnchorLatest, fetchMerkleHead } from "./api";
import { MerkleView } from "./components/MerkleView";
import { AgentGraph } from "./components/AgentGraph";
import { EventStream } from "./components/EventStream";
import { useAuditStream } from "./hooks/useAuditStream";
import { usePoll } from "./hooks/usePoll";
import type { AnchorLatest, KeyList, MerkleHead } from "./types";

export default function App() {
  const stream = useAuditStream();

  const headFetcher = useCallback((): Promise<MerkleHead> => fetchMerkleHead(), []);
  const anchorFetcher = useCallback((): Promise<AnchorLatest | null> => fetchAnchorLatest(), []);
  const agentsFetcher = useCallback((): Promise<KeyList> => fetchAgents(), []);

  const head = usePoll<MerkleHead>(headFetcher, 5_000);
  const anchor = usePoll<AnchorLatest | null>(anchorFetcher, 10_000);
  const agents = usePoll<KeyList>(agentsFetcher, 30_000);

  return (
    <div className="flex h-screen flex-col">
      <header className="flex items-center justify-between gap-4 border-b border-slate-800 bg-slate-900/60 px-4 py-2">
        <div className="flex items-center gap-3">
          <span className="font-mono text-sm font-semibold text-slate-100">CryptoAgent</span>
          <span className="text-xs text-slate-500">audit dashboard</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-slate-400">
          <Stat label="schema" value="v1" mono />
          <Stat label="tree" value={head.data ? head.data.size.toLocaleString() : "—"} />
          <Stat
            label="root"
            value={head.data ? head.data.root_hex.slice(0, 10) + "…" : "—"}
            mono
            title={head.data?.root_hex}
          />
        </div>
      </header>
      <main className="grid flex-1 grid-cols-2 grid-rows-[1fr_minmax(0,260px)] overflow-hidden">
        <section className="overflow-hidden border-r border-b border-slate-800">
          <MerkleView head={head.data} anchor={anchor.data ?? null} events={stream.events} />
        </section>
        <section className="overflow-hidden border-b border-slate-800">
          <AgentGraph events={stream.events} knownAgents={agents.data?.agent_ids ?? []} />
        </section>
        <section className="col-span-2 overflow-hidden">
          <EventStream events={stream.events} anchor={anchor.data ?? null} connected={stream.connected} />
        </section>
      </main>
    </div>
  );
}

function Stat({
  label,
  value,
  mono,
  title,
}: {
  label: string;
  value: string;
  mono?: boolean;
  title?: string;
}) {
  return (
    <span className="flex items-baseline gap-1.5" title={title}>
      <span className="text-[10px] uppercase tracking-wider text-slate-500">{label}</span>
      <span className={`text-slate-100 ${mono ? "font-mono" : ""}`}>{value}</span>
    </span>
  );
}
