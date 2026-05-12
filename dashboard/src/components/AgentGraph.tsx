import { useMemo } from "react";
import { ReactFlow, Background, Controls, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { AuditEvent } from "../types";

interface Props {
  events: AuditEvent[];
  knownAgents: string[];
}

// A small palette to colour edges by action_type. Hashed mod palette
// keeps colors stable across renders without us having to plumb a
// shared map through.
const PALETTE = ["#38bdf8", "#a78bfa", "#fbbf24", "#34d399", "#f472b6", "#f87171"];

function colorForActionType(t: string): string {
  let h = 0;
  for (let i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) >>> 0;
  return PALETTE[h % PALETTE.length];
}

function edgeKey(agent: string, actionType: string, target: string): string {
  return JSON.stringify([agent, actionType, target]);
}

// Build {nodes, edges} from the event stream. Each agent that appears
// is a node; each (agent, action_type, target) tuple is an edge from
// the agent to the target. Rejected events get a red overlay.
function deriveGraph(events: AuditEvent[], knownAgents: string[]): { nodes: Node[]; edges: Edge[] } {
  const agents = new Set(knownAgents);
  const targets = new Set<string>();
  const edgeMap = new Map<string, { count: number; rejected: number; actionType: string }>();

  for (const ev of events) {
    const agent = ev.kind === "appended" ? ev.action.agent_id : (ev.agent_id ?? ev.action?.agent_id);
    const actionType = ev.kind === "appended" ? ev.action.action_type : (ev.action_type ?? ev.action?.action_type);
    const target = ev.kind === "appended" ? ev.action.target : (ev.target ?? ev.action?.target);
    if (!agent || !actionType || !target) continue;
    agents.add(agent);
    targets.add(target);
    const key = edgeKey(agent, actionType, target);
    const cur = edgeMap.get(key) ?? { count: 0, rejected: 0, actionType };
    cur.count++;
    if (ev.kind === "rejected") cur.rejected++;
    edgeMap.set(key, cur);
  }

  // Layout: agents on the left column, targets on the right, evenly
  // spaced. React Flow handles drag, so this only matters at first paint.
  const agentList = Array.from(agents).sort();
  const targetList = Array.from(targets).sort();
  const nodes: Node[] = [];
  agentList.forEach((id, i) => {
    nodes.push({
      id: `agent:${id}`,
      type: "default",
      position: { x: 0, y: i * 70 },
      data: { label: id },
      style: { background: "#1e293b", color: "#e2e8f0", border: "1px solid #334155", fontSize: 12 },
    });
  });
  targetList.forEach((t, i) => {
    nodes.push({
      id: `target:${t}`,
      type: "default",
      position: { x: 360, y: i * 70 },
      data: { label: t },
      style: {
        background: "#0f172a",
        color: "#94a3b8",
        border: "1px dashed #475569",
        fontSize: 12,
      },
    });
  });

  const edges: Edge[] = [];
  for (const [key, info] of edgeMap.entries()) {
    const [agent, actionType, target] = JSON.parse(key) as [string, string, string];
    const allRejected = info.rejected > 0 && info.rejected === info.count;
    const someRejected = info.rejected > 0 && !allRejected;
    const stroke = allRejected ? "#ef4444" : colorForActionType(actionType);
    edges.push({
      id: key,
      source: `agent:${agent}`,
      target: `target:${target}`,
      label: `${actionType}${info.count > 1 ? ` ×${info.count}` : ""}${someRejected ? ` (${info.rejected} rejected)` : ""}`,
      labelStyle: { fill: "#cbd5e1", fontSize: 10 },
      labelBgStyle: { fill: "#0f172a" },
      style: {
        stroke,
        strokeWidth: 2,
        strokeDasharray: allRejected ? "4 4" : undefined,
      },
      animated: someRejected,
    });
  }

  return { nodes, edges };
}

export function AgentGraph({ events, knownAgents }: Props) {
  const { nodes, edges } = useMemo(() => deriveGraph(events, knownAgents), [events, knownAgents]);

  return (
    <div className="flex h-full flex-col p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">
        Agent interaction graph
      </h2>
      <div className="flex-1 overflow-hidden rounded border border-slate-800">
        {nodes.length === 0 ? (
          <div className="flex h-full items-center justify-center p-4 text-sm text-slate-500">
            No interactions yet. Once agents submit signed actions, they'll appear here as edges to their targets.
          </div>
        ) : (
          <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
            <Background color="#334155" gap={20} />
            <Controls className="!bg-slate-900 !text-slate-100" />
          </ReactFlow>
        )}
      </div>
    </div>
  );
}
