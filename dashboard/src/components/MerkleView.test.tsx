import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MerkleView } from "./MerkleView";
import type { AppendedEvent } from "../types";

function makeAppended(seq: number, agent: string): AppendedEvent {
  return {
    seq,
    kind: "appended",
    leaf_index: seq,
    leaf_hash: `${seq.toString().padStart(2, "0")}cafebabe`,
    action: {
      schema_version: 1,
      agent_id: agent,
      action_type: "ping",
      target: "peer",
      timestamp: 0,
      nonce: "0".repeat(32),
    },
    signature: "0".repeat(128),
    public_key: "0".repeat(64),
    recorded_at: new Date().toISOString(),
  };
}

describe("MerkleView", () => {
  it("renders the live root, tree size, and last leaves", () => {
    const events = Array.from({ length: 3 }, (_, i) => makeAppended(i, "alice"));
    render(
      <MerkleView
        head={{ size: 3, root_hex: "0xdeadbeefcafebabe1234" }}
        anchor={null}
        events={events}
      />,
    );
    expect(screen.getByText(/0xdeadbeef…babe1234/)).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText(/no anchor yet/)).toBeInTheDocument();
    expect(screen.getByText(/Last 3 leaves/)).toBeInTheDocument();
  });

  it("hides rejected events from the leaves panel", () => {
    const events: AppendedEvent[] = [makeAppended(0, "alice")];
    const withReject = [
      ...events,
      {
        seq: 1,
        kind: "rejected" as const,
        agent_id: "mallory",
        reason: "invalid_signature",
        recorded_at: new Date().toISOString(),
      },
    ];
    render(
      <MerkleView head={{ size: 1, root_hex: "0xabc" }} anchor={null} events={withReject} />,
    );
    expect(screen.getByText(/Last 1 leaves/)).toBeInTheDocument();
  });
});
