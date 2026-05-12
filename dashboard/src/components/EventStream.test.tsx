import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { EventStream } from "./EventStream";
import type { AuditEvent } from "../types";

const appended: AuditEvent = {
  seq: 0,
  kind: "appended",
  leaf_index: 0,
  leaf_hash: "abcdef0123456789",
  action: {
    schema_version: 1,
    agent_id: "alice",
    action_type: "transfer_funds",
    target: "treasury",
    timestamp: 1_700_000_000_000,
    nonce: "0".repeat(32),
  },
  signature: "11".repeat(64),
  public_key: "22".repeat(32),
  recorded_at: "2025-01-01T00:00:00Z",
};

const rejected: AuditEvent = {
  seq: 1,
  kind: "rejected",
  agent_id: "alice",
  action_type: "transfer_funds",
  target: "treasury",
  reason: "action_type_not_allowed",
  recorded_at: "2025-01-01T00:00:01Z",
};

describe("EventStream", () => {
  it("renders appended events with leaf index badge", () => {
    render(<EventStream events={[appended]} anchor={null} connected={true} />);
    expect(screen.getByText("#0")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("transfer_funds")).toBeInTheDocument();
  });

  it("flags ACL denials distinctly from generic rejections", () => {
    const genericRejected: AuditEvent = {
      ...rejected,
      seq: 2,
      reason: "invalid_signature",
    };
    render(<EventStream events={[rejected, genericRejected]} anchor={null} connected={true} />);
    expect(screen.getByText("ACL")).toBeInTheDocument();
    expect(screen.getByText("ACL: action denied")).toBeInTheDocument();
    expect(screen.getByText("REJECT")).toBeInTheDocument();
    expect(screen.getByText("Invalid signature")).toBeInTheDocument();
  });

  it("shows anchor badge when anchor is set", () => {
    render(
      <EventStream
        events={[]}
        anchor={{ id: 42, tree_size: 100, root_hex: "0xabc", timestamp_ms: Date.now(), block_number: 12345 }}
        connected={true}
      />,
    );
    expect(screen.getByText(/anchor #42/)).toBeInTheDocument();
    expect(screen.getByText(/block 12345/)).toBeInTheDocument();
  });
});
