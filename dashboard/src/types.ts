// Wire types matching go-key-service/internal/auditlog/pipeline.go
// MarshalJSON. Keep in sync if the Go side changes.

export type EventKind = "appended" | "rejected";

export interface ActionMessage {
  schema_version: number;
  agent_id: string;
  action_type: string;
  target: string;
  timestamp: number;
  nonce: string;
}

export interface AppendedEvent {
  seq: number;
  kind: "appended";
  leaf_index: number;
  leaf_hash: string; // hex (no 0x prefix)
  action: ActionMessage;
  signature: string; // hex
  public_key: string; // hex
  recorded_at: string; // RFC3339
}

export interface RejectedEvent {
  seq: number;
  kind: "rejected";
  action?: ActionMessage;
  agent_id?: string;
  action_type?: string;
  target?: string;
  reason: string;
  recorded_at: string;
}

export type AuditEvent = AppendedEvent | RejectedEvent;

export interface MerkleHead {
  size: number;
  root_hex: string; // 0x-prefixed
}

export interface AnchorLatest {
  id: number;
  tree_size: number;
  root_hex: string; // 0x-prefixed
  timestamp_ms: number;
  block_number?: number;
  tx_hash?: string;
}

export interface KeyList {
  agent_ids: string[];
}
