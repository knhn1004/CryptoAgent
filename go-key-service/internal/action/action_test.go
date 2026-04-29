package action

import "testing"

func sample() Action {
	return Action{
		SchemaVersion: 1,
		AgentID:       "agent-001",
		ActionType:    "ping",
		Target:        "peer-002",
		TimestampMs:   1700000000000,
		Nonce:         "0123456789abcdef0123456789abcdef",
	}
}

func TestCanonicalReferenceVector(t *testing.T) {
	a := sample()
	want := `{"action_type":"ping","agent_id":"agent-001","nonce":"0123456789abcdef0123456789abcdef","schema_version":1,"target":"peer-002","timestamp":1700000000000}`
	got, err := a.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if string(got) != want {
		t.Fatalf("canonical mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestCanonicalDeterministic(t *testing.T) {
	a := sample()
	first, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		again, err := a.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(again) {
			t.Fatalf("non-deterministic encoding")
		}
	}
}

func TestValidateRejectsBadNonce(t *testing.T) {
	cases := map[string]string{
		"too_short":  "deadbeef",
		"upper_hex":  "0123456789ABCDEF0123456789abcdef",
		"non_hex":    "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		"with_space": "0123456789abcdef0123456789abcde ",
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			a := sample()
			a.Nonce = n
			if err := a.Validate(); err == nil {
				t.Fatalf("expected ErrNonceShape, got nil")
			}
		})
	}
}

func TestValidateRejectsWrongSchemaVersion(t *testing.T) {
	a := sample()
	a.SchemaVersion = 2
	if err := a.Validate(); err == nil {
		t.Fatal("expected ErrSchemaVersion")
	}
}

func TestValidateRejectsEmptyFields(t *testing.T) {
	for _, mut := range []func(*Action){
		func(a *Action) { a.AgentID = "" },
		func(a *Action) { a.ActionType = "" },
		func(a *Action) { a.Target = "" },
	} {
		a := sample()
		mut(&a)
		if err := a.Validate(); err == nil {
			t.Fatal("expected ErrEmptyField")
		}
	}
}
