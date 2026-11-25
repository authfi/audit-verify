package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/authfi/audit-verify/verify"
)

// oneLeafBundle is a log holding one act, with the head that signs it, written to a file.
func oneLeafBundle(t *testing.T, change func(*verify.AccessBundle)) (string, verify.TreeHead) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := verify.AccessEntry{TenantSeq: 1, Salt: strings.Repeat("ab", 32), RecordedAt: "2026-11-25T10:00:00Z", Class: "staff_access",
		Action: "federation.session.opened", Actor: "fed:a:b", Resource: "federation_trust:t"}
	leaf := verify.AccessLeaf("log", "t1", e)
	e.LeafHash = hex.EncodeToString(verify.HashLeaf(leaf))
	root := hex.EncodeToString(verify.HashLeaf(leaf))
	ts := time.Now().UTC().Format(time.RFC3339)
	head := verify.TreeHead{LogID: "log", TreeSize: 1, RootHash: root, Timestamp: ts, KeyID: "k1", Algorithm: "Ed25519",
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, verify.TreeHeadMessage("log", 1, root, ts)))}
	b := verify.AccessBundle{Format: verify.AccessFormat, LogID: "log", TenantID: "t1", GeneratedAt: ts, Head: head,
		Entries: []verify.AccessEntry{e},
		Keys:    []verify.Key{{Kty: "OKP", Crv: "Ed25519", Kid: "k1", X: base64.RawURLEncoding.EncodeToString(pub), Use: verify.UseAccessTransparency}}}
	if change != nil {
		change(&b)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "access.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, head
}

func TestTheAccessCommandExitsByTheResult(t *testing.T) {
	var out, errOut bytes.Buffer
	good, head := oneLeafBundle(t, nil)
	heads := filepath.Join(t.TempDir(), "heads.ndjson")
	saved, _ := json.Marshal(head)
	if err := os.WriteFile(heads, []byte(string(saved)+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runAccessCommand([]string{"--bundle", good, "--heads", heads}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "saved heads:     1 proven") || !strings.Contains(out.String(), "result: PASS") {
		t.Fatalf("output: %s", out.String())
	}

	out.Reset()
	bad, _ := oneLeafBundle(t, func(b *verify.AccessBundle) { b.Entries[0].Actor = "someone else" })
	if code := runAccessCommand([]string{"--bundle", bad}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "FAILED") {
		t.Fatalf("exit %d: %s", code, out.String())
	}

	if code := runAccessCommand([]string{"--bundle", filepath.Join(t.TempDir(), "absent.json")}, &out, &errOut); code != 2 {
		t.Fatalf("a missing bundle exited %d", code)
	}
	if code := runAccessCommand(nil, &out, &errOut); code != 2 {
		t.Fatalf("no bundle exited %d", code)
	}
}

func TestReadTreeHeadsRefusesABadLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heads.ndjson")
	if err := os.WriteFile(path, []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTreeHeads(path); err == nil {
		t.Fatal("a bad line was accepted")
	}
}
