package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/authfi/audit-verify/verify"
)

func TestSavedHeadReadsAnExportAsItArrived(t *testing.T) {
	for name, tc := range map[string]struct {
		line string
		ok   bool
		seq  int64
	}{
		"an exported head": {`{"action":"audit.chain_head.signed","metadata":{"seq":7,"entry_hash":"h"}}`, true, 7},
		"a head alone":     {`{"seq":9,"entry_hash":"h"}`, true, 9},
		"another event":    {`{"action":"user.login","metadata":{"seq":3}}`, false, 0},
	} {
		h, ok, err := savedHead([]byte(tc.line))
		if err != nil || ok != tc.ok || h.Seq != tc.seq {
			t.Errorf("%s: head = %+v, ok = %v, err = %v", name, h, ok, err)
		}
	}
	if _, _, err := savedHead([]byte("not json")); err == nil {
		t.Error("a bad line was accepted")
	}
}

// bundleWith writes a chained tape of filler with the given governed calls near its start, and returns its path.
func bundleWith(t *testing.T, calls []verify.Entry) string {
	t.Helper()
	var entries []verify.Entry
	prev := ""
	add := func(e verify.Entry) {
		e.Seq, e.PrevHash, e.ID, e.RecordedAt = int64(len(entries)+1), prev, "id-"+strconv.Itoa(len(entries)+1), "2026-10-30T10:00:00Z"
		e.EntryHash = verify.EntryHash(e.PrevHash, e.ID, e.Actor, e.Action, e.Resource, e.RecordedAt, []byte(e.Metadata))
		prev = e.EntryHash
		entries = append(entries, e)
	}
	for _, c := range calls {
		add(c)
	}
	for i := 0; i < verify.ReceiptLag+5; i++ {
		add(verify.Entry{Actor: "user:a", Action: "user.login", Resource: "user:a", Metadata: "{}"})
	}
	raw, err := json.Marshal(verify.Bundle{Format: verify.Format, TenantID: "t1", Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The command reports the receipt counts from the verifier: a tape from before receipts is noted, and a call
// that names a receipt the bundle does not hold fails the run.
func TestRunReportsReceipts(t *testing.T) {
	call := func(meta string) verify.Entry {
		return verify.Entry{Actor: "agent:a", Action: verify.ActionToolCall, Resource: "mcp_tool:x", Metadata: meta}
	}
	before, err := run(bundleWith(t, []verify.Entry{call(`{"decision":"allow"}`)}), "", "")
	if err != nil || !before.OK || before.Calls != 1 || before.CallsBeforeReceipts != 1 {
		t.Fatalf("report = %+v, err = %v", before, err)
	}
	missing, err := run(bundleWith(t, []verify.Entry{call(`{"decision":"allow","receipt_id":"r1","request_id":"q"}`)}), "", "")
	if err != nil || missing.OK || missing.ReceiptsMissing != 1 {
		t.Fatalf("report = %+v, err = %v", missing, err)
	}
}

// The command prints every receipt count the verifier reports, so none is a number only a library user sees.
func TestTheReceiptCountsArePrinted(t *testing.T) {
	var out bytes.Buffer
	printReceipts(&out, verify.Report{Receipts: 3, Calls: 5, ReceiptsMissing: 1, CallsBeforeReceipts: 2, CallsAtEdge: 4,
		RefusedForWantOfReceipt: 6, DecisionsWithoutCall: 7})
	for _, want := range []string{"3 verified", "1 missing", "5 governed calls", "2 predate", "4 at the window edge", "6 refused for want of a receipt", "7 allowed decisions with no call record"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output lacks %q: %s", want, out.String())
		}
	}
	out.Reset()
	printReceipts(&out, verify.Report{})
	if out.Len() != 0 {
		t.Errorf("a tape with no governed call printed %q", out.String())
	}
}
