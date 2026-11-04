package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

const otherTenant = "22222222-2222-2222-2222-222222222222"

// spec is one tape entry before it is chained.
type spec struct {
	action, actor, resource string
	meta                    map[string]any
}

// world is a tenant's tape the way the gateway and the audit writer make it: filler, then two governed calls
// (an allow with its outcome and a deny), each with its decision receipt, then filler. Every test starts from
// a world that passes and breaks one thing.
type world struct {
	t       *testing.T
	head    signer // the audit_head key
	rk      signer // the receipt key
	from    int64
	prev    string
	specs   []spec
	keys    []Key
	iat     int64
	dA, cA  int // indexes of the allow's decision entry and its call
	dB, cB  int
	options Options
}

func merge(base map[string]any, over map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// jws signs header.payload with s the way kms does.
func (s signer) jws(header, payload map[string]any) string {
	in := b64(header) + "." + b64(payload)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, []byte(in)))
}

func (w *world) header(over map[string]any) map[string]any {
	return merge(map[string]any{"alg": "EdDSA", "typ": ReceiptType, "kid": w.rk.kid}, over)
}

func (w *world) claims(over map[string]any) map[string]any {
	return merge(map[string]any{"v": 1, "tid": testTenant, "iat": w.iat}, over)
}

func (w *world) receipt(over map[string]any) string {
	return w.rk.jws(w.header(nil), w.claims(over))
}

func newWorld(t *testing.T, before, after int, from int64) *world {
	t.Helper()
	return newWorldAt(t, before, after, from, time.Now().Unix())
}

func newWorldAt(t *testing.T, before, after int, from, iat int64) *world {
	t.Helper()
	w := &world{t: t, head: newSigner(t), rk: newSigner(t), from: from, iat: iat}
	w.rk.kid = "rk-1"
	if from > 1 {
		w.prev = "older"
	}
	w.keys = []Key{
		{Kty: "OKP", Crv: "Ed25519", Kid: w.head.kid, X: base64.RawURLEncoding.EncodeToString(w.head.pub), Status: "active", Use: UseAuditHead},
		{Kty: "OKP", Crv: "Ed25519", Kid: w.rk.kid, X: base64.RawURLEncoding.EncodeToString(w.rk.pub), Status: "active", Use: UseReceipt},
	}
	filler := func(n int) {
		for i := 0; i < n; i++ {
			w.specs = append(w.specs, spec{"user.login", "user:alice", "user:alice", map[string]any{"ip": "10.0.0.1"}})
		}
	}
	filler(before)
	decA := w.receipt(map[string]any{"rid": "rcpt-A", "ph": "decision", "req": "req-A", "verdict": "allow", "agent": "agent-1", "tool": "send_email"})
	outA := w.receipt(map[string]any{"rid": "rcpt-A-out", "ph": "outcome", "drid": "rcpt-A", "req": "req-A", "agent": "agent-1", "tool": "send_email", "out": "ok"})
	decB := w.receipt(map[string]any{"rid": "rcpt-B", "ph": "decision", "req": "req-B", "verdict": "deny", "agent": "agent-1", "tool": "wire_money"})
	w.dA = len(w.specs)
	w.specs = append(w.specs, spec{ActionDecisionReceipt, "agent:agent-1", "mcp_tool:send_email", map[string]any{"receipt": decA}})
	w.cA = len(w.specs)
	w.specs = append(w.specs, spec{ActionToolCall, "agent:agent-1", "mcp_tool:send_email", map[string]any{
		"decision": "allow", "request_id": "req-A", "receipt_id": "rcpt-A", "outcome": "ok", "receipt": outA}})
	w.dB = len(w.specs)
	w.specs = append(w.specs, spec{ActionDecisionReceipt, "agent:agent-1", "mcp_tool:wire_money", map[string]any{"receipt": decB}})
	w.cB = len(w.specs)
	w.specs = append(w.specs, spec{ActionToolCall, "agent:agent-1", "mcp_tool:wire_money", map[string]any{
		"decision": "deny", "request_id": "req-B", "receipt_id": "rcpt-B"}})
	filler(after)
	return w
}

func defaultWorld(t *testing.T) *world { return newWorld(t, 120, 120, 1) }

// meta sets or (with nil) removes members of an entry's metadata.
func (w *world) meta(i int, over map[string]any) { w.specs[i].meta = merge(w.specs[i].meta, over) }

func (w *world) remove(i int) {
	w.specs = append(w.specs[:i:i], w.specs[i+1:]...)
	for _, p := range []*int{&w.dA, &w.cA, &w.dB, &w.cB} {
		if *p > i {
			*p--
		}
	}
}

// bundle chains the entries and signs a head over the last one.
func (w *world) bundle() Bundle {
	prev := w.prev
	entries := make([]Entry, 0, len(w.specs))
	for i, s := range w.specs {
		meta, _ := json.Marshal(s.meta)
		seq := w.from + int64(i)
		e := Entry{Seq: seq, PrevHash: prev, ID: "id-" + strconv.FormatInt(seq, 10), Actor: s.actor, Action: s.action,
			Resource: s.resource, RecordedAt: "2026-10-30T10:00:00.123456Z", Metadata: string(meta)}
		e.EntryHash = EntryHash(e.PrevHash, e.ID, e.Actor, e.Action, e.Resource, e.RecordedAt, meta)
		prev = e.EntryHash
		entries = append(entries, e)
	}
	last := entries[len(entries)-1]
	return Bundle{Format: Format, TenantID: testTenant, Entries: entries, Keys: w.keys,
		Heads: []Head{w.head.head(testTenant, last.Seq, last.EntryHash)}}
}

func (w *world) verify() Report { return Verify(w.bundle(), w.options) }

func TestAReceiptedTapePasses(t *testing.T) {
	w := defaultWorld(t)
	r := w.verify()
	if !r.OK {
		t.Fatalf("failures: %q", r.Failures)
	}
	if r.Receipts != 3 || r.Calls != 2 || r.ReceiptsMissing != 0 || r.CallsBeforeReceipts != 0 || r.CallsAtEdge != 0 {
		t.Errorf("report = %+v", r)
	}
}

// flipPayload changes one byte of the payload segment of a compact receipt, leaving the signature as it was.
func flipPayload(compact string) string {
	parts := strings.Split(compact, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	raw[len(raw)/2] ^= 0x01
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

// Each case breaks exactly one thing in a tape that otherwise passes, and names what must be said about it.
func TestABrokenReceiptFails(t *testing.T) {
	headSigner := func(w *world) signer { s := w.head; return s }
	cases := []struct {
		name    string
		break_  func(w *world)
		want    string
		missing int
	}{
		{"flipped payload byte", func(w *world) {
			w.meta(w.dA, map[string]any{"receipt": flipPayload(w.specs[w.dA].meta["receipt"].(string))})
		}, "does not verify", 1},
		{"signed by an audit_head key", func(w *world) {
			w.rk = headSigner(w)
			w.meta(w.dA, map[string]any{"receipt": w.receipt(map[string]any{"rid": "rcpt-A", "ph": "decision", "req": "req-A",
				"verdict": "allow", "agent": "agent-1", "tool": "send_email"})})
		}, "may not sign a receipt", 1},
		{"a receipt of tenant B", func(w *world) {
			w.meta(w.dA, map[string]any{"receipt": w.receipt(map[string]any{"tid": otherTenant, "rid": "rcpt-A", "ph": "decision",
				"req": "req-A", "verdict": "allow", "agent": "agent-1", "tool": "send_email"})})
		}, "for tenant", 1},
		{"typ of an agent configuration", func(w *world) {
			c := w.claims(map[string]any{"rid": "rcpt-A", "ph": "decision", "req": "req-A", "verdict": "allow", "agent": "agent-1", "tool": "send_email"})
			w.meta(w.dA, map[string]any{"receipt": w.rk.jws(w.header(map[string]any{"typ": "authfi-agent-config+jwt"}), c)})
		}, "its typ is", 1},
		{"alg none", func(w *world) {
			c := w.claims(map[string]any{"rid": "rcpt-A", "ph": "decision", "req": "req-A", "verdict": "allow", "agent": "agent-1", "tool": "send_email"})
			w.meta(w.dA, map[string]any{"receipt": b64(w.header(map[string]any{"alg": "none"})) + "." + b64(c) + "."})
		}, "only EdDSA", 1},
		{"a critical extension", func(w *world) {
			c := w.claims(map[string]any{"rid": "rcpt-A", "ph": "decision", "req": "req-A", "verdict": "allow", "agent": "agent-1", "tool": "send_email"})
			w.meta(w.dA, map[string]any{"receipt": w.rk.jws(w.header(map[string]any{"crit": []string{"x"}}), c)})
		}, "critical", 1},
		{"not a compact JWS", func(w *world) { w.meta(w.dA, map[string]any{"receipt": "abc"}) }, "not a compact JWS", 1},
		{"a receipt that is not a string", func(w *world) { w.meta(w.dA, map[string]any{"receipt": 7}) }, "not a receipt", 1},
		{"no issue time", func(w *world) {
			w.meta(w.dA, map[string]any{"receipt": w.receipt(map[string]any{"iat": 0, "rid": "rcpt-A", "ph": "decision", "req": "req-A",
				"verdict": "allow", "agent": "agent-1", "tool": "send_email"})})
		}, "no usable time", 1},
		{"no receipt id", func(w *world) {
			w.meta(w.dA, map[string]any{"receipt": w.receipt(map[string]any{"rid": "", "ph": "decision", "req": "req-A",
				"verdict": "allow", "agent": "agent-1", "tool": "send_email"})})
		}, "no receipt id", 1},
		{"a rule receipt named as a call's decision", func(w *world) {
			w.meta(w.dB, map[string]any{"receipt": w.receipt(map[string]any{"rid": "rcpt-B", "ph": "rule", "req": "req-B",
				"verdict": "deny", "agent": "agent-1", "tool": "wire_money"})})
		}, "receipt missing", 1},
		{"revoked key", func(w *world) { w.keys[1].Status = "disabled" }, "revoked", 1},
		{"unknown key id", func(w *world) { w.keys = w.keys[:1] }, "not in the bundle", 1},
		{"a key with no use is an audit_head key", func(w *world) { w.keys[1].Use = "" }, "may not sign a receipt", 1},
		{"unknown version", func(w *world) {
			w.meta(w.dA, map[string]any{"receipt": w.receipt(map[string]any{"v": 2, "rid": "rcpt-A", "ph": "decision", "req": "req-A",
				"verdict": "allow", "agent": "agent-1", "tool": "send_email"})})
		}, "version 2", 1},
		{"removed receipt entry", func(w *world) { w.remove(w.dA) }, "receipt missing", 1},
		{"every receipt entry removed", func(w *world) { w.remove(w.dB); w.remove(w.dA) }, "receipt missing", 2},
		{"duplicate receipt id with other bytes", func(w *world) {
			other := w.receipt(map[string]any{"rid": "rcpt-B", "ph": "rule", "verdict": "hold"})
			w.specs = append(w.specs, spec{ActionDecisionReceipt, "agent:agent-1", "mcp_tool:wire_money", map[string]any{"receipt": other}})
		}, "two different receipts", 0},
		{"outcome receipt with the wrong decision", func(w *world) {
			w.meta(w.cA, map[string]any{"receipt": w.receipt(map[string]any{"rid": "rcpt-A-out", "ph": "outcome", "drid": "rcpt-OTHER",
				"req": "req-A", "agent": "agent-1", "tool": "send_email", "out": "ok"})})
		}, "belongs to decision", 0},
		{"an outcome receipt for another request", func(w *world) {
			w.meta(w.cA, map[string]any{"receipt": w.receipt(map[string]any{"rid": "rcpt-A-out", "ph": "outcome", "drid": "rcpt-A",
				"req": "req-Z", "agent": "agent-1", "tool": "send_email", "out": "ok"})})
		}, "outcome receipt is not for this call", 0},
		{"an outcome receipt for another tool", func(w *world) {
			w.meta(w.cA, map[string]any{"receipt": w.receipt(map[string]any{"rid": "rcpt-A-out", "ph": "outcome", "drid": "rcpt-A",
				"req": "req-A", "agent": "agent-1", "tool": "wire_money", "out": "ok"})})
		}, "outcome receipt is not for this call", 0},
		{"outcome the tape does not record", func(w *world) {
			w.meta(w.cA, map[string]any{"outcome": "error"})
		}, "outcome receipt says", 0},
		{"allow without an outcome receipt", func(w *world) { w.meta(w.cA, map[string]any{"receipt": nil}) }, "no outcome receipt", 0},
		{"the outcome of another call copied onto this one", func(w *world) {
			w.meta(w.cB, map[string]any{"receipt": w.specs[w.cA].meta["receipt"]})
		}, "belongs to decision", 0},
		{"another call's decision receipt named by this call", func(w *world) {
			w.meta(w.cB, map[string]any{"receipt_id": "rcpt-A"})
		}, "not for this call", 0},
		{"receipt for another request", func(w *world) { w.meta(w.cA, map[string]any{"request_id": "req-Z"}) }, "is for request", 0},
		{"receipt for another tool", func(w *world) { w.specs[w.cA].resource = "mcp_tool:delete_all" }, "is for tool", 0},
		{"receipt for another agent", func(w *world) { w.specs[w.cA].actor = "agent:agent-2" }, "is for agent", 0},
		{"the tape says allow, the receipt says deny", func(w *world) { w.meta(w.cB, map[string]any{"decision": "allow"}) }, "decision receipt says", 0},
		{"a decision receipt on a tool call", func(w *world) {
			w.meta(w.cA, map[string]any{"receipt": w.specs[w.dA].meta["receipt"]})
		}, "only its outcome belongs", 0},
		{"an outcome receipt on a decision entry", func(w *world) {
			w.meta(w.dA, map[string]any{"receipt": w.specs[w.cA].meta["receipt"]})
		}, "on a decision entry", 1},
		{"a receipt on another kind of entry", func(w *world) {
			w.meta(0, map[string]any{"receipt": w.specs[w.dA].meta["receipt"]})
		}, "receipts ride", 0},
		{"a call after receipts began with no receipt", func(w *world) {
			w.specs = append(w.specs, spec{ActionToolCall, "agent:agent-1", "mcp_tool:x", map[string]any{"decision": "deny", "request_id": "req-C"}})
		}, "after receipts began", 1},
		{"metadata of a call that is not JSON", func(w *world) {
			w.specs[w.cA].meta = nil
			w.specs = append(w.specs, spec{ActionToolCall, "agent:agent-1", "mcp_tool:x", nil})
		}, "after receipts began", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := defaultWorld(t)
			tc.break_(w)
			r := w.verify()
			wantFailure(t, r, tc.want)
			if r.ReceiptsMissing < tc.missing {
				t.Errorf("ReceiptsMissing = %d, want at least %d", r.ReceiptsMissing, tc.missing)
			}
		})
	}
}

// The same receipt delivered twice is one receipt: the bus delivers at least once.
func TestTheSameReceiptTwiceIsOneReceipt(t *testing.T) {
	w := defaultWorld(t)
	w.specs = append(w.specs, w.specs[w.dB])
	r := w.verify()
	if !r.OK || r.Receipts != 3 {
		t.Fatalf("report = %+v", r)
	}
}

// A rule receipt is not tied to a call and needs no call to exist.
func TestARuleReceiptStandsAlone(t *testing.T) {
	w := defaultWorld(t)
	w.specs = append(w.specs, spec{ActionDecisionReceipt, "agent:agent-1", "mcp_tool:wire_money",
		map[string]any{"receipt": w.receipt(map[string]any{"rid": "rcpt-R", "ph": "rule", "verdict": "hold"})}})
	r := w.verify()
	if !r.OK || r.Receipts != 4 {
		t.Fatalf("report = %+v failures %q", r, r.Failures)
	}
}

func TestACallBeforeReceiptsBeganIsNotedNotFailed(t *testing.T) {
	w := defaultWorld(t)
	old := spec{ActionToolCall, "agent:agent-1", "mcp_tool:legacy", map[string]any{"decision": "allow", "request_id": "req-old"}}
	w.specs = append([]spec{old, old}, w.specs...)
	r := w.verify()
	if !r.OK || r.CallsBeforeReceipts != 2 || r.ReceiptsMissing != 0 {
		t.Fatalf("report = %+v failures %q", r, r.Failures)
	}
	if !hasNote(r, "2 governed calls predate receipts") {
		t.Errorf("notes = %q", r.Notes)
	}
}

func hasNote(r Report, contains string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, contains) {
			return true
		}
	}
	return false
}

// A tape of calls with no receipt at all is a tape from before receipts: noted, not failed.
func TestATapeWithNoReceiptsAtAllPredatesThem(t *testing.T) {
	w := defaultWorld(t)
	w.specs = []spec{{ActionToolCall, "agent:agent-1", "mcp_tool:legacy", map[string]any{"decision": "allow"}}, w.specs[0]}
	r := w.verify()
	if !r.OK || r.CallsBeforeReceipts != 1 || r.Receipts != 0 {
		t.Fatalf("report = %+v failures %q", r, r.Failures)
	}
}

// A window that starts mid-tape may start between a call and the receipt recorded just before it.
func TestAMissingReceiptNearTheStartOfAWindowIsNotedNotFailed(t *testing.T) {
	w := newWorld(t, 5, 150, 1000)
	w.remove(w.dA)
	r := w.verify()
	if !r.OK || r.CallsAtEdge != 1 || r.ReceiptsMissing != 0 || !hasNote(r, "near the edge") {
		t.Fatalf("report = %+v failures %q notes %q", r, r.Failures, r.Notes)
	}

	far := newWorld(t, ReceiptLag+10, 150, 1000)
	far.remove(far.dA)
	wantFailure(t, far.verify(), "receipt missing")

	// The tape's first entry has nothing before it, so a missing receipt there is missing.
	genesis := newWorld(t, 5, 150, 1)
	genesis.remove(genesis.dA)
	wantFailure(t, genesis.verify(), "receipt missing")
}

func TestAMissingReceiptNearTheEndOfAWindowIsNotedNotFailed(t *testing.T) {
	w := newWorld(t, 150, 5, 1)
	w.remove(w.dA)
	r := w.verify()
	if !r.OK || r.CallsAtEdge != 1 {
		t.Fatalf("report = %+v failures %q", r, r.Failures)
	}
}

func TestAHeadSignedByAReceiptKeyFails(t *testing.T) {
	b, s := signedBundle(t)
	b.Keys[0].Use = UseReceipt
	_ = s
	wantFailure(t, Verify(b, Options{}), "may not sign a head")
}

func TestAHeadUnderAKeyOfAnotherUseFails(t *testing.T) {
	b, _ := signedBundle(t)
	b.Keys[0].Use = "agent_config"
	wantFailure(t, Verify(b, Options{}), "may not sign a head")
	b.Keys[0].Use = UseAuditHead
	if r := Verify(b, Options{}); !r.OK {
		t.Fatalf("an explicit audit_head key: %q", r.Failures)
	}
}

// chained gives the world both keys a certificate from root, or the receipt key one from a stranger.
func (w *world) certify(t *testing.T, receiptIssuer string) {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	root := certFor(t, rootPub, nil, rootPriv, true)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	w.options.Root = pool
	cert := func(pub ed25519.PublicKey, issuer *x509.Certificate, key ed25519.PrivateKey) []string {
		return []string{base64.StdEncoding.EncodeToString(certFor(t, pub, issuer, key, false).Raw)}
	}
	w.keys[0].X5C = cert(w.head.pub, root, rootPriv)
	if receiptIssuer == "root" {
		w.keys[1].X5C = cert(w.rk.pub, root, rootPriv)
		return
	}
	strangerPub, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	stranger := certFor(t, strangerPub, nil, strangerPriv, true)
	w.keys[1].X5C = cert(w.rk.pub, stranger, strangerPriv)
}

func TestAReceiptKeyChainsToThePinnedRoot(t *testing.T) {
	good := defaultWorld(t)
	good.certify(t, "root")
	if r := good.verify(); !r.OK || !r.Certified {
		t.Fatalf("report = %+v failures %q", r, r.Failures)
	}

	stranger := defaultWorld(t)
	stranger.certify(t, "stranger")
	r := stranger.verify()
	wantFailure(t, r, "receipt key rk-1")
	wantFailure(t, r, "does not chain")
	if r.Certified {
		t.Error("certified with a receipt key from another root")
	}

	uncertified := defaultWorld(t)
	uncertified.certify(t, "root")
	uncertified.keys[1].X5C = nil
	wantFailure(t, uncertified.verify(), "no certificate")
}

// A receipt is judged by its certificate when it was issued, not when it is read.
func TestAReceiptKeyIsJudgedWhenTheReceiptWasIssued(t *testing.T) {
	now := newWorldAt(t, 120, 120, 1, time.Now().Unix())
	now.certify(t, "root") // valid for an hour either side of now
	if r := now.verify(); !r.OK {
		t.Fatalf("receipts issued while the certificate was valid: %q", r.Failures)
	}
	late := newWorldAt(t, 120, 120, 1, time.Now().Add(48*time.Hour).Unix())
	late.certify(t, "root")
	wantFailure(t, late.verify(), "does not chain")
}

// What the maker of a bundle could not include reaches the person checking it, so a missing key is explained.
func TestABundlesNotesReachTheReport(t *testing.T) {
	w := defaultWorld(t)
	b := w.bundle()
	b.Notes = []string{"the receipt keys could not be read"}
	if r := Verify(b, w.options); !r.OK || !hasNote(r, "the receipt keys could not be read") {
		t.Fatalf("report = %+v", r)
	}
}
