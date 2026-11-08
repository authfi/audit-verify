// Package vectorgen makes the test vectors of the verifier (see package vectors) from fixed seeds. Tape, head
// and receipt vectors use Ed25519 and SHA-256 only, so the same code gives the same bytes on every run and the
// committed files can be checked against a fresh run. Vectors that need X.509 certificates are not made here:
// ECDSA signing is randomised, so those files are committed and checked by result, not by bytes.
package vectorgen

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/authfi/audit-verify/vectors"
	"github.com/authfi/audit-verify/verify"
)

// Tenant is the tenant of every vector. It is not a real tenant.
const Tenant = "00000000-0000-4000-8000-00000000a4e1"

// At is the instant every vector is run at.
var At = time.Date(2026, 11, 1, 12, 30, 0, 0, time.UTC)

var base = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

type signer struct {
	kid  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	use  string
}

// newSigner derives a key from its name, so it is the same key on every run. The keys are published with the
// vectors and protect nothing.
func newSigner(name, kid, use string) signer {
	seed := sha256.Sum256([]byte("AuthFI VECTOR key - not trusted: " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return signer{kid: kid, pub: priv.Public().(ed25519.PublicKey), priv: priv, use: use}
}

func (s signer) key() verify.Key {
	return verify.Key{Kty: "OKP", Crv: "Ed25519", Kid: s.kid, X: base64.RawURLEncoding.EncodeToString(s.pub), Status: "active", Use: s.use}
}

func (s signer) head(seq int64, hash string) verify.Head {
	sig := ed25519.Sign(s.priv, verify.HeadMessage(Tenant, seq, hash))
	return verify.Head{Seq: seq, EntryHash: hash, KeyID: s.kid, Algorithm: "Ed25519", Signature: base64.RawURLEncoding.EncodeToString(sig)}
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// jws signs a receipt the way the key service does for the gateway.
func (s signer) jws(claims map[string]any) string {
	in := b64(map[string]any{"alg": "EdDSA", "typ": verify.ReceiptType, "kid": s.kid}) + "." + b64(claims)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, []byte(in)))
}

type spec struct {
	action, actor, resource string
	meta                    map[string]any
}

// tape is one window of the tape before it is chained and signed.
type tape struct {
	head, receipt signer
	headKeyID     string // the key id the head names; the head key's, unless a vector changes it
	headSigner    signer // who signs the head
	specs         []spec
	mutate        func(*verify.Bundle)
}

func newTape() *tape {
	t := &tape{
		head:    newSigner("audit head", "vector-head-1", verify.UseAuditHead),
		receipt: newSigner("receipt", "vector-receipt-1", verify.UseReceipt),
	}
	t.headSigner = t.head
	return t
}

func (t *tape) filler(n int) {
	for i := 0; i < n; i++ {
		t.specs = append(t.specs, spec{"user.login", "user:alice", "user:alice", map[string]any{"ip": "192.0.2.1"}})
	}
}

// governed adds the two calls of a gateway: an allow with its outcome receipt and a deny, each with its decision
// receipt. It returns the index of the first decision entry, for vectors that damage a receipt.
func (t *tape) governed() int {
	iat := base.Unix() + int64(len(t.specs))
	rc := func(over map[string]any) string {
		m := map[string]any{"v": 1, "tid": Tenant, "iat": iat}
		for k, v := range over {
			m[k] = v
		}
		return t.receipt.jws(m)
	}
	decA := rc(map[string]any{"rid": "rcpt-A", "ph": "decision", "req": "req-A", "verdict": "allow", "agent": "agent-1", "tool": "send_email"})
	outA := rc(map[string]any{"rid": "rcpt-A-out", "ph": "outcome", "drid": "rcpt-A", "req": "req-A", "agent": "agent-1", "tool": "send_email", "out": "ok"})
	decB := rc(map[string]any{"rid": "rcpt-B", "ph": "decision", "req": "req-B", "verdict": "deny", "agent": "agent-1", "tool": "wire_money"})
	first := len(t.specs)
	t.specs = append(t.specs,
		spec{verify.ActionDecisionReceipt, "agent:agent-1", "mcp_tool:send_email", map[string]any{"receipt": decA}},
		spec{verify.ActionToolCall, "agent:agent-1", "mcp_tool:send_email", map[string]any{
			"decision": "allow", "request_id": "req-A", "receipt_id": "rcpt-A", "outcome": "ok", "receipt": outA}},
		spec{verify.ActionDecisionReceipt, "agent:agent-1", "mcp_tool:wire_money", map[string]any{"receipt": decB}},
		spec{verify.ActionToolCall, "agent:agent-1", "mcp_tool:wire_money", map[string]any{
			"decision": "deny", "request_id": "req-B", "receipt_id": "rcpt-B"}},
	)
	return first
}

// bundle chains the entries and signs a head over the last one.
func (t *tape) bundle() verify.Bundle {
	prev := ""
	entries := make([]verify.Entry, 0, len(t.specs))
	for i, s := range t.specs {
		meta, _ := json.Marshal(s.meta)
		seq := int64(i + 1)
		at := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		e := verify.Entry{Seq: seq, PrevHash: prev, ID: "vec-" + strconv.FormatInt(seq, 10), Actor: s.actor, Action: s.action,
			Resource: s.resource, RecordedAt: at, Metadata: string(meta)}
		e.EntryHash = verify.EntryHash(e.PrevHash, e.ID, e.Actor, e.Action, e.Resource, e.RecordedAt, meta)
		prev = e.EntryHash
		entries = append(entries, e)
	}
	last := entries[len(entries)-1]
	h := t.headSigner.head(last.Seq, last.EntryHash)
	h.KeyID = t.headKeyID
	if h.KeyID == "" {
		h.KeyID = t.head.kid
	}
	b := verify.Bundle{Format: verify.Format, TenantID: Tenant, Entries: entries,
		Keys: []verify.Key{t.head.key(), t.receipt.key()}, Heads: []verify.Head{h}}
	if t.mutate != nil {
		t.mutate(&b)
	}
	return b
}

func encode(b verify.Bundle) []byte {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		panic(err) // a bundle always marshals
	}
	return append(raw, '\n')
}

// Files returns every generated file by its path under the vectors directory, manifest included.
func Files() map[string][]byte {
	files := map[string][]byte{}
	var vs []vectors.Vector
	add := func(v vectors.Vector, b verify.Bundle) {
		path := v.Kind + "/" + v.ID + ".bundle.json"
		v.Input = map[string]string{"bundle": path}
		// These vectors carry no pinned root, so they say so: when pinning becomes the verifier's default they
		// keep passing.
		v.Args = []string{"--unpinned"}
		files[path] = encode(b)
		vs = append(vs, v)
	}
	pass := vectors.Expect{Result: "pass"}
	fail := func(reason, phrase string) vectors.Expect {
		return vectors.Expect{Result: "fail", Reason: reason, FailureContains: phrase}
	}

	t := newTape()
	t.filler(6)
	add(vectors.Vector{ID: "T1", Kind: "tape", Expect: pass,
		Why: "a window from the start of the tape, linked and covered by a head signed by an audit_head key"}, t.bundle())

	t = newTape()
	t.filler(6)
	t.mutate = func(b *verify.Bundle) { b.Entries[2].Actor = "user:mallory" }
	add(vectors.Vector{ID: "T2", Kind: "tape", Expect: fail("entry_changed", "the entry was changed"),
		Why: "one field of one entry is changed after the chain was made"}, t.bundle())

	t = newTape()
	t.filler(6)
	t.headSigner = newSigner("stranger", "vector-head-1", verify.UseAuditHead)
	add(vectors.Vector{ID: "H1", Kind: "head", Expect: fail("head_signature", "the signature does not verify under key"),
		Why: "the head names the tenant's audit_head key but was signed by another key"}, t.bundle())

	t = newTape()
	t.filler(6)
	t.headSigner = t.receipt
	t.headKeyID = t.receipt.kid
	add(vectors.Vector{ID: "H2", Kind: "head", Expect: fail("head_wrong_use", "may not sign a head"),
		Why: "the gateway's receipt key signs a head: a key signs only the statements of its own use"}, t.bundle())

	t = newTape()
	t.filler(2)
	t.governed()
	t.filler(2)
	add(vectors.Vector{ID: "R1", Kind: "receipt", Expect: pass,
		Why: "an allowed call with its decision and outcome receipts and a denied call with its decision receipt"}, t.bundle())

	t = newTape()
	t.filler(2)
	i := t.governed()
	t.filler(2)
	raw := t.specs[i].meta["receipt"].(string)
	t.specs[i].meta["receipt"] = raw[:len(raw)-4] + flip(raw[len(raw)-4:])
	add(vectors.Vector{ID: "R2", Kind: "receipt", Expect: fail("receipt_signature", "its signature does not verify under key"),
		Why: "the last bytes of a decision receipt's signature are changed and the chain and head are rebuilt over the damaged entry"}, t.bundle())

	manifest := vectors.Manifest{Format: vectors.Format, VerifierMin: "1.3.0", At: At.Format(time.RFC3339), Vectors: vs}
	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		panic(err)
	}
	files["manifest.json"] = append(out, '\n')
	return files
}

// flip changes every character of a base64url tail to another in the same alphabet.
func flip(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c == 'A' {
			out[i] = 'B'
		} else {
			out[i] = 'A'
		}
	}
	return string(out)
}
