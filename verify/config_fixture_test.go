package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"

	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The fixtures build the world a tenant's configuration lives in, with real keys: a software root and intermediate
// standing for the HSM chain, the tenant's agent_config key with its custody certificate, people who approve
// by the sudo window and a CI key. The acts are signed the way the contracts say, with a digest
// computed here from the contract's text and not by the code under test.

const (
	agentA = "agt_A1"
	agentB = "agt_B2"
)

var (
	oidCustody = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 67322, 1, 1}
	baseTime   = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pki is a root and an intermediate, standing for the HSM root and the cluster's intermediate.
type pki struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	pool     *x509.CertPool
}

func newCert(t *testing.T, tmpl, parent *x509.Certificate, pub, signer any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newPKI(t *testing.T) *pki { return newPKIPolicies(t, []asn1.ObjectIdentifier{oidCustody}) }

// newPKIPolicies makes a chain whose intermediate states the given certificate policies.
func newPKIPolicies(t *testing.T, interPolicies []asn1.ObjectIdentifier) *pki {
	t.Helper()
	p := &pki{}
	var err error
	if p.rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: baseTime.Add(-72 * time.Hour), NotAfter: baseTime.Add(72 * time.Hour)}
	p.root = newCert(t, rootTmpl, rootTmpl, &p.rootKey.PublicKey, p.rootKey)
	if p.interKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"}, IsCA: true,
		BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		PolicyIdentifiers: interPolicies, NotBefore: baseTime.Add(-60 * time.Hour), NotAfter: baseTime.Add(60 * time.Hour)}
	p.inter = newCert(t, interTmpl, p.root, &p.interKey.PublicKey, p.rootKey)
	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.root)
	return p
}

// leafSpec is a custody certificate; the zero value of each field is the right one.
type leafSpec struct {
	tenant, use, kid string
	notBefore        time.Time
	notAfter         time.Time
	noPolicy         bool
	subjectHeld      bool // also states the subject-held policy, which no custody certificate does
	isCA             bool
}

// kmsKey is the tenant's agent_config key, with its certificate chain.
type kmsKey struct {
	priv ed25519.PrivateKey
	kid  string
	x5c  []string
}

func (p *pki) kmsKey(t *testing.T, tenant string, s leafSpec) *kmsKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if s.kid == "" {
		s.kid = "ac-key-1"
	}
	if s.use == "" {
		s.use = "agent_config"
	}
	if s.tenant == "" {
		s.tenant = tenant
	}
	if s.notBefore.IsZero() {
		s.notBefore = baseTime.Add(-48 * time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = baseTime.Add(48 * time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:   pkix.Name{OrganizationalUnit: []string{"tenant " + s.tenant}, CommonName: s.use + " signing key " + s.kid},
		NotBefore: s.notBefore, NotAfter: s.notAfter, KeyUsage: x509.KeyUsageDigitalSignature, IsCA: s.isCA, BasicConstraintsValid: true}
	if !s.noPolicy {
		tmpl.PolicyIdentifiers = []asn1.ObjectIdentifier{oidCustody}
	}
	if s.subjectHeld {
		tmpl.PolicyIdentifiers = append(tmpl.PolicyIdentifiers, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 67322, 1, 3})
	}
	leaf := newCert(t, tmpl, p.inter, pub, p.interKey)
	return &kmsKey{priv: priv, kid: s.kid, x5c: []string{
		base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(p.inter.Raw)}}
}

// person is someone who approves by the "Confirm it's you" sudo window.
type person struct{ by string }

func newPerson(by string) *person { return &person{by: by} }

// sudo lets a test bend what the console token and the window say.
type sudo struct {
	by          string
	method      []string
	authTime    int64 // 0: ten minutes before the proposal
	signedInAgo int64 // when set (and authTime is 0), seconds before the proposal
	windowS     int64
	confirmedAt int64 // 0: ten seconds after the proposal
	sess        string
	digest      string // "" : the act's own
	statement   string
	extra       map[string]any
}

func (p *person) sudoFor(d [32]byte, claims map[string]any, mods ...func(*sudo)) map[string]any {
	proposed := claims["proposed_at"].(int64)
	s := sudo{by: p.by, method: []string{"mfa", "hwk"}, windowS: 900, sess: hex.EncodeToString(sessHash(p.by)),
		digest: hex.EncodeToString(d[:]), statement: testStatement}
	for _, m := range mods {
		m(&s)
	}
	if s.authTime == 0 && s.signedInAgo > 0 {
		s.authTime = proposed - s.signedInAgo
	}
	if s.authTime == 0 {
		s.authTime = proposed - 600
	}
	if s.confirmedAt == 0 {
		s.confirmedAt = proposed + 10
	}
	ap := map[string]any{"kind": "sudo", "by": s.by, "method": toAny(s.method), "auth_time": s.authTime, "window_s": s.windowS,
		"confirmed_at": s.confirmedAt, "sess": s.sess, "digest": s.digest, "statement": s.statement}
	for k, v := range s.extra {
		ap[k] = v
	}
	return ap
}

func sessHash(by string) []byte { h := sha256.Sum256([]byte("sid-of-" + by)); return h[:16] }

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// testStatement is the contract's sentence, written here from its text.
const testStatement = "confirmed by sudo (Confirm it's you) within the project's sudo window; no passkey of the person signed this act"

// ciSigner is a pipeline's key.
type ciSigner struct {
	id, name, alg string
	priv          crypto.Signer
	pub           string
}

func newCI(t *testing.T, name, alg string) *ciSigner {
	t.Helper()
	c := &ciSigner{id: "ci-" + name, name: name, alg: alg}
	var err error
	if alg == "ES256" {
		c.priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		_, c.priv, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(c.priv.Public())
	c.pub = b64u(der)
	return c
}

func (c *ciSigner) registered() map[string]any {
	return map[string]any{"id": c.id, "name": c.name, "alg": c.alg, "pub": c.pub}
}

func (c *ciSigner) approval(d [32]byte, prefix string) map[string]any {
	msg := append([]byte(prefix), d[:]...)
	var sig []byte
	if c.alg == "ES256" {
		h := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, c.priv.(*ecdsa.PrivateKey), h[:])
	} else {
		sig = ed25519.Sign(c.priv.(ed25519.PrivateKey), msg)
	}
	return map[string]any{"kind": "ci", "by": "ci:" + c.name, "kid": c.id, "alg": c.alg, "pub": c.pub, "sig": b64u(sig)}
}

func (c *ciSigner) signer() signerFn {
	return func(d [32]byte, _ map[string]any) map[string]any {
		return c.approval(d, "authfi-agent-config-ci-approval-v1\n")
	}
}

// signerFn makes one approval over a digest.
type signerFn func(d [32]byte, claims map[string]any) map[string]any

func (p *person) signer(mods ...func(*sudo)) signerFn {
	return func(d [32]byte, claims map[string]any) map[string]any { return p.sudoFor(d, claims, mods...) }
}

// testDigest is the contract's digest, written here from its text.
func testDigest(typ string, claims map[string]any) [32]byte {
	body := map[string]any{}
	for k, v := range claims {
		switch k {
		case "approvals", "approved_by", "second_approver", "approved_at":
		default:
			body[k] = v
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
	prefix := "authfi-agent-config-approval-v1:version\n"
	if typ == ConfigStateType {
		prefix = "authfi-agent-config-approval-v1:state\n"
	}
	return sha256.Sum256(append([]byte(prefix), bytes.TrimSuffix(buf.Bytes(), []byte("\n"))...))
}

// tw is a tenant's world: the PKI, the signing key, some people and a clock.
type tw struct {
	t      *testing.T
	tenant string
	pki    *pki
	kms    *kmsKey
	alice  *person
	bob    *person
	carol  *person
	ci     *ciSigner
	clock  int64
	now    time.Time

	versions []ConfigVersionRow
	states   []ConfigStateRow
}

func newTW(t *testing.T) *tw {
	t.Helper()
	w := &tw{t: t, tenant: testTenant, pki: newPKI(t), clock: baseTime.Unix(), now: baseTime.Add(3 * time.Hour)}
	w.kms = w.pki.kmsKey(t, w.tenant, leafSpec{})
	w.alice = newPerson("user:alice")
	w.bob = newPerson("user:bob")
	w.carol = newPerson("user:carol")
	w.ci = newCI(t, "pipeline", "EdDSA")
	return w
}

// tick is the next proposal time.
func (w *tw) tick() int64 { w.clock += 60; return w.clock }

// actOpts bends how an act is made.
type actOpts struct {
	kms        *kmsKey
	approvedAt int64
	mutate     func(claims map[string]any)
	header     func(h map[string]any)
	keepSig    bool // leave the approvals as the signers made them even when mutate changes the claims
}

func (w *tw) sign(typ string, claims map[string]any, o actOpts, signers ...signerFn) string {
	d := testDigest(typ, claims)
	var approvals []any
	for _, s := range signers {
		approvals = append(approvals, s(d, claims))
	}
	if approvals != nil {
		claims["approvals"] = approvals
		claims["approved_by"] = approvals[0].(map[string]any)["by"]
		second := ""
		if len(approvals) > 1 {
			second, _ = approvals[1].(map[string]any)["by"].(string)
		}
		claims["second_approver"] = second
	}
	if o.approvedAt == 0 {
		o.approvedAt = claims["proposed_at"].(int64) + 30
	}
	claims["approved_at"] = o.approvedAt
	if o.mutate != nil {
		o.mutate(claims)
	}
	k := o.kms
	if k == nil {
		k = w.kms
	}
	header := map[string]any{"alg": "EdDSA", "typ": typ, "kid": k.kid, "x5c": k.x5c}
	if o.header != nil {
		o.header(header)
	}
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(claims)
	in := b64u(hraw) + "." + b64u(praw)
	return in + "." + b64u(ed25519.Sign(k.priv, []byte(in)))
}

func kref() map[string]any { return map[string]any{"kind": "tenant", "id": "agent_config"} }

// profiles is one profile with a served tool and the named host tools, each "name@sha".
func profiles(hosts ...string) []any {
	tools := []any{map[string]any{"name": "jira.search", "sha256": "aa11", "host": false}}
	for _, h := range hosts {
		name, sum, _ := strings.Cut(h, "@")
		tools = append(tools, map[string]any{"name": name, "sha256": sum, "host": true})
	}
	return []any{map[string]any{"name": "default", "sys": []any{"d0"}, "tools": tools}}
}

func (w *tw) versionClaims(agent string, ver int64, floor int64, hosts ...string) map[string]any {
	return map[string]any{"v": 2, "kref": kref(), "tid": w.tenant, "agent": agent, "ver": ver, "profiles": profiles(hosts...),
		"floor": floor, "review_by": 0, "proposed_at": w.tick()}
}

func (w *tw) stateClaims(agent string, seq int64, mode string, floor int64) map[string]any {
	return map[string]any{"v": 1, "kref": kref(), "tid": w.tenant, "scope": "agent", "agent": agent, "seq": seq, "mode": mode,
		"floor": floor, "proposed_at": w.tick()}
}

func (w *tw) tenantClaims(seq int64, needSecond bool, keys ...*ciSigner) map[string]any {
	list := []any{}
	for _, k := range keys {
		list = append(list, k.registered())
	}
	return map[string]any{"v": 1, "kref": kref(), "tid": w.tenant, "scope": "tenant", "agent": "*", "seq": seq,
		"need_second": needSecond, "ci_keys": list, "proposed_at": w.tick()}
}

// addVersion signs a version and files it. It returns the token.
func (w *tw) addVersion(claims map[string]any, o actOpts, signers ...signerFn) string {
	tok := w.sign(ConfigVersionType, claims, o, signers...)
	w.versions = append(w.versions, ConfigVersionRow{Agent: claims["agent"].(string), Ver: claims["ver"].(int64), Token: tok})
	return tok
}

func (w *tw) addState(claims map[string]any, o actOpts, signers ...signerFn) string {
	tok := w.sign(ConfigStateType, claims, o, signers...)
	w.states = append(w.states, ConfigStateRow{Scope: claims["scope"].(string), Agent: claims["agent"].(string), Seq: claims["seq"].(int64), Token: tok})
	return tok
}

func (w *tw) bundle() ConfigBundle {
	return ConfigBundle{Tenant: w.tenant, Versions: append([]ConfigVersionRow(nil), w.versions...), States: append([]ConfigStateRow(nil), w.states...)}
}

func (w *tw) options() ConfigOptions { return ConfigOptions{Root: w.pki.pool, Now: w.now} }

func (w *tw) verify() ConfigReport { return VerifyConfig(w.bundle(), w.options()) }

// healthy fills a tenant that passes: a tenant act registering the CI key, then agent A with two versions (the
// second adding a host tool) and a strict state, all by Alice alone while the second-approver setting is off.
func (w *tw) healthy() {
	w.addState(w.tenantClaims(1, false, w.ci), actOpts{}, w.alice.signer())
	w.addVersion(w.versionClaims(agentA, 1, 0, "bash@b1"), actOpts{}, w.alice.signer())
	w.addVersion(w.versionClaims(agentA, 2, 0, "bash@b1", "sh@s1"), actOpts{}, w.alice.signer())
	w.addState(w.stateClaims(agentA, 1, "strict", 0), actOpts{}, w.alice.signer())
}

func wantConfigFailure(t *testing.T, r ConfigReport, contains string) {
	t.Helper()
	if r.OK {
		t.Fatalf("passed, want a failure saying %q", contains)
	}
	for _, f := range r.Failures {
		if strings.Contains(f, contains) {
			return
		}
	}
	t.Fatalf("failures = %q, want one saying %q", r.Failures, contains)
}

func mustPass(t *testing.T, r ConfigReport) {
	t.Helper()
	if !r.OK {
		t.Fatalf("failures: %q", r.Failures)
	}
}

// flipPayloadByte changes a digit of the token's ver without re-signing: the JWS signature then no longer holds.
func flipPayloadByte(tok string) string {
	parts := strings.Split(tok, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	i := bytes.Index(raw, []byte(`"ver"`))
	raw[i+len(`"ver":`)] ^= 0x01 // a digit becomes another digit
	parts[1] = b64u(raw)
	return strings.Join(parts, ".")
}

// tapeFor builds a tape bundle with approved-version events: each is "agent:ver:approved_by".
func tapeFor(tenant string, genesis bool, events ...string) Bundle {
	prev := ""
	from := int64(1)
	if !genesis {
		prev, from = "older", 50
	}
	var entries []Entry
	for i, ev := range events {
		parts := strings.Split(ev, ":")
		agent, ver, by := parts[0], parts[1], strings.Join(parts[2:], ":")
		meta, _ := json.Marshal(map[string]any{"ver": ver, "approved_by": by, "profiles": "1"})
		seq := from + int64(i)
		e := Entry{Seq: seq, PrevHash: prev, ID: "id-" + strconv.FormatInt(seq, 10), Actor: by, Action: ConfigApprovedAction,
			Resource: "agent:" + agent, RecordedAt: "2026-11-04T12:30:00.123456Z", Metadata: string(meta)}
		e.EntryHash = EntryHash(e.PrevHash, e.ID, e.Actor, e.Action, e.Resource, e.RecordedAt, []byte(e.Metadata))
		prev = e.EntryHash
		entries = append(entries, e)
	}
	return Bundle{Format: Format, TenantID: tenant, Entries: entries}
}
