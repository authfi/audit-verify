package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// addV3 adds version 3 of agent A with the given host tools.
func (w *tw) addV3(o actOpts, hosts []string, signers ...signerFn) {
	w.addVersion(w.versionClaims(agentA, 3, 0, hosts...), o, signers...)
}

// secondOn files a tenant act turning the second-approver setting on, keeping the CI key.
func (w *tw) secondOn() {
	w.addState(w.tenantClaims(2, true, w.ci), actOpts{}, w.alice.signer())
}

func TestAHealthyConfigurationPasses(t *testing.T) {
	w := newTW(t)
	w.healthy()
	r := w.verify()
	mustPass(t, r)
	if r.Versions != 2 || r.ValidVersions != 2 || r.States != 2 || r.ValidStates != 2 {
		t.Errorf("counts = %+v", r)
	}
	if r.TenantSeq != 1 || r.NeedSecond || r.CIKeys != 1 {
		t.Errorf("tenant settings = %+v", r)
	}
	if len(r.Agents) != 1 {
		t.Fatalf("agents = %+v", r.Agents)
	}
	a := r.Agents[0]
	if a.Agent != agentA || a.Newest != 2 || len(a.InForce) != 2 || a.Mode != "strict" || !a.Signed || a.StateSeq != 1 || a.Floor != 0 {
		t.Errorf("agent = %+v", a)
	}
}

func TestAFloorRetiresTheVersionsBelowIt(t *testing.T) {
	w := newTW(t)
	w.healthy()
	w.addV3(actOpts{}, []string{"bash@b1"}, w.alice.signer())
	w.addVersion(w.versionClaims(agentA, 4, 3, "bash@b1"), actOpts{}, w.alice.signer())
	r := w.verify()
	mustPass(t, r)
	if a := r.Agents[0]; a.Floor != 3 || a.Newest != 4 || len(a.InForce) != 2 || a.InForce[0] != 3 || a.InForce[1] != 4 {
		t.Errorf("agent = %+v", a)
	}
}

func TestAStateFloorCountsToo(t *testing.T) {
	w := newTW(t)
	w.healthy()
	w.addState(w.stateClaims(agentA, 2, "strict", 2), actOpts{}, w.alice.signer())
	r := w.verify()
	mustPass(t, r)
	if a := r.Agents[0]; a.Floor != 2 || len(a.InForce) != 1 || a.InForce[0] != 2 || a.StateSeq != 2 {
		t.Errorf("agent = %+v", a)
	}
}

// An agent with a valid version and no state is at the default tier, tools.
func TestAnAgentWithNoStateIsAtToolsByDefault(t *testing.T) {
	w := newTW(t)
	w.addState(w.tenantClaims(1, false), actOpts{}, w.alice.signer())
	w.addVersion(w.versionClaims(agentB, 1, 0), actOpts{}, w.alice.signer())
	r := w.verify()
	mustPass(t, r)
	if a := r.Agents[0]; a.Mode != "tools" || a.Signed || a.StateSeq != 0 || a.Newest != 1 {
		t.Errorf("agent = %+v", a)
	}
}

func TestEveryPasskeyAlgorithmApproves(t *testing.T) {
	for _, alg := range []string{"ES256", "RS256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			w := newTW(t)
			w.addState(w.tenantClaims(1, false), actOpts{}, w.alice.signer())
			p := newPasskey(t, "user:dave", alg)
			w.addVersion(w.versionClaims(agentA, 1, 0), actOpts{}, p.signer())
			mustPass(t, w.verify())
		})
	}
}

func TestEveryPasskeyAlgorithmRefusesAFlippedSignature(t *testing.T) {
	for _, alg := range []string{"ES256", "RS256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			w := newTW(t)
			w.addState(w.tenantClaims(1, false), actOpts{}, w.alice.signer())
			p := newPasskey(t, "user:dave", alg)
			w.addVersion(w.versionClaims(agentA, 1, 0), actOpts{}, p.signer(func(a *assertion) { a.flipSig = true }))
			wantConfigFailure(t, w.verify(), "approval 0 by user:dave: the signature does not verify")
		})
	}
}

func TestACertificateIsJudgedWhenTheActWasCountersigned(t *testing.T) {
	w := newTW(t)
	w.addState(w.tenantClaims(1, false), actOpts{}, w.alice.signer())
	short := w.pki.kmsKey(t, w.tenant, leafSpec{notAfter: baseTime.Add(time.Hour)})
	// countersigned half an hour in, checked three hours in: the certificate has lapsed since and the act stands.
	w.addVersion(w.versionClaims(agentA, 1, 0), actOpts{kms: short, approvedAt: baseTime.Add(30 * time.Minute).Unix()}, w.alice.signer())
	mustPass(t, w.verify())
}

// The digest is the contract's, byte for byte: a vector computed apart from this code.
// The canonical body uses Go 1.22's string escaping, which is why the module needs Go 1.22.
func TestTheCanonicalBodyEscapesAsGo122Does(t *testing.T) {
	const backslash = "\\"
	claims, err := strictObject([]byte("{\"s\":\"a" + backslash + "b" + backslash + "f" + backslash + "u2028<&>\",\"n\":1.50}"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := canonicalBody(claims)
	if want := "{\"n\":1.50,\"s\":\"a" + backslash + "b" + backslash + "f" + backslash + "u2028<&>\"}"; string(got) != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func TestTheDigestMatchesTheContractsVector(t *testing.T) {
	const payload = `{"v":2,"kref":{"kind":"tenant","id":"agent_config"},"tid":"11111111-1111-1111-1111-111111111111","agent":"agt_A1","ver":1,` +
		`"profiles":[{"name":"café <p>&","sys":["d1"],"tools":[{"name":"bash","sha256":"ab","host":true}]}],"floor":0,"review_by":0,` +
		`"proposed_at":1783000000,"approvals":[{"x":1}],"approved_by":"user:a","second_approver":"","approved_at":1783000100}`
	claims, err := strictObject([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	for typ, want := range map[string]string{
		ConfigVersionType: "7401fb6a55c45062161aa29373374c215ace892de8a57b9b8712170e7257f5d2",
		ConfigStateType:   "e37bb0287492c9d2e893837a04fedfe8d780d781c7772852da2622d6a5c3e92a",
	} {
		d, err := actDigest(typ, claims)
		if err != nil || hex.EncodeToString(d[:]) != want {
			t.Errorf("%s: digest = %x, %v; want %s", typ, d, err, want)
		}
	}
	if _, err := actDigest("authfi-receipt+jwt", claims); err == nil {
		t.Error("a digest was made for a typ that is not an agent configuration act")
	}
}

type refusal struct {
	name  string
	build func(t *testing.T, w *tw)
	want  string
}

func runRefusals(t *testing.T, cases []refusal) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newTW(t)
			w.healthy()
			tc.build(t, w)
			wantConfigFailure(t, w.verify(), tc.want)
		})
	}
}

func TestTheTokenIsRefusedWhen(t *testing.T) {
	otherPKI := func(t *testing.T, w *tw) *kmsKey { return newPKI(t).kmsKey(t, w.tenant, leafSpec{}) }
	runRefusals(t, []refusal{
		{"a payload byte is flipped", func(t *testing.T, w *tw) {
			w.versions[1].Token = flipPayloadByte(w.versions[1].Token)
		}, "its signature does not verify under its key"},
		{"it is not a JWS", func(t *testing.T, w *tw) { w.versions[1].Token = "nonsense" }, "not a compact JWS"},
		{"the header says alg none", func(t *testing.T, w *tw) {
			w.addV3(actOpts{header: func(h map[string]any) { h["alg"] = "none" }}, nil, w.alice.signer())
		}, `signed with "none"; only EdDSA`},
		{"the typ is the other act's", func(t *testing.T, w *tw) {
			w.addV3(actOpts{header: func(h map[string]any) { h["typ"] = ConfigStateType }}, nil, w.alice.signer())
		}, "its typ is"},
		{"the typ is a receipt's", func(t *testing.T, w *tw) {
			w.addV3(actOpts{header: func(h map[string]any) { h["typ"] = ReceiptType }}, nil, w.alice.signer())
		}, "its typ is"},
		{"the header lists critical extensions", func(t *testing.T, w *tw) {
			w.addV3(actOpts{header: func(h map[string]any) { h["crit"] = []string{"x"} }}, nil, w.alice.signer())
		}, "critical extensions"},
		{"the header carries no x5c", func(t *testing.T, w *tw) {
			w.addV3(actOpts{header: func(h map[string]any) { delete(h, "x5c") }}, nil, w.alice.signer())
		}, "carries no x5c"},
		{"the header carries an empty x5c", func(t *testing.T, w *tw) {
			w.addV3(actOpts{header: func(h map[string]any) { h["x5c"] = []string{} }}, nil, w.alice.signer())
		}, "carries no x5c"},
		{"the header names another kid than the certificate", func(t *testing.T, w *tw) {
			w.addV3(actOpts{header: func(h map[string]any) { h["kid"] = "other-key" }}, nil, w.alice.signer())
		}, "another key use or kid"},
		{"the key is another tenant's", func(t *testing.T, w *tw) {
			k := w.pki.kmsKey(t, w.tenant, leafSpec{tenant: otherTenant})
			w.addV3(actOpts{kms: k}, nil, w.alice.signer())
		}, "not for this tenant"},
		{"the key is an audit_head key", func(t *testing.T, w *tw) {
			k := w.pki.kmsKey(t, w.tenant, leafSpec{use: "audit_head"})
			w.addV3(actOpts{kms: k}, nil, w.alice.signer())
		}, "another key use or kid"},
		{"the key is a receipt key", func(t *testing.T, w *tw) {
			k := w.pki.kmsKey(t, w.tenant, leafSpec{use: "receipt"})
			w.addV3(actOpts{kms: k}, nil, w.alice.signer())
		}, "another key use or kid"},
		{"the chain does not reach the pinned root", func(t *testing.T, w *tw) {
			w.addV3(actOpts{kms: otherPKI(t, w)}, nil, w.alice.signer())
		}, "does not chain to the root"},
		{"the certificate had lapsed when the act was countersigned", func(t *testing.T, w *tw) {
			k := w.pki.kmsKey(t, w.tenant, leafSpec{notAfter: baseTime.Add(time.Hour)})
			w.addV3(actOpts{kms: k, approvedAt: baseTime.Add(2 * time.Hour).Unix()}, nil, w.alice.signer())
		}, "does not chain to the root"},
		{"the certificate was not yet valid when the act was countersigned", func(t *testing.T, w *tw) {
			k := w.pki.kmsKey(t, w.tenant, leafSpec{notBefore: baseTime.Add(2 * time.Hour)})
			w.addV3(actOpts{kms: k, approvedAt: baseTime.Add(time.Hour).Unix()}, nil, w.alice.signer())
		}, "does not chain to the root"},
		{"the certificate states no custody", func(t *testing.T, w *tw) {
			k := w.pki.kmsKey(t, w.tenant, leafSpec{noPolicy: true})
			w.addV3(actOpts{kms: k}, nil, w.alice.signer())
		}, "does not state that AuthFI custody"},
		{"the certificate also states the subject-held policy", func(t *testing.T, w *tw) {
			k := w.pki.kmsKey(t, w.tenant, leafSpec{subjectHeld: true})
			w.addV3(actOpts{kms: k}, nil, w.alice.signer())
		}, "does not state that AuthFI custody"},
		{"an intermediate states no custody", func(t *testing.T, w *tw) {
			bare := newPKIPolicies(t, nil)
			w.pki = bare
			w.addV3(actOpts{kms: bare.kmsKey(t, w.tenant, leafSpec{})}, nil, w.alice.signer())
		}, "between its key and the root does not state AuthFI custody"},
		{"the certificate is a CA", func(t *testing.T, w *tw) {
			k := w.pki.kmsKey(t, w.tenant, leafSpec{isCA: true})
			w.addV3(actOpts{kms: k}, nil, w.alice.signer())
		}, "not a signing certificate"},
		{"it was countersigned in the future", func(t *testing.T, w *tw) {
			w.addV3(actOpts{approvedAt: w.now.Add(time.Hour).Unix()}, nil, w.alice.signer())
		}, "in the future"},
		{"it is for another tenant", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["tid"] = otherTenant }}, nil, w.alice.signer())
		}, "not this bundle's tenant"},
		{"its claims are another version", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["v"] = 1 }}, nil, w.alice.signer())
		}, "this verifier reads version 2"},
		{"its payload repeats a key", func(t *testing.T, w *tw) {
			c := w.versionClaims(agentA, 3, 0)
			c["approved_at"] = c["proposed_at"].(int64) + 30
			raw, _ := json.Marshal(c)
			dup := strings.Replace(string(raw), `"ver":3`, `"ver":3,"ver":9`, 1)
			w.versions = append(w.versions, ConfigVersionRow{Agent: agentA, Ver: 3, Token: resignRaw(w, ConfigVersionType, dup)})
		}, `repeats the key "ver"`},
		{"it holds no profiles", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["profiles"] = []any{} }}, nil, w.alice.signer())
		}, "holds no profiles"},
		{"its floor is above its own version", func(t *testing.T, w *tw) {
			w.addVersion(w.versionClaims(agentA, 3, 4), actOpts{}, w.alice.signer())
		}, "floor is not 0 or a version up to this one"},
		{"its row says another version", func(t *testing.T, w *tw) { w.versions[1].Ver = 5 }, "the row is version 5, the act signed version 2"},
		{"its row says another agent", func(t *testing.T, w *tw) { w.versions[1].Agent = agentB }, "the row is for agent"},
		{"the agent holds a version twice", func(t *testing.T, w *tw) {
			w.versions = append(w.versions, w.versions[1])
		}, "holds version 2 twice"},
	})
}

// resignRaw signs a payload exactly as given, as the KMS does for whatever mcp hands it.
func resignRaw(w *tw, typ, payload string) string {
	hdr := map[string]any{"alg": "EdDSA", "typ": typ, "kid": w.kms.kid, "x5c": w.kms.x5c}
	hraw, _ := json.Marshal(hdr)
	in := b64u(hraw) + "." + b64u([]byte(payload))
	return in + "." + b64u(ed25519.Sign(w.kms.priv, []byte(in)))
}

func TestAnApprovalIsRefusedWhen(t *testing.T) {
	flip := func(a *assertion) { a.flipSig = true }
	runRefusals(t, []refusal{
		{"its signature is flipped", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(flip))
		}, "approval 0 by user:alice: the signature does not verify"},
		{"it is over another digest", func(t *testing.T, w *tw) {
			other := testDigest(ConfigVersionType, w.versionClaims(agentA, 99, 0))
			w.addV3(actOpts{}, nil, func(_ [32]byte) map[string]any { return w.alice.approval(other) })
		}, "challenge is not this act's digest"},
		{"its challenge differs by a character", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.challenge = a.challenge[:len(a.challenge)-1] + "A" }))
		}, "challenge is not this act's digest"},
		{"the act was changed after it was approved", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["profiles"] = profiles("evil@e1") }}, nil, w.alice.signer())
		}, "challenge is not this act's digest"},
		{"it approved a version as a state", func(t *testing.T, w *tw) {
			c := w.versionClaims(agentA, 3, 0)
			asState := testDigest(ConfigStateType, c)
			w.addVersion(c, actOpts{}, func(_ [32]byte) map[string]any { return w.alice.approval(asState) })
		}, "challenge is not this act's digest"},
		{"it names no relying party", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.rp = "" }))
		}, "names no relying party"},
		{"its origin is not https", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.cdOrigin, a.origin = "http://console.authfi.io", "http://console.authfi.io" }))
		}, "not an https origin"},
		{"its origin has a path", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.cdOrigin, a.origin = origin+"/x", origin+"/x" }))
		}, "not an https origin"},
		{"its client data names another origin than the approval", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.cdOrigin = "https://other.authfi.io" }))
		}, "not the origin the approval states"},
		{"its assertion was made cross-origin", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.crossOrigin = true }))
		}, "cross-origin"},
		{"its assertion says crossOrigin as a string", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.crossOrigin = "false" }))
		}, "cross-origin"},
		{"its assertion is a registration", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.typ = "webauthn.create" }))
		}, "not a webauthn.get"},
		{"its rp id hash is another site's", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.hashOf = "other.io" }))
		}, "another relying party"},
		{"user verification is clear", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.flags = 0x01 }))
		}, "did not verify the user"},
		{"user presence is clear", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.flags = 0x04 }))
		}, "did not report the user present"},
		{"its alg is none", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.algLabel = "none" }))
		}, `alg "none" is not accepted`},
		{"its alg is ES384", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.algLabel = "ES384" }))
		}, `alg "ES384" is not accepted`},
		{"its ES256 key is on another curve", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, newPasskey(t, "user:dave", "ES256-on-P384").signer())
		}, "alg ES256 needs a P-256 key"},
		{"its RSA key is too small", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, newPasskey(t, "user:dave", "RS256-1024").signer())
		}, "RSA key of at least 2048 bits"},
		{"its alg does not fit its key", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(func(a *assertion) { a.algLabel = "EdDSA" }))
		}, "alg EdDSA needs an Ed25519 key"},
		{"its authenticator data stops before the counter ends", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) {
				ap := c["approvals"].([]any)[0].(map[string]any)
				ad, _ := base64.RawURLEncoding.DecodeString(ap["ad"].(string))
				ap["ad"] = b64u(ad[:36])
			}}, nil, w.alice.signer())
		}, "at least 37 bytes"},
		{"its authenticator data is short", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) {
				ap := c["approvals"].([]any)[0].(map[string]any)
				ap["ad"] = b64u([]byte("short"))
			}}, nil, w.alice.signer())
		}, "at least 37 bytes"},
		{"it is by a name that is not a person", func(t *testing.T, w *tw) {
			p := *w.alice
			p.by = "ci:alice"
			w.addV3(actOpts{}, nil, p.signer())
		}, "is by a person (user:<id>)"},
		{"its kind is unknown", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["approvals"].([]any)[0].(map[string]any)["kind"] = "sms" }}, nil, w.alice.signer())
		}, `kind "sms" is not passkey or ci`},
		{"its key is not a key", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["approvals"].([]any)[0].(map[string]any)["pub"] = b64u([]byte("junk")) }}, nil, w.alice.signer())
		}, "not a PKIX key"},
		{"it is by a key that signed another message", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) {
				ap := c["approvals"].([]any)[0].(map[string]any)
				ap["pub"] = w.bob.pub // the assertion was made by Alice's key
			}}, nil, w.alice.signer())
		}, "the signature does not verify"},
	})
}

func TestTheApproversAreRefusedWhen(t *testing.T) {
	runRefusals(t, []refusal{
		{"one person approves twice, with two credentials", func(t *testing.T, w *tw) {
			second := newPasskey(t, "user:alice", "ES256")
			w.addV3(actOpts{}, nil, w.alice.signer(), second.signer())
		}, "one approver counts once"},
		{"one credential approves for two people", func(t *testing.T, w *tw) {
			p := *w.bob
			p.kid = w.alice.kid
			w.addV3(actOpts{}, nil, w.alice.signer(), p.signer())
		}, "by credential"},
		{"one key approves under two names and credentials", func(t *testing.T, w *tw) {
			p := *w.alice
			p.by, p.kid = "user:bob", "another-credential"
			w.addV3(actOpts{}, nil, w.alice.signer(), p.signer())
		}, "the same public key"},
		{"three approve", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, nil, w.alice.signer(), w.bob.signer(), w.carol.signer())
		}, "at most two"},
		{"approved_by is not the first approval's", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["approved_by"] = "user:mallory" }}, nil, w.alice.signer())
		}, `approved_by is "user:mallory", the first approval is by "user:alice"`},
		{"second_approver is not the second approval's", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["second_approver"] = "user:mallory" }}, nil, w.alice.signer(), w.bob.signer())
		}, "second_approver is"},
		{"second_approver is named with only one approval", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["second_approver"] = "user:bob" }}, nil, w.alice.signer())
		}, "second_approver is"},
		{"second_approver is left out of two approvals", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["second_approver"] = "" }}, nil, w.alice.signer(), w.bob.signer())
		}, "second_approver is"},
		{"there are no approvals", func(t *testing.T, w *tw) { w.addV3(actOpts{}, nil) }, "carries no approvals"},
		{"the approvals list is empty", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["approvals"] = []any{} }}, nil)
		}, "carries no approvals"},
		{"the approvals are not a list", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) { c["approvals"] = "yes" }}, nil)
		}, "carries no approvals"},
	})
}

// The console may run on a related origin, so an origin outside the relying party's domain is not refused offline.
func TestARelatedOriginIsNotRefused(t *testing.T) {
	w := newTW(t)
	w.addState(w.tenantClaims(1, false), actOpts{}, w.alice.signer())
	w.addVersion(w.versionClaims(agentA, 1, 0), actOpts{}, w.alice.signer(func(a *assertion) {
		a.cdOrigin, a.origin = "https://console.example.com", "https://console.example.com"
	}))
	mustPass(t, w.verify())
}

func TestTwoPeopleMayApprove(t *testing.T) {
	w := newTW(t)
	w.healthy()
	w.addV3(actOpts{}, []string{"bash@b1"}, w.alice.signer(), w.bob.signer())
	r := w.verify()
	mustPass(t, r)
	if r.Agents[0].Newest != 3 {
		t.Errorf("agent = %+v", r.Agents[0])
	}
}

func TestTheSecondApproverRuleForVersions(t *testing.T) {
	runRefusals(t, []refusal{
		{"a host tool is added with one approval", func(t *testing.T, w *tw) {
			w.secondOn()
			w.addV3(actOpts{}, []string{"bash@b1", "sh@s1", "curl@c1"}, w.alice.signer())
		}, "adds the host tool curl@c1 and the tenant requires a second approver"},
		{"a host tool keeps its name under another definition", func(t *testing.T, w *tw) {
			w.secondOn()
			w.addV3(actOpts{}, []string{"bash@b2", "sh@s1"}, w.alice.signer())
		}, "adds the host tool bash@b2"},
		{"the agent's first version has one approval", func(t *testing.T, w *tw) {
			w.secondOn()
			w.addVersion(w.versionClaims(agentB, 1, 0), actOpts{}, w.alice.signer())
		}, "is the agent's first version"},
		{"a CI key and one person approve a new host tool", func(t *testing.T, w *tw) {
			w.secondOn()
			w.addV3(actOpts{}, []string{"bash@b1", "sh@s1", "curl@c1"}, w.alice.signer(), w.ci.signer())
		}, "carries 1 person's approval"},
	})

	pass := []struct {
		name  string
		build func(w *tw)
	}{
		{"a host tool is added with two people", func(w *tw) {
			w.secondOn()
			w.addV3(actOpts{}, []string{"bash@b1", "sh@s1", "curl@c1"}, w.alice.signer(), w.bob.signer())
		}},
		{"the host tools are unchanged", func(w *tw) {
			w.secondOn()
			w.addV3(actOpts{}, []string{"bash@b1", "sh@s1"}, w.alice.signer())
		}},
		{"a host tool is dropped", func(w *tw) {
			w.secondOn()
			w.addV3(actOpts{}, []string{"bash@b1"}, w.alice.signer())
		}},
		{"a served tool is added", func(w *tw) {
			w.secondOn()
			c := w.versionClaims(agentA, 3, 0, "bash@b1", "sh@s1")
			c["profiles"].([]any)[0].(map[string]any)["tools"] = append(c["profiles"].([]any)[0].(map[string]any)["tools"].([]any),
				map[string]any{"name": "jira.get", "sha256": "bb22", "host": false})
			w.addVersion(c, actOpts{}, w.alice.signer())
		}},
		{"a host tool returns that an older version had", func(w *tw) {
			w.addV3(actOpts{}, []string{"bash@b1"}, w.alice.signer())
			w.secondOn()
			w.addVersion(w.versionClaims(agentA, 4, 0, "bash@b1", "sh@s1"), actOpts{}, w.alice.signer())
		}},
		{"the setting came after the version was proposed", func(w *tw) {
			late := w.versionClaims(agentA, 3, 0, "curl@c1") // proposed before the setting is on
			w.secondOn()
			w.addVersion(late, actOpts{}, w.alice.signer())
		}},
	}
	for _, tc := range pass {
		t.Run(tc.name, func(t *testing.T) {
			w := newTW(t)
			w.healthy()
			tc.build(w)
			mustPass(t, w.verify())
		})
	}
}

func TestTheLooseningRulesForStates(t *testing.T) {
	runRefusals(t, []refusal{
		{"the tier falls with one approval", func(t *testing.T, w *tw) {
			w.secondOn()
			w.addState(w.stateClaims(agentA, 2, "tools", 0), actOpts{}, w.alice.signer())
		}, "lowers the tier and carries 1 person's approval"},
		{"the tier falls to watch with one approval", func(t *testing.T, w *tw) {
			w.secondOn()
			w.addState(w.stateClaims(agentA, 2, "watch", 0), actOpts{}, w.alice.signer())
		}, "lowers the tier"},
		{"the floor falls with one approval", func(t *testing.T, w *tw) {
			w.addState(w.stateClaims(agentA, 2, "strict", 2), actOpts{}, w.alice.signer())
			w.addState(w.stateClaims(agentA, 3, "strict", 1), actOpts{}, w.alice.signer())
		}, "a floor only goes up"},
		{"the floor falls even with two approvals", func(t *testing.T, w *tw) {
			w.addState(w.stateClaims(agentA, 2, "strict", 2), actOpts{}, w.alice.signer())
			w.addState(w.stateClaims(agentA, 3, "strict", 1), actOpts{}, w.alice.signer(), w.bob.signer())
		}, "a floor only goes up"},
		{"a first state of watch is set for an agent with a version", func(t *testing.T, w *tw) {
			w.addVersion(w.versionClaims(agentB, 1, 0), actOpts{}, w.alice.signer())
			w.secondOn()
			w.addState(w.stateClaims(agentB, 1, "watch", 0), actOpts{}, w.alice.signer())
		}, "lowers the tier"},
		{"the second-approver setting is turned off with one approval", func(t *testing.T, w *tw) {
			w.secondOn()
			w.addState(w.tenantClaims(3, false, w.ci), actOpts{}, w.alice.signer())
		}, "turns the second-approver setting off"},
		{"a CI key is added while the setting is on, with one approval", func(t *testing.T, w *tw) {
			w.secondOn()
			w.addState(w.tenantClaims(3, true, w.ci, newCI(t, "second", "ES256")), actOpts{}, w.alice.signer())
		}, "adds the CI key ci-second while the second-approver setting is on"},
		{"a CI key is swapped for another under the same id while the setting is on", func(t *testing.T, w *tw) {
			w.secondOn()
			swap := newCI(t, "pipeline", "EdDSA")
			w.addState(w.tenantClaims(3, true, swap), actOpts{}, w.alice.signer())
		}, "adds the CI key ci-pipeline"},
		{"a state is approved by a CI key", func(t *testing.T, w *tw) {
			w.addState(w.stateClaims(agentA, 2, "strict", 0), actOpts{}, w.ci.signer())
		}, "approved by people, not by a CI key"},
	})

	pass := []struct {
		name  string
		build func(w *tw)
	}{
		{"the tier falls with two people", func(w *tw) {
			w.addState(w.stateClaims(agentA, 2, "tools", 0), actOpts{}, w.alice.signer(), w.bob.signer())
		}},
		{"the tier rises with one", func(w *tw) {
			w.addState(w.stateClaims(agentA, 2, "tools", 0), actOpts{}, w.alice.signer(), w.bob.signer())
			w.addState(w.stateClaims(agentA, 3, "strict", 0), actOpts{}, w.alice.signer())
		}},
		{"the floor rises with one", func(w *tw) {
			w.addState(w.stateClaims(agentA, 2, "strict", 2), actOpts{}, w.alice.signer())
		}},
		{"a first state of tools is no loosening", func(w *tw) {
			w.addVersion(w.versionClaims(agentB, 1, 0), actOpts{}, w.alice.signer())
			w.addState(w.stateClaims(agentB, 1, "tools", 0), actOpts{}, w.alice.signer())
		}},
		{"a first state of watch for an agent with no version is no loosening", func(w *tw) {
			w.addState(w.stateClaims(agentB, 1, "watch", 0), actOpts{}, w.alice.signer())
		}},
		{"the setting is turned off with two people", func(w *tw) {
			w.secondOn()
			w.addState(w.tenantClaims(3, false, w.ci), actOpts{}, w.alice.signer(), w.bob.signer())
		}},
		{"a CI key is added with two people while the setting is on", func(w *tw) {
			w.secondOn()
			w.addState(w.tenantClaims(3, true, w.ci, newCI(t, "second", "ES256")), actOpts{}, w.alice.signer(), w.bob.signer())
		}},
		{"a CI key is added with one person while the setting is off", func(w *tw) {
			w.addState(w.tenantClaims(2, false, w.ci, newCI(t, "second", "ES256")), actOpts{}, w.alice.signer())
		}},
		{"a CI key is removed while the setting is on", func(w *tw) {
			w.secondOn()
			w.addState(w.tenantClaims(3, true), actOpts{}, w.alice.signer())
		}},
	}
	for _, tc := range pass {
		t.Run(tc.name, func(t *testing.T) {
			w := newTW(t)
			w.healthy()
			tc.build(w)
			mustPass(t, w.verify())
		})
	}
}

func TestStateNumbering(t *testing.T) {
	runRefusals(t, []refusal{
		{"a replayed act is filed under a newer number", func(t *testing.T, w *tw) {
			old := w.states[1].Token // agent A, seq 1
			w.states = append(w.states, ConfigStateRow{Scope: "agent", Agent: agentA, Seq: 2, Token: old})
		}, "the row is seq 2, the act signed seq 1: a replayed act"},
		{"an act is filed under another agent", func(t *testing.T, w *tw) {
			w.states = append(w.states, ConfigStateRow{Scope: "agent", Agent: agentB, Seq: 1, Token: w.states[1].Token})
		}, "the row says scope"},
		{"an act is filed under the tenant's scope", func(t *testing.T, w *tw) {
			w.states = append(w.states, ConfigStateRow{Scope: "tenant", Agent: "*", Seq: 2, Token: w.states[1].Token})
		}, "the row says scope"},
		{"two acts hold one number", func(t *testing.T, w *tw) {
			w.addState(w.stateClaims(agentA, 1, "strict", 0), actOpts{}, w.alice.signer())
		}, "hold seq 1 twice"},
		{"a number is skipped", func(t *testing.T, w *tw) {
			w.addState(w.stateClaims(agentA, 3, "strict", 0), actOpts{}, w.alice.signer())
		}, "jump from seq 1 to 3"},
		{"an agent's first acts are missing", func(t *testing.T, w *tw) {
			w.addState(w.stateClaims(agentA, 2, "strict", 0), actOpts{}, w.alice.signer())
			w.states = append(w.states[:1], w.states[2:]...)
		}, "begin at seq 2"},
		{"the tenant's acts begin late", func(t *testing.T, w *tw) {
			w.states = w.states[1:]
			w.addState(w.tenantClaims(3, false, w.ci), actOpts{}, w.alice.signer())
		}, "the tenant's states"},
		{"a row names neither scope", func(t *testing.T, w *tw) {
			w.states = append(w.states, ConfigStateRow{Scope: "global", Agent: agentA, Seq: 9, Token: "x"})
		}, "names no tenant act and no agent"},
		{"an agent state names an agent that is not one", func(t *testing.T, w *tw) {
			w.addState(w.stateClaims("agent-without-prefix", 1, "strict", 0), actOpts{}, w.alice.signer())
		}, "names no tenant act and no agent"},
		{"a state has an unknown tier", func(t *testing.T, w *tw) {
			w.addState(w.stateClaims(agentB, 1, "lax", 0), actOpts{}, w.alice.signer())
		}, `mode "lax" is not watch, tools or strict`},
		{"a tenant act lacks its setting", func(t *testing.T, w *tw) {
			c := w.tenantClaims(2, true, w.ci)
			delete(c, "need_second")
			w.addState(c, actOpts{}, w.alice.signer())
		}, "need_second is not true or false"},
	})
}

func TestCIApproval(t *testing.T) {
	runRefusals(t, []refusal{
		{"the key is not registered", func(t *testing.T, w *tw) {
			stranger := newCI(t, "stranger", "EdDSA")
			w.addV3(actOpts{}, []string{"bash@b1"}, stranger.signer())
		}, "CI key ci-stranger is not registered"},
		{"the key was registered after the version was proposed", func(t *testing.T, w *tw) {
			late := newCI(t, "late", "EdDSA")
			claims := w.versionClaims(agentA, 3, 0, "bash@b1")
			w.addState(w.tenantClaims(2, false, w.ci, late), actOpts{}, w.alice.signer())
			w.addVersion(claims, actOpts{}, late.signer())
		}, "CI key ci-late is not registered"},
		{"the key was removed before the version was proposed", func(t *testing.T, w *tw) {
			w.addState(w.tenantClaims(2, false), actOpts{}, w.alice.signer())
			w.addV3(actOpts{}, []string{"bash@b1"}, w.ci.signer())
		}, "CI key ci-pipeline is not registered"},
		{"the approval carries another public key under a registered id", func(t *testing.T, w *tw) {
			imposter := newCI(t, "pipeline", "EdDSA")
			w.addV3(actOpts{}, []string{"bash@b1"}, imposter.signer())
		}, "registered with another key"},
		{"the signature is over the passkey message", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, []string{"bash@b1"}, func(d [32]byte) map[string]any {
				return w.ci.approval(d, "authfi-agent-config-approval-v1:version\n")
			})
		}, "the signature does not verify"},
		{"the signature is over another digest", func(t *testing.T, w *tw) {
			w.addV3(actOpts{}, []string{"bash@b1"}, func(d [32]byte) map[string]any {
				d[0] ^= 1
				return w.ci.approval(d, "authfi-agent-config-ci-approval-v1\n")
			})
		}, "the signature does not verify"},
		{"the approval names another pipeline", func(t *testing.T, w *tw) {
			w.addV3(actOpts{mutate: func(c map[string]any) {
				c["approvals"].([]any)[0].(map[string]any)["by"] = "ci:other"
				c["approved_by"] = "ci:other"
			}}, []string{"bash@b1"}, w.ci.signer())
		}, `registered as "pipeline"`},
	})

	for _, alg := range []string{"EdDSA", "ES256"} {
		t.Run("a registered "+alg+" key approves", func(t *testing.T) {
			w := newTW(t)
			c := newCI(t, "p", alg)
			w.addState(w.tenantClaims(1, false, c), actOpts{}, w.alice.signer())
			w.addVersion(w.versionClaims(agentA, 1, 0, "bash@b1"), actOpts{}, c.signer())
			mustPass(t, w.verify())
		})
	}
}

func TestTheTenantsOwnActsAreChecked(t *testing.T) {
	w := newTW(t)
	w.healthy()
	// a tenant act with a CI key of an algorithm that does not fit
	c := w.tenantClaims(2, false, w.ci)
	c["ci_keys"].([]any)[0].(map[string]any)["alg"] = "RS256"
	w.addState(c, actOpts{}, w.alice.signer())
	wantConfigFailure(t, w.verify(), "does not fit the key")
}

func TestAnEmptyBundleSaysSo(t *testing.T) {
	w := newTW(t)
	r := w.verify()
	mustPass(t, r)
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "no acts") {
		t.Errorf("notes = %q", r.Notes)
	}
}

func TestARunWithNothingToCheckAgainstFails(t *testing.T) {
	w := newTW(t)
	w.healthy()
	b := w.bundle()
	wantConfigFailure(t, VerifyConfig(b, ConfigOptions{Now: w.now}), "no root was given")
	b.Tenant = ""
	wantConfigFailure(t, VerifyConfig(b, w.options()), "names no tenant")
	other := w.bundle()
	other.Tenant = otherTenant
	wantConfigFailure(t, VerifyConfig(other, w.options()), "not for this tenant")
}

func TestOnlyTheVersionsOfThePinnedRootAreBelieved(t *testing.T) {
	w := newTW(t)
	w.healthy()
	stranger := newPKI(t)
	o := w.options()
	o.Root = stranger.pool
	r := VerifyConfig(w.bundle(), o)
	wantConfigFailure(t, r, "does not chain to the root")
	if r.ValidVersions != 0 || r.ValidStates != 0 {
		t.Errorf("acts counted valid under a root that did not sign them: %+v", r)
	}
}

func TestTheTape(t *testing.T) {
	healthyTape := func() Bundle {
		return tapeFor(testTenant, true, "agt_A1:1:user:alice", "agt_A1:2:user:alice")
	}
	run := func(t *testing.T, mut func(w *tw), tape Bundle) ConfigReport {
		w := newTW(t)
		w.healthy()
		if mut != nil {
			mut(w)
		}
		o := w.options()
		o.Tape = &tape
		return VerifyConfig(w.bundle(), o)
	}

	t.Run("a tape that agrees passes", func(t *testing.T) {
		r := run(t, nil, healthyTape())
		mustPass(t, r)
		if r.TapeAgents != 1 {
			t.Errorf("TapeAgents = %d", r.TapeAgents)
		}
	})
	t.Run("a tape newer than the bundle names a possible rollback", func(t *testing.T) {
		r := run(t, nil, tapeFor(testTenant, true, "agt_A1:1:user:alice", "agt_A1:2:user:alice", "agt_A1:3:user:alice"))
		wantConfigFailure(t, r, "the bundle may be rolled back")
	})
	t.Run("a bundle that lost every version of an agent the tape approved", func(t *testing.T) {
		r := run(t, func(w *tw) { w.versions = nil }, healthyTape())
		wantConfigFailure(t, r, "the bundle may be rolled back")
	})
	t.Run("a bundle newer than the tape", func(t *testing.T) {
		r := run(t, nil, tapeFor(testTenant, true, "agt_A1:1:user:alice"))
		wantConfigFailure(t, r, "was not approved on the tape")
	})
	t.Run("the newest event decides, not the order the agents appear", func(t *testing.T) {
		r := run(t, nil, tapeFor(testTenant, true, "agt_A1:2:user:alice", "agt_B2:1:user:alice", "agt_A1:1:user:alice"))
		wantConfigFailure(t, r, "the bundle holds version 2 and the tape's newest approved version is 1")
	})
	t.Run("the tape names another approver", func(t *testing.T) {
		r := run(t, nil, tapeFor(testTenant, true, "agt_A1:1:user:alice", "agt_A1:2:user:mallory"))
		wantConfigFailure(t, r, `approved by "user:mallory", the act says "user:alice"`)
	})
	t.Run("the tape is another tenant's", func(t *testing.T) {
		r := run(t, nil, tapeFor(otherTenant, true, "agt_A1:2:user:alice"))
		wantConfigFailure(t, r, "the tape is for tenant")
	})
	t.Run("a tape from its beginning records nothing for an agent the bundle holds", func(t *testing.T) {
		r := run(t, nil, tapeFor(testTenant, true, "agt_B2:1:user:alice"))
		wantConfigFailure(t, r, "records no approved version")
	})
	t.Run("a tape window that starts late only notes it", func(t *testing.T) {
		r := run(t, nil, tapeFor(testTenant, false))
		mustPass(t, r)
		if len(r.Notes) == 0 {
			t.Error("no note that the window records nothing for the agent")
		}
	})
	t.Run("an event with no usable version fails", func(t *testing.T) {
		tape := healthyTape()
		tape.Entries[1].Metadata = `{"ver":"two","approved_by":"user:alice"}`
		tape.Entries[1].EntryHash = EntryHash(tape.Entries[1].PrevHash, tape.Entries[1].ID, tape.Entries[1].Actor, tape.Entries[1].Action, tape.Entries[1].Resource, tape.Entries[1].RecordedAt, []byte(tape.Entries[1].Metadata))
		r := run(t, nil, tape)
		wantConfigFailure(t, r, "no usable agent or ver")
	})
	t.Run("other events about an agent's configuration are not approvals", func(t *testing.T) {
		tape := healthyTape()
		tape.Entries = append(tape.Entries, tapeFor(testTenant, true, "agt_A1:9:user:alice").Entries[0])
		last := &tape.Entries[2]
		last.Seq, last.PrevHash, last.Action = tape.Entries[1].Seq+1, tape.Entries[1].EntryHash, "mcp.agent_config.proposed"
		last.EntryHash = EntryHash(last.PrevHash, last.ID, last.Actor, last.Action, last.Resource, last.RecordedAt, []byte(last.Metadata))
		mustPass(t, run(t, nil, tape))
	})
	t.Run("a tape whose own chain is broken fails", func(t *testing.T) {
		tape := healthyTape()
		tape.Entries[0].Actor = "user:mallory"
		wantConfigFailure(t, run(t, nil, tape), "the tape: ")
	})
}

func TestThePolicyOIDsAreTheRegistered(t *testing.T) {
	if oidCustody.String() != policyHSMCustody {
		t.Errorf("the fixtures' custody policy %s is not the verifier's %s", oidCustody, policyHSMCustody)
	}
}

func TestTokensAreReadWithTheirNumbersAsWritten(t *testing.T) {
	m, err := strictObject([]byte(`{"a":1.50,"b":12345678901234567890}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := m["a"].(json.Number).String(); got != "1.50" {
		t.Errorf("a = %s", got)
	}
	if _, ok := claimInt(m, "a"); ok {
		t.Error("1.50 read as an integer")
	}
	if _, ok := claimInt(m, "b"); ok {
		t.Error("a number past int64 read as an integer")
	}
	for _, bad := range []string{`[]`, `{"a":1} x`, `{"a":1,"a":2}`, `{"a":`, ``} {
		if _, err := strictObject([]byte(bad)); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

func TestAnOriginMustBeAnHTTPSOrigin(t *testing.T) {
	for origin, ok := range map[string]bool{
		"https://authfi.io":              true,
		"https://console.authfi.io:8443": true,
		"https://console.example.com":    true, // a related origin: not tied to the rp id here
		"https://user@authfi.io":         false,
		"https://authfi.io/":             false,
		"https://authfi.io?x":            false,
		"https://authfi.io#x":            false,
		"http://authfi.io":               false,
		"authfi.io":                      false,
		"":                               false,
	} {
		if err := checkOrigin(origin, "authfi.io"); (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok = %v", origin, err, ok)
		}
	}
	if checkOrigin("https://authfi.io", "") == nil {
		t.Error("an empty rp id was accepted")
	}
}

func TestWithTheSettingOffOnePersonMayLoosenTheTier(t *testing.T) {
	w := newTW(t)
	w.healthy()
	w.addState(w.stateClaims(agentA, 2, "watch", 0), actOpts{}, w.alice.signer())
	mustPass(t, w.verify())
}
