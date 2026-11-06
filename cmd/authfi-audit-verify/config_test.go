package main

import (
	"bytes"
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
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/authfi/audit-verify/verify"
)

const cliTenant = "11111111-1111-1111-1111-111111111111"

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub, signer any) *x509.Certificate {
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

// cliWorld writes a root file and a bundle of one tenant act signed by a key chained to that root and approved by a
// sudo confirmation, and returns their paths. tamper changes the act after it was approved.
func cliWorld(t *testing.T, tamper bool) (dir, root, bundle string) {
	t.Helper()
	dir = t.TempDir()
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(48 * time.Hour)}
	rootCert := mustCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	policy := []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 67322, 1, 1}}
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interCert := mustCert(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"}, IsCA: true,
		BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, PolicyIdentifiers: policy,
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour)}, rootCert, &interKey.PublicKey, rootKey)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	leaf := mustCert(t, &x509.Certificate{SerialNumber: big.NewInt(3),
		Subject:  pkix.Name{OrganizationalUnit: []string{"tenant " + cliTenant}, CommonName: "agent_config signing key k1"},
		KeyUsage: x509.KeyUsageDigitalSignature, PolicyIdentifiers: policy, BasicConstraintsValid: true,
		NotBefore: now.Add(-12 * time.Hour), NotAfter: now.Add(12 * time.Hour)}, interCert, pub, interKey)

	root = filepath.Join(dir, "root.pem")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	claims := map[string]any{"v": 1, "kref": map[string]any{"kind": "tenant", "id": "agent_config"}, "tid": cliTenant, "scope": "tenant",
		"agent": "*", "seq": 1, "need_second": false, "ci_keys": []any{}, "proposed_at": now.Add(-time.Hour).Unix()}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(claims)
	digest := sha256.Sum256(append([]byte("authfi-agent-config-approval-v1:state\n"), bytes.TrimSuffix(buf.Bytes(), []byte("\n"))...))
	proposed := claims["proposed_at"].(int64)
	claims["approvals"] = []any{map[string]any{"kind": "sudo", "by": "user:alice", "method": []any{"mfa", "hwk"},
		"auth_time": proposed - 300, "window_s": 900, "confirmed_at": proposed + 10, "sess": "00112233445566778899aabbccddeeff",
		"digest":    hex.EncodeToString(digest[:]),
		"statement": "confirmed by sudo (Confirm it's you) within the project's sudo window; no passkey of the person signed this act"}}
	claims["approved_by"], claims["second_approver"], claims["approved_at"] = "user:alice", "", now.Add(-30*time.Minute).Unix()
	if tamper {
		claims["need_second"] = true
	}
	hdr, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "authfi-agent-config-state+jwt", "kid": "k1",
		"x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(interCert.Raw)}})
	payload, _ := json.Marshal(claims)
	in := b64u(hdr) + "." + b64u(payload)
	token := in + "." + b64u(ed25519.Sign(priv, []byte(in)))
	bundle = writeJSON(t, dir, "config.json", map[string]any{"tenant": cliTenant, "versions": []any{},
		"states": []any{map[string]any{"scope": "tenant", "agent": "*", "seq": 1, "token": token}}})
	return dir, root, bundle
}

func runCLI(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := runConfigCommand(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestConfigPassesAGoodBundle(t *testing.T) {
	_, root, bundle := cliWorld(t, false)
	code, out, errOut := runCLI("--bundle", bundle, "--root", root)
	if code != 0 || !strings.Contains(out, "result: PASS") || !strings.Contains(out, "states:          1 read, 1 valid") {
		t.Fatalf("code = %d\nout = %s\nerr = %s", code, out, errOut)
	}
}

// The key signed an act that was changed after the person approved it, so the signature holds and the approval's digest does not.
func TestConfigFailsAnActChangedAfterItWasApproved(t *testing.T) {
	_, root, bundle := cliWorld(t, true)
	code, out, _ := runCLI("--bundle", bundle, "--root", root)
	if code != 1 || !strings.Contains(out, "FAILED: tenant state seq 1: approval 0 by user:alice: the confirmation names another act") ||
		strings.Contains(out, "PASS") {
		t.Fatalf("code = %d\nout = %s", code, out)
	}
}

func TestConfigFailsAKeyOfAnotherRoot(t *testing.T) {
	_, _, bundle := cliWorld(t, false)
	_, otherRoot, _ := cliWorld(t, false)
	code, out, _ := runCLI("--bundle", bundle, "--root", otherRoot)
	if code != 1 || !strings.Contains(out, "does not chain to the root") {
		t.Fatalf("code = %d\nout = %s", code, out)
	}
}

func TestConfigReadsATape(t *testing.T) {
	dir, root, bundle := cliWorld(t, false)
	tape := writeJSON(t, dir, "proof.json", map[string]any{"format": "authfi.audit.proof.v1", "tenant_id": "22222222-2222-2222-2222-222222222222",
		"entries": []any{}, "heads": []any{}, "keys": []any{}})
	code, out, _ := runCLI("--bundle", bundle, "--root", root, "--tape", tape)
	if code != 1 || !strings.Contains(out, "FAILED: the tape is for tenant") {
		t.Fatalf("code = %d\nout = %s", code, out)
	}
}

func TestConfigCouldNotRun(t *testing.T) {
	dir, root, bundle := cliWorld(t, false)
	notPEM := filepath.Join(dir, "x.pem")
	if err := os.WriteFile(notPEM, []byte("nothing"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no flags":                         {},
		"no root":                          {"--bundle", bundle},
		"no bundle":                        {"--root", root},
		"a missing bundle":                 {"--bundle", filepath.Join(dir, "none.json"), "--root", root},
		"a root that is not a certificate": {"--bundle", bundle, "--root", notPEM},
		"a missing tape":                   {"--bundle", bundle, "--root", root, "--tape", filepath.Join(dir, "none.json")},
		"an unknown flag":                  {"--nope"},
	} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%s: exit code %d, want 2", name, code)
		}
	}
}

func TestConfigPrintsWhatItFound(t *testing.T) {
	var out bytes.Buffer
	printConfig(&out, verify.ConfigReport{Tenant: "t1", Versions: 3, ValidVersions: 2, Notes: []string{"n1"}, Failures: []string{"f1"}, TapeAgents: 1,
		Agents: []verify.AgentConfig{{Agent: "agt_x", Mode: "strict", Signed: true, StateSeq: 4, Floor: 2, Newest: 5, InForce: []int64{2, 5}}}}, true)
	for _, want := range []string{"tenant:          t1", "versions:        3 read, 2 valid", "agent agt_x: tier strict (signed, seq 4), floor 2, newest version 5, in force 2, 5",
		"1 agents' newest approved version matches", "note: n1", "FAILED: f1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output lacks %q:\n%s", want, out.String())
		}
	}
}
