package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"go/parser"
	"go/token"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testTenant = "11111111-1111-1111-1111-111111111111"

// signer is the tenant's key, the way kms would hold it.
type signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	kid  string
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{pub, priv, "kid-1"}
}

func (s signer) key() Key {
	return Key{Kty: "OKP", Crv: "Ed25519", Kid: s.kid, X: base64.RawURLEncoding.EncodeToString(s.pub), Status: "active"}
}

func (s signer) head(tenant string, seq int64, hash string) Head {
	sig := ed25519.Sign(s.priv, HeadMessage(tenant, seq, hash))
	return Head{Seq: seq, EntryHash: hash, KeyID: s.kid, Algorithm: "Ed25519", Signature: base64.RawURLEncoding.EncodeToString(sig)}
}

// tape builds n linked entries from position from.
func tape(from int64, n int, prev string) []Entry {
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		seq := from + int64(i)
		e := Entry{Seq: seq, PrevHash: prev, ID: "id-" + strconv.FormatInt(seq, 10), Actor: "alice", Action: "user.login",
			Resource: "user:alice", RecordedAt: "2026-10-30T10:00:00.123456Z", Metadata: `{"ip": "10.0.0.1"}`}
		e.EntryHash = EntryHash(e.PrevHash, e.ID, e.Actor, e.Action, e.Resource, e.RecordedAt, []byte(e.Metadata))
		prev = e.EntryHash
		out = append(out, e)
	}
	return out
}

func signedBundle(t *testing.T) (Bundle, signer) {
	t.Helper()
	s := newSigner(t)
	entries := tape(1, 5, "")
	return Bundle{Format: Format, TenantID: testTenant, Entries: entries,
		Heads: []Head{s.head(testTenant, 4, entries[3].EntryHash)}, Keys: []Key{s.key()}}, s
}

func wantFailure(t *testing.T, r Report, contains string) {
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

func TestAnUntouchedBundlePasses(t *testing.T) {
	b, _ := signedBundle(t)
	r := Verify(b, Options{})
	if !r.OK {
		t.Fatalf("failures: %q", r.Failures)
	}
	if r.FromSeq != 1 || r.ToSeq != 5 || r.SignedTo != 4 || r.Unsigned != 1 || !r.ChainStartsAtGenesis {
		t.Errorf("report = %+v", r)
	}
}

func TestAChangedEntryFails(t *testing.T) {
	b, _ := signedBundle(t)
	b.Entries[2].Actor = "mallory"
	wantFailure(t, Verify(b, Options{}), "the entry was changed")
}

func TestARemovedEntryFails(t *testing.T) {
	b, _ := signedBundle(t)
	b.Entries = append(b.Entries[:2], b.Entries[3:]...)
	wantFailure(t, Verify(b, Options{}), "entries are missing")
}

// A careful editor recomputes every hash after the change, so the links all hold. The signature is what
// still disagrees.
func TestARecomputedTapeFailsAgainstItsSignedHead(t *testing.T) {
	b, _ := signedBundle(t)
	forged := tape(1, 5, "")
	forged[1].Actor = "mallory"
	prev := forged[0].EntryHash
	for i := 1; i < len(forged); i++ {
		e := &forged[i]
		e.PrevHash = prev
		e.EntryHash = EntryHash(e.PrevHash, e.ID, e.Actor, e.Action, e.Resource, e.RecordedAt, []byte(e.Metadata))
		prev = e.EntryHash
	}
	b.Entries = forged
	wantFailure(t, Verify(b, Options{}), "rewritten after signing")
}

func TestAForgedSignatureFails(t *testing.T) {
	b, _ := signedBundle(t)
	other := newSigner(t)
	b.Heads = []Head{other.head(testTenant, 4, b.Entries[3].EntryHash)}
	wantFailure(t, Verify(b, Options{}), "does not verify")
}

func TestAHeadSignedForAnotherTenantFails(t *testing.T) {
	b, s := signedBundle(t)
	b.Heads = []Head{s.head("22222222-2222-2222-2222-222222222222", 4, b.Entries[3].EntryHash)}
	wantFailure(t, Verify(b, Options{}), "does not verify")
}

func TestARevokedKeyFails(t *testing.T) {
	b, _ := signedBundle(t)
	b.Keys[0].Status = "disabled"
	wantFailure(t, Verify(b, Options{}), "revoked")
}

func TestAMissingKeyFails(t *testing.T) {
	b, _ := signedBundle(t)
	b.Keys = nil
	wantFailure(t, Verify(b, Options{}), "not in the bundle")
}

func TestAWrongFormatFails(t *testing.T) {
	b, _ := signedBundle(t)
	b.Format = "something.else"
	wantFailure(t, Verify(b, Options{}), "format")
}

// The attack only an outside copy catches: the whole tape rewritten and signed again with the real key.
func TestAHeadYouSavedCatchesARewriteMadeWithTheRealKey(t *testing.T) {
	b, s := signedBundle(t)
	saved := b.Heads[0]

	forged := tape(1, 5, "x")
	b.Entries = forged
	b.Heads = []Head{s.head(testTenant, 4, forged[3].EntryHash)}
	if r := Verify(b, Options{}); !r.OK {
		t.Fatalf("without a saved head this rewrite is invisible, and should pass: %q", r.Failures)
	}
	wantFailure(t, Verify(b, Options{Saved: []Head{saved}}), "the tape was rewritten")
}

func TestAHeadYouSavedCatchesEntriesRemovedFromTheEnd(t *testing.T) {
	b, s := signedBundle(t)
	saved := s.head(testTenant, 9, "later")
	wantFailure(t, Verify(b, Options{Saved: []Head{saved}}), "removed from the end")
}

func TestAMatchingSavedHeadIsCounted(t *testing.T) {
	b, _ := signedBundle(t)
	r := Verify(b, Options{Saved: b.Heads})
	if !r.OK || r.SavedChecked != 1 {
		t.Fatalf("report = %+v", r)
	}
}

// Retention removes the start of a chain: the rest still verifies, and the report says what is not covered.
func TestAPrunedStartIsReportedNotFailed(t *testing.T) {
	s := newSigner(t)
	entries := tape(100, 3, "older")
	b := Bundle{Format: Format, TenantID: testTenant, Entries: entries,
		Heads: []Head{s.head(testTenant, 102, entries[2].EntryHash)}, Keys: []Key{s.key()}}
	r := Verify(b, Options{})
	if !r.OK || r.ChainStartsAtGenesis || len(r.Notes) == 0 {
		t.Fatalf("report = %+v", r)
	}
}

func certFor(t *testing.T, pub ed25519.PublicKey, issuer *x509.Certificate, issuerKey ed25519.PrivateKey, isCA bool) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	parent := issuer
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestARootIsPinned(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	root := certFor(t, rootPub, nil, rootPriv, true)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	b, s := signedBundle(t)

	wantFailure(t, Verify(b, Options{Root: pool}), "no certificate")

	leaf := certFor(t, s.pub, root, rootPriv, false)
	b.Keys[0].X5C = []string{base64.StdEncoding.EncodeToString(leaf.Raw)}
	r := Verify(b, Options{Root: pool})
	if !r.OK || !r.Certified {
		t.Fatalf("report = %+v", r)
	}

	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	stranger := certFor(t, otherPub, nil, otherPriv, true)
	b.Keys[0].X5C = []string{base64.StdEncoding.EncodeToString(certFor(t, s.pub, stranger, otherPriv, false).Raw)}
	wantFailure(t, Verify(b, Options{Root: pool}), "does not chain")

	wrongKey := certFor(t, otherPub, root, rootPriv, false)
	b.Keys[0].X5C = []string{base64.StdEncoding.EncodeToString(wrongKey.Raw)}
	wantFailure(t, Verify(b, Options{Root: pool}), "different key")
}

// A retired key's certificate expires, and what it signed while valid still stands.
func TestACertificateIsJudgedWhenTheHeadWasSigned(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	root := certFor(t, rootPub, nil, rootPriv, true)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	b, s := signedBundle(t)
	leaf := certFor(t, s.pub, root, rootPriv, false) // valid for an hour either side of now
	b.Keys[0].X5C = []string{base64.StdEncoding.EncodeToString(leaf.Raw)}

	b.Heads[0].SignedAt = time.Now().Format(time.RFC3339)
	if r := Verify(b, Options{Root: pool}); !r.OK {
		t.Fatalf("signed while valid: %q", r.Failures)
	}
	b.Heads[0].SignedAt = time.Now().Add(48 * time.Hour).Format(time.RFC3339)
	wantFailure(t, Verify(b, Options{Root: pool}), "does not chain")
}

// Certificates are renewed and only the newest is listed, so an old head predates the one it is judged by.
func TestACertificateIssuedAfterTheHeadStillNamesTheKey(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	root := certFor(t, rootPub, nil, rootPriv, true)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	b, s := signedBundle(t)
	leaf := certFor(t, s.pub, root, rootPriv, false)
	b.Keys[0].X5C = []string{base64.StdEncoding.EncodeToString(leaf.Raw)}
	b.Heads[0].SignedAt = time.Now().Add(-48 * time.Hour).Format(time.RFC3339)

	r := Verify(b, Options{Root: pool})
	if !r.OK || !r.Certified {
		t.Fatalf("a head older than the certificate: %q", r.Failures)
	}
}

// A head saved after the bundle was made, or past a window that was asked to end sooner, is not evidence of
// anything. A false alarm of tampering would teach people to ignore a true one.
func TestASavedHeadPastTheBundleFailsOnlyWhenTheBundleShouldReachIt(t *testing.T) {
	b, _ := signedBundle(t)
	b.GeneratedAt = "2026-10-30T12:00:00Z"
	past := b.Entries[len(b.Entries)-1].Seq + 1
	saved := func(signedAt string) []Head { return []Head{{Seq: past, EntryHash: "h", SignedAt: signedAt}} }

	if r := Verify(b, Options{Saved: saved("2026-10-30T12:00:01Z")}); !r.OK {
		t.Fatalf("a head signed after the bundle: %q", r.Failures)
	}
	wantFailure(t, Verify(b, Options{Saved: saved("2026-10-30T11:59:59Z")}), "removed from the end")
	wantFailure(t, Verify(b, Options{Saved: saved("")}), "removed from the end")

	b.RequestedToSeq = past - 1
	if r := Verify(b, Options{Saved: saved("2026-10-30T11:59:59Z")}); !r.OK {
		t.Fatalf("a window asked to end before the head: %q", r.Failures)
	}
	b.RequestedToSeq = past
	wantFailure(t, Verify(b, Options{Saved: saved("2026-10-30T12:00:01Z")}), "removed from the end")
}

// Anyone must be able to read and rerun this package, so it stays on the standard library.
func TestThePackageImportsOnlyTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			if path := strings.Trim(imp.Path.Value, `"`); strings.Contains(path, ".") {
				t.Errorf("%s imports %s", f, path)
			}
		}
	}
}
