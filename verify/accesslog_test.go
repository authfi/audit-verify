package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testLog = "authfi-test-region"

// goldenLeafHash is the leaf hash of the entry in TestTheLeafFormatIsFixed.
const goldenLeafHash = "aa572f39219199cda69322e7a44e3b4bd7fc54798762221483d9a710a02d0c49"

// logWorld is a region's log of several tenants' acts, with the key that signs its heads.
type logWorld struct {
	t      *testing.T
	key    signer
	leaves [][]byte
	// mine are the leaf indexes and entries of testTenant.
	mine []AccessEntry
}

func (s signer) logKey() Key {
	k := s.key()
	k.Use = UseAccessTransparency
	return k
}

func (s signer) treeHead(size int64, root []byte, at time.Time) TreeHead {
	ts := at.UTC().Format(time.RFC3339)
	rh := hex.EncodeToString(root)
	sig := ed25519.Sign(s.priv, TreeHeadMessage(testLog, size, rh, ts))
	return TreeHead{LogID: testLog, TreeSize: size, RootHash: rh, Timestamp: ts, KeyID: s.kid, Algorithm: "Ed25519",
		Signature: base64.RawURLEncoding.EncodeToString(sig)}
}

// newLogWorld appends n leaves, every third one an act on testTenant and the rest other tenants' acts.
func newLogWorld(t *testing.T, n int) *logWorld {
	w := &logWorld{t: t, key: newSigner(t)}
	prev := ""
	for i := 0; i < n; i++ {
		if i%3 != 1 {
			w.leaves = append(w.leaves, []byte("another tenant's act "+strconv.Itoa(i)))
			continue
		}
		e := AccessEntry{LeafIndex: int64(i), TenantSeq: int64(len(w.mine) + 1), PrevLeafHash: prev,
			Salt: strings.Repeat("ab", 32), RecordedAt: "2026-11-25T10:00:00.123456Z", Class: "staff_access",
			Action: "federation.session.opened", Actor: "fed:00000000-0000-0000-0000-00000000000a:staff-1",
			Resource: "federation_trust:t1", Justification: "ticket 42", TapeSeq: int64(100 + i), TapeEntryHash: strings.Repeat("cd", 32)}
		e.LeafHash = hex.EncodeToString(HashLeaf(AccessLeaf(testLog, testTenant, e)))
		w.leaves = append(w.leaves, AccessLeaf(testLog, testTenant, e))
		w.mine = append(w.mine, e)
		prev = e.LeafHash
	}
	return w
}

func (w *logWorld) bundleAt(size int, at time.Time) AccessBundle {
	d := w.leaves[:size]
	entries := make([]AccessEntry, 0, len(w.mine))
	for _, e := range w.mine {
		if e.LeafIndex >= int64(size) {
			break
		}
		for _, p := range refPath(int(e.LeafIndex), d) {
			e.Inclusion = append(e.Inclusion, hex.EncodeToString(p))
		}
		entries = append(entries, e)
	}
	return AccessBundle{Format: AccessFormat, LogID: testLog, TenantID: testTenant, GeneratedAt: at.UTC().Format(time.RFC3339),
		Head: w.key.treeHead(int64(size), refMTH(d), at), Entries: entries, Keys: []Key{w.key.logKey()}}
}

func (w *logWorld) bundle() AccessBundle { return w.bundleAt(len(w.leaves), time.Now()) }

// withConsistency adds a proof from an earlier size to b.
func (w *logWorld) withConsistency(b AccessBundle, from int) AccessBundle {
	d := w.leaves[:b.Head.TreeSize]
	c := Consistency{FromSize: int64(from), FromRoot: hex.EncodeToString(refMTH(d[:from]))}
	for _, p := range refProof(from, d) {
		c.Proof = append(c.Proof, hex.EncodeToString(p))
	}
	b.Consistency = append(b.Consistency, c)
	return b
}

func wantAccessFailure(t *testing.T, r AccessReport, contains string) {
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

func TestAnUntouchedAccessBundlePasses(t *testing.T) {
	w := newLogWorld(t, 20)
	r := VerifyAccessLog(w.bundle(), AccessOptions{})
	if !r.OK || r.Included != len(w.mine) || r.Entries != len(w.mine) || !r.ChainStartsAtGenesis || r.TreeSize != 20 {
		t.Fatalf("report = %+v", r)
	}
}

func TestAChangedAccessEntryFails(t *testing.T) {
	for _, change := range []func(*AccessEntry){
		func(e *AccessEntry) { e.Actor = "someone else" },
		func(e *AccessEntry) { e.Justification = "" },
		func(e *AccessEntry) { e.Class = "routine" },
		func(e *AccessEntry) { e.RecordedAt = "2026-11-25T11:00:00.123456Z" },
		func(e *AccessEntry) { e.Salt = strings.Repeat("ef", 32) },
		func(e *AccessEntry) { e.TapeEntryHash = "" },
		func(e *AccessEntry) { e.TapeSeq = 0 },
	} {
		w := newLogWorld(t, 20)
		b := w.bundle()
		change(&b.Entries[2])
		wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "the entry was changed")
	}
}

// A rewritten entry whose leaf hash was recomputed is no longer the leaf the head signs.
func TestARecomputedAccessEntryFailsItsInclusion(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	b.Entries[2].Actor = "someone else"
	b.Entries[2].LeafHash = hex.EncodeToString(HashLeaf(AccessLeaf(testLog, testTenant, b.Entries[2])))
	r := VerifyAccessLog(b, AccessOptions{})
	wantAccessFailure(t, r, "is not in the log the head signs")
}

func TestAnEntryMovedToAnotherLeafFails(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	b.Entries[1].LeafIndex++
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "is not in the log the head signs")
}

func TestAnEntryOfAnotherTenantOrLogFails(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	b.TenantID = "22222222-2222-2222-2222-222222222222"
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "the entry was changed")
}

func TestAHiddenEntryBreaksTheTenantChain(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	b.Entries = append(b.Entries[:2], b.Entries[3:]...)
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "entries are missing")
}

func TestARelinkedChainFails(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	b.Entries[0], b.Entries[1] = b.Entries[1], b.Entries[0]
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "does not link")
}

func TestAPartOfTheChainIsANoteNotAFailure(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	b.Entries = b.Entries[2:]
	r := VerifyAccessLog(b, AccessOptions{})
	if !r.OK || r.ChainStartsAtGenesis || len(r.Notes) == 0 {
		t.Fatalf("report = %+v", r)
	}
}

func TestAForgedTreeHeadFails(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	b.Head.TreeSize = 19
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "does not verify")

	b = w.bundle()
	b.Head.Timestamp = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "does not verify")
}

// A tape head key, a receipt key or a revoked key may not vouch for the log.
func TestOnlyAnAccessTransparencyKeyMaySignAHead(t *testing.T) {
	for _, use := range []string{"", UseAuditHead, UseReceipt} {
		w := newLogWorld(t, 10)
		b := w.bundle()
		b.Keys[0].Use = use
		wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "may not sign a tree head")
	}
	w := newLogWorld(t, 10)
	b := w.bundle()
	b.Keys[0].Status = keyRevoked
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "revoked")
}

func TestATreeHeadIsNotATapeHead(t *testing.T) {
	s := newSigner(t)
	tape := HeadMessage(testTenant, 3, strings.Repeat("ab", 32))
	if _, _, _, _, err := ParseTreeHeadMessage(tape); err == nil {
		t.Fatal("a tape head parsed as a tree head")
	}
	h := s.treeHead(3, EmptyRoot(), time.Now())
	h.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, tape))
	if _, _, _, err := CheckTreeHead(h, []Key{s.logKey()}); err == nil {
		t.Fatal("a tape head's signature verified as a tree head")
	}
}

func TestATreeHeadMessageIsCanonical(t *testing.T) {
	root := hex.EncodeToString(EmptyRoot())
	good := TreeHeadMessage(testLog, 7, root, "2026-11-25T10:00:00Z")
	if _, size, _, _, err := ParseTreeHeadMessage(good); err != nil || size != 7 {
		t.Fatalf("size=%d err=%v", size, err)
	}
	for name, msg := range map[string][]byte{
		"empty":          []byte{},
		"size 07":        []byte(TreeHeadPrefix + "\n" + testLog + "\n07\n" + root + "\n2026-11-25T10:00:00Z"),
		"negative size":  TreeHeadMessage(testLog, -1, root, "2026-11-25T10:00:00Z"),
		"upper hex":      TreeHeadMessage(testLog, 7, strings.ToUpper(root), "2026-11-25T10:00:00Z"),
		"short root":     TreeHeadMessage(testLog, 7, root[:62], "2026-11-25T10:00:00Z"),
		"offset time":    TreeHeadMessage(testLog, 7, root, "2026-11-25T15:30:00+05:30"),
		"fractional":     TreeHeadMessage(testLog, 7, root, "2026-11-25T10:00:00.5Z"),
		"newline in log": TreeHeadMessage("a\nb", 7, root, "2026-11-25T10:00:00Z"),
		"no log":         TreeHeadMessage("", 7, root, "2026-11-25T10:00:00Z"),
		"another prefix": []byte(strings.Join([]string{HeadPrefix, testLog, "7", root, "2026-11-25T10:00:00Z"}, "\n")),
	} {
		if _, _, _, _, err := ParseTreeHeadMessage(msg); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}
}

func TestASavedHeadOfTheSameLogIsProvenConsistent(t *testing.T) {
	w := newLogWorld(t, 30)
	earlier := w.bundleAt(11, time.Now().Add(-time.Hour)).Head
	same := w.bundle().Head
	b := w.withConsistency(w.bundle(), 11)
	r := VerifyAccessLog(b, AccessOptions{Saved: []TreeHead{earlier, same}})
	if !r.OK || r.SavedChecked != 2 {
		t.Fatalf("report = %+v", r)
	}
}

// A log that shows the person checking one history and everybody else another is caught by any head they saved.
func TestASplitViewIsCaughtByASavedHead(t *testing.T) {
	w := newLogWorld(t, 30)
	saved := w.bundleAt(11, time.Now().Add(-time.Hour)).Head

	// The other view rewrote a leaf before 11 and was signed with the real key.
	other := newLogWorld(t, 30)
	other.key = w.key
	other.leaves[3] = []byte("history rewritten")
	b := other.withConsistency(other.bundle(), 11)
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{Saved: []TreeHead{saved}}), "different history")

	// The same size with another root.
	b = other.bundleAt(11, time.Now())
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{Saved: []TreeHead{saved}}), "different history")
}

func TestAConsistencyProofThatDoesNotHoldFails(t *testing.T) {
	w := newLogWorld(t, 30)
	b := w.withConsistency(w.bundle(), 11)
	b.Consistency[0].Proof[0] = hex.EncodeToString(flip(must(hex.DecodeString(b.Consistency[0].Proof[0]))))
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "consistency proof from 11")
}

func TestARolledBackLogIsCaughtByANewerSavedHead(t *testing.T) {
	w := newLogWorld(t, 30)
	newer := w.bundleAt(30, time.Now().Add(-time.Hour)).Head
	b := w.bundleAt(20, time.Now())
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{Saved: []TreeHead{newer}}), "rolled back")

	// An older bundle than the head is only a note.
	b = w.bundleAt(20, time.Now().Add(-2*time.Hour))
	if r := VerifyAccessLog(b, AccessOptions{Saved: []TreeHead{newer}}); !r.OK || r.SavedChecked != 0 {
		t.Fatalf("report = %+v", r)
	}
}

func TestASavedHeadWithNoProofFails(t *testing.T) {
	w := newLogWorld(t, 30)
	saved := w.bundleAt(11, time.Now().Add(-time.Hour)).Head
	r := VerifyAccessLog(w.bundle(), AccessOptions{Saved: []TreeHead{saved}})
	wantAccessFailure(t, r, "no consistency proof from the size 11 head")
	if r.SavedChecked != 0 {
		t.Fatalf("report = %+v", r)
	}
}

// generated_at is not signed, so stripping or backdating it must not turn a rollback into a note.
func TestARollbackIsJudgedOnTheSignedHeadTimeNotGeneratedAt(t *testing.T) {
	w := newLogWorld(t, 30)
	newer := w.bundleAt(30, time.Now().Add(-time.Hour)).Head
	for name, generatedAt := range map[string]string{
		"stripped":  "",
		"backdated": time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339),
	} {
		b := w.bundleAt(20, time.Now())
		b.GeneratedAt = generatedAt
		r := VerifyAccessLog(b, AccessOptions{Saved: []TreeHead{newer}})
		if r.OK {
			t.Fatalf("%s generated_at: passed, want rolled back", name)
		}
		wantAccessFailure(t, r, "rolled back")
	}
}

func TestAForgedSavedHeadFails(t *testing.T) {
	w := newLogWorld(t, 30)
	saved := w.bundleAt(11, time.Now().Add(-time.Hour)).Head
	saved.Signature = w.bundle().Head.Signature
	wantAccessFailure(t, VerifyAccessLog(w.withConsistency(w.bundle(), 11), AccessOptions{Saved: []TreeHead{saved}}), "the head you saved of size 11")
}

func TestTheAccessHeadKeyIsCertifiedAtTheHeadsTime(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	root := certFor(t, rootPub, nil, rootPriv, true)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	w := newLogWorld(t, 10)

	b := w.bundle()
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{Root: pool}), "no certificate")

	b.Keys[0].X5C = []string{base64.StdEncoding.EncodeToString(certFor(t, w.key.pub, root, rootPriv, false).Raw)}
	if r := VerifyAccessLog(b, AccessOptions{Root: pool}); !r.OK || !r.Certified {
		t.Fatalf("report = %+v", r)
	}

	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	stranger := certFor(t, otherPub, nil, otherPriv, true)
	b.Keys[0].X5C = []string{base64.StdEncoding.EncodeToString(certFor(t, w.key.pub, stranger, otherPriv, false).Raw)}
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{Root: pool}), "does not chain")
}

func TestAWrongAccessFormatFails(t *testing.T) {
	w := newLogWorld(t, 10)
	b := w.bundle()
	b.Format = Format
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "format")
}

func TestAnOverlongLeafFieldIsRefused(t *testing.T) {
	e := AccessEntry{Justification: strings.Repeat("x", maxLeafField+1)}
	if _, err := AccessLeafHash(testLog, testTenant, e); err == nil {
		t.Fatal("an overlong field hashed")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestTwoEntriesCannotClaimOneLeaf(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	dup := b.Entries[1]
	dup.TenantSeq, dup.PrevLeafHash = b.Entries[len(b.Entries)-1].TenantSeq+1, b.Entries[len(b.Entries)-1].LeafHash
	dup.LeafHash = hex.EncodeToString(HashLeaf(AccessLeaf(testLog, testTenant, dup)))
	b.Entries = append(b.Entries, dup)
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "two entries claim leaf")
}

func TestAFirstEntryThatLinksBackFails(t *testing.T) {
	w := newLogWorld(t, 20)
	b := w.bundle()
	b.Entries[0].PrevLeafHash = strings.Repeat("ab", 32)
	b.Entries[0].LeafHash = hex.EncodeToString(HashLeaf(AccessLeaf(testLog, testTenant, b.Entries[0])))
	r := VerifyAccessLog(b, AccessOptions{})
	wantAccessFailure(t, r, "first entry links")
	if r.ChainStartsAtGenesis {
		t.Fatal("a first entry that links back was called the start of the chain")
	}
}

func TestAHeadOfAnotherLogFails(t *testing.T) {
	w := newLogWorld(t, 10)
	b := w.bundle()
	b.LogID = "another-region"
	wantAccessFailure(t, VerifyAccessLog(b, AccessOptions{}), "the head is of log")
}

// A head whose signed bytes are not canonical is refused even when the signature over those bytes is good.
func TestASignedButNonCanonicalHeadIsRefused(t *testing.T) {
	s := newSigner(t)
	root := hex.EncodeToString(EmptyRoot())
	ts := "2026-11-25T10:00:00.5Z"
	h := TreeHead{LogID: testLog, TreeSize: 0, RootHash: root, Timestamp: ts, KeyID: s.kid, Algorithm: "Ed25519",
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, TreeHeadMessage(testLog, 0, root, ts)))}
	if _, _, _, err := CheckTreeHead(h, []Key{s.logKey()}); err == nil {
		t.Fatal("a non-canonical head was accepted")
	}
	h.Algorithm = "EdDSA"
	if _, _, _, err := CheckTreeHead(h, []Key{s.logKey()}); err == nil || !strings.Contains(err.Error(), "only Ed25519") {
		t.Fatalf("err = %v", err)
	}
}

// Each field is length-prefixed, so moving bytes from one field to the next is a different leaf.
func TestLeafFieldsCannotBeShifted(t *testing.T) {
	a := AccessEntry{Actor: "ab", Resource: "c"}
	b := AccessEntry{Actor: "a", Resource: "bc"}
	ha, _ := AccessLeafHash(testLog, testTenant, a)
	hb, _ := AccessLeafHash(testLog, testTenant, b)
	if ha == hb {
		t.Fatal("two entries that differ only in where a field ends hash the same")
	}
}

// The leaf format is fixed: this hash changes only with a new AccessLeafPrefix.
func TestTheLeafFormatIsFixed(t *testing.T) {
	e := AccessEntry{TenantSeq: 3, PrevLeafHash: strings.Repeat("01", 32), Salt: strings.Repeat("ab", 32),
		RecordedAt: "2026-11-25T10:00:00.123456Z", Class: "staff_access", Action: "federation.session.opened",
		Actor: "fed:a:b", Resource: "federation_trust:t", Justification: "ticket 42", TapeSeq: 9, TapeEntryHash: strings.Repeat("cd", 32)}
	got, err := AccessLeafHash(testLog, testTenant, e)
	if err != nil {
		t.Fatal(err)
	}
	if got != goldenLeafHash {
		t.Fatalf("leaf hash = %s, want %s", got, goldenLeafHash)
	}
}

// A head of another log, even one signed by the same key, says nothing about this one.
func TestASavedHeadOfAnotherLogIsANote(t *testing.T) {
	w := newLogWorld(t, 10)
	b := w.bundle()
	ts := time.Now().UTC().Format(time.RFC3339)
	root := strings.Repeat("ab", 32)
	other := TreeHead{LogID: "another-region", TreeSize: b.Head.TreeSize, RootHash: root, Timestamp: ts, KeyID: w.key.kid, Algorithm: "Ed25519",
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(w.key.priv, TreeHeadMessage("another-region", b.Head.TreeSize, root, ts)))}
	r := VerifyAccessLog(b, AccessOptions{Saved: []TreeHead{other}})
	if !r.OK || r.SavedChecked != 0 || !strings.Contains(strings.Join(r.Notes, "|"), "another-region") {
		t.Fatalf("report = %+v", r)
	}
}
