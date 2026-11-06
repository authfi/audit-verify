package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// backfillHead is a head signed after the fact, the way the audit signer asks kms to.
func (s signer) backfillHead(tenant string, seq int64, hash string) Head {
	sig := ed25519.Sign(s.priv, BackfillHeadMessage(tenant, seq, hash))
	return Head{Seq: seq, EntryHash: hash, KeyID: s.kid, Algorithm: "Ed25519", Backfilled: true,
		Signature: base64.RawURLEncoding.EncodeToString(sig)}
}

func backfilledBundle(t *testing.T) (Bundle, signer) {
	t.Helper()
	s := newSigner(t)
	entries := tape(1, 8, "")
	return Bundle{Format: Format, TenantID: testTenant, Entries: entries, Keys: []Key{s.key()},
		Heads: []Head{s.backfillHead(testTenant, 5, entries[4].EntryHash)}}, s
}

// A backfilled head carries a bundle exactly as an ordinary one does, and the report says it was signed after the fact.
func TestABackfilledHeadVerifiesAndIsReported(t *testing.T) {
	b, _ := backfilledBundle(t)
	r := Verify(b, Options{})
	if !r.OK || r.SignedTo != 5 || r.Backfilled != 1 {
		t.Fatalf("report = %+v", r)
	}
	var noted bool
	for _, n := range r.Notes {
		noted = noted || strings.Contains(n, "after the fact")
	}
	if !noted {
		t.Errorf("notes = %q: a backfilled head was not called out", r.Notes)
	}
}

// The mark is inside the signed bytes: clearing it, or putting it on an ordinary head, fails the signature.
func TestTheBackfillMarkCannotBeClearedOrAdded(t *testing.T) {
	b, s := backfilledBundle(t)
	b.Heads[0].Backfilled = false
	wantFailure(t, Verify(b, Options{}), "does not verify")

	ordinary, _ := signedBundle(t)
	ordinary.Heads[0].Backfilled = true
	wantFailure(t, Verify(ordinary, Options{}), "does not verify")

	same, _ := backfilledBundle(t)
	same.Heads = []Head{s.head(testTenant, 5, same.Entries[4].EntryHash)}
	same.Keys = []Key{s.key()}
	if r := Verify(same, Options{}); !r.OK || r.Backfilled != 0 {
		t.Errorf("an ordinary head at the same position was not reported as ordinary: %+v", r)
	}
}

// An edit anywhere in the stretch a backfilled head covers is found: a changed entry breaks its own hash, and a tape
// recomputed from the edit onward disagrees with the head.
func TestAnEditInABackfilledStretchIsDetected(t *testing.T) {
	b, _ := backfilledBundle(t)
	b.Entries[1].Actor = "mallory"
	wantFailure(t, Verify(b, Options{}), "the entry was changed")

	forged, _ := backfilledBundle(t)
	rebuilt := tape(1, 8, "")
	rebuilt[1].Actor = "mallory"
	prev := rebuilt[0].EntryHash
	for i := 1; i < len(rebuilt); i++ {
		e := &rebuilt[i]
		e.PrevHash = prev
		e.EntryHash = EntryHash(e.PrevHash, e.ID, e.Actor, e.Action, e.Resource, e.RecordedAt, []byte(e.Metadata))
		prev = e.EntryHash
	}
	forged.Entries = rebuilt
	wantFailure(t, Verify(forged, Options{}), "rewritten after signing")
}

// A backfilled head for another tenant, or signed by a stranger's key, fails like any other head.
func TestABackfilledHeadForAnotherTenantOrKeyFails(t *testing.T) {
	b, s := backfilledBundle(t)
	b.Heads = []Head{s.backfillHead("22222222-2222-2222-2222-222222222222", 5, b.Entries[4].EntryHash)}
	wantFailure(t, Verify(b, Options{}), "does not verify")

	c, _ := backfilledBundle(t)
	c.Heads = []Head{newSigner(t).backfillHead(testTenant, 5, c.Entries[4].EntryHash)}
	wantFailure(t, Verify(c, Options{}), "does not verify")
}
