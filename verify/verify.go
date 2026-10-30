// Package verify checks a proof bundle of an AuthFI audit tape, without AuthFI.
//
// It holds no secret, calls nothing and imports only the standard library, so anyone can read it, run
// it and rewrite it from this description of the format:
//
//	entry_hash  = hex(sha256(prev_hash US id US actor US action US resource US recorded_at US metadata))
//	head signed = "authfi.audit.chain-head.v1" LF tenant LF seq LF entry_hash, with Ed25519
//
// US is the byte 0x1F, LF is 0x0A. recorded_at and metadata are the exact strings in the bundle.
//
// What a passing result means: the entries in the bundle link to each other, each says what was hashed,
// and a key signed the position it claims. Pin the AuthFI root to know whose key that was. Keep the heads
// your log stream receives to know the tape was not rewritten as a whole: a head you saved earlier
// disagrees with any later rewrite, even one made with the signing key.
//
// A key's certificate is judged at the head's signed_at, as the bundle states it, because a retired key's
// certificate expires and what it signed while valid still stands.
//
// What it cannot say: that an entry was true when it was written, or anything about entries outside the
// bundle.
package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// Format names this bundle shape and is versioned with it.
const Format = "authfi.audit.proof.v1"

// HeadPrefix names what a signed chain head says, and versions it. The message has newlines, so it can
// never be read as a JWS signing input.
const HeadPrefix = "authfi.audit.chain-head.v1"

const keyRevoked = "disabled"

// Entry is one chain entry and the audit event it attests.
type Entry struct {
	Seq        int64  `json:"seq"`
	PrevHash   string `json:"prev_hash"`
	EntryHash  string `json:"entry_hash"`
	ID         string `json:"id"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	Resource   string `json:"resource"`
	RecordedAt string `json:"recorded_at"`
	Metadata   string `json:"metadata,omitempty"`
}

// Head is a signed chain head. Signature is base64url without padding.
type Head struct {
	Seq       int64  `json:"seq"`
	EntryHash string `json:"entry_hash"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
	SignedAt  string `json:"signed_at,omitempty"`
}

// Key is a public key that may have signed a head, as a JWK. X5C is the custody certificate and its
// issuers, standard base64 DER, leaf first; empty when the key is not certified.
type Key struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	Kid    string   `json:"kid"`
	X      string   `json:"x"`
	X5C    []string `json:"x5c,omitempty"`
	Status string   `json:"status,omitempty"`
}

// Bundle is a window of a tenant's tape with what vouches for it.
type Bundle struct {
	Format      string `json:"format"`
	TenantID    string `json:"tenant_id"`
	GeneratedAt string `json:"generated_at,omitempty"`
	// RequestedToSeq is the position this bundle was asked to reach; 0 when it was asked for the newest.
	RequestedToSeq int64   `json:"requested_to_seq,omitempty"`
	Entries        []Entry `json:"entries"`
	Heads          []Head  `json:"heads"`
	Keys           []Key   `json:"keys"`
}

// Options are what the person checking brings. Both are optional, and each adds a check.
type Options struct {
	// Root is the pinned trust anchor. When set, every key that signed a head in the bundle must chain to it.
	Root *x509.CertPool
	// Saved are heads kept outside AuthFI, such as those a log stream delivered.
	Saved []Head
}

// Report is the outcome. OK is false once anything in Failures is set.
type Report struct {
	OK bool
	// FromSeq and ToSeq bound the entries checked; 0 when there were none.
	FromSeq, ToSeq int64
	Entries        int
	// SignedTo is the highest position in the bundle a good signature covers; 0 when none does.
	SignedTo int64
	// Unsigned is how many entries come after SignedTo. They are linked but nothing vouches for them yet.
	Unsigned int64
	// ChainStartsAtGenesis is true when the first entry has no predecessor. When false, older entries were
	// removed by retention or are outside this window.
	ChainStartsAtGenesis bool
	// Certified is true when a root was given and every signing key chained to it.
	Certified bool
	// SavedChecked is how many saved heads fell in the window and matched.
	SavedChecked int
	Failures     []string
	Notes        []string
}

// EntryHash is the chain's hash of one event, over the hash before it.
func EntryHash(prev, id, actor, action, resource, recordedAt string, metadata []byte) string {
	const us = "\x1f"
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte(us + id))
	h.Write([]byte(us + actor))
	h.Write([]byte(us + action))
	h.Write([]byte(us + resource))
	h.Write([]byte(us + recordedAt))
	h.Write([]byte(us))
	h.Write(metadata)
	return hex.EncodeToString(h.Sum(nil))
}

// HeadMessage is the exact bytes signed for a tenant's chain head at seq.
func HeadMessage(tenant string, seq int64, entryHash string) []byte {
	return []byte(HeadPrefix + "\n" + tenant + "\n" + strconv.FormatInt(seq, 10) + "\n" + entryHash)
}

// Verify checks b.
func Verify(b Bundle, o Options) Report {
	r := Report{Entries: len(b.Entries)}
	fail := func(format string, args ...any) { r.Failures = append(r.Failures, fmt.Sprintf(format, args...)) }

	if b.Format != Format {
		fail("the bundle's format is %q, this verifier reads %q", b.Format, Format)
	}
	if b.TenantID == "" {
		fail("the bundle names no tenant")
	}

	bySeq := make(map[int64]string, len(b.Entries))
	for i, e := range b.Entries {
		if i == 0 {
			r.FromSeq = e.Seq
			r.ChainStartsAtGenesis = e.PrevHash == ""
		} else {
			before := b.Entries[i-1]
			if e.Seq != before.Seq+1 {
				fail("entries jump from position %d to %d: entries are missing", before.Seq, e.Seq)
			}
			if e.PrevHash != before.EntryHash {
				fail("position %d does not link to the one before it", e.Seq)
			}
		}
		if got := EntryHash(e.PrevHash, e.ID, e.Actor, e.Action, e.Resource, e.RecordedAt, []byte(e.Metadata)); got != e.EntryHash {
			fail("position %d says something other than what was hashed: the entry was changed", e.Seq)
		}
		bySeq[e.Seq] = e.EntryHash
		r.ToSeq = e.Seq
	}

	keys := make(map[string]Key, len(b.Keys))
	for _, k := range b.Keys {
		keys[k.Kid] = k
	}
	// The newest time each key is said to have signed: a certificate is judged at that moment, because a
	// retired key's certificate expires and its old signatures still stand.
	usedKeys := map[string]time.Time{}
	for _, h := range b.Heads {
		if err := checkHead(b.TenantID, h, keys); err != nil {
			fail("the head at position %d: %v", h.Seq, err)
			continue
		}
		at, _ := time.Parse(time.RFC3339, h.SignedAt)
		if at.After(usedKeys[h.KeyID]) || usedKeys[h.KeyID].IsZero() {
			usedKeys[h.KeyID] = at
		}
		hash, inWindow := bySeq[h.Seq]
		if !inWindow {
			continue
		}
		if hash != h.EntryHash {
			fail("the entry at position %d is not the one that was signed: the tape was rewritten after signing", h.Seq)
			continue
		}
		if h.Seq > r.SignedTo {
			r.SignedTo = h.Seq
		}
	}
	if r.SignedTo == 0 {
		r.Notes = append(r.Notes, "no signed head covers these entries, so only the links between them were checked")
	} else {
		r.Unsigned = r.ToSeq - r.SignedTo
	}
	if !r.ChainStartsAtGenesis && len(b.Entries) > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("entries before position %d are not in this bundle", r.FromSeq))
	}

	if o.Root != nil {
		r.Certified = len(usedKeys) > 0
		for kid, at := range usedKeys {
			if err := checkCertified(keys[kid], o.Root, at); err != nil {
				r.Certified = false
				fail("key %s: %v", kid, err)
			}
		}
	} else if len(usedKeys) > 0 {
		r.Notes = append(r.Notes, "no root was given, so the signatures were checked but not who holds the key")
	}

	for _, s := range o.Saved {
		if s.Seq > r.ToSeq {
			if !shouldReach(b, s) {
				r.Notes = append(r.Notes, fmt.Sprintf("the head you saved at position %d is past this bundle, which ends at %d: download a newer bundle to check it", s.Seq, r.ToSeq))
				continue
			}
			fail("you hold a head at position %d, past the end of this bundle at %d: entries were removed from the end", s.Seq, r.ToSeq)
			continue
		}
		hash, inWindow := bySeq[s.Seq]
		if !inWindow {
			r.Notes = append(r.Notes, fmt.Sprintf("the head you saved at position %d is outside this bundle", s.Seq))
			continue
		}
		if hash != s.EntryHash {
			fail("the head you saved at position %d disagrees with this bundle: the tape was rewritten", s.Seq)
			continue
		}
		r.SavedChecked++
	}

	r.OK = len(r.Failures) == 0
	return r
}

// shouldReach reports whether b should contain the saved head: it was asked to reach that position, or it
// was asked for the newest and the head was signed before b was made. An older bundle or a narrower window
// ending short of a head says nothing about the tape.
func shouldReach(b Bundle, s Head) bool {
	if b.RequestedToSeq != 0 {
		return b.RequestedToSeq >= s.Seq
	}
	signed, err := time.Parse(time.RFC3339, s.SignedAt)
	if err != nil {
		return true
	}
	made, err := time.Parse(time.RFC3339, b.GeneratedAt)
	if err != nil {
		return true
	}
	return !signed.After(made)
}

// checkHead checks one head's signature under the key it names.
func checkHead(tenant string, h Head, keys map[string]Key) error {
	if h.Algorithm != "Ed25519" {
		return fmt.Errorf("signed with %q; only Ed25519 is accepted", h.Algorithm)
	}
	k, ok := keys[h.KeyID]
	if !ok {
		return fmt.Errorf("key %s is not in the bundle", h.KeyID)
	}
	if k.Status == keyRevoked {
		return fmt.Errorf("key %s was revoked, so its signature cannot be relied on", h.KeyID)
	}
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return fmt.Errorf("key %s is not an Ed25519 key", h.KeyID)
	}
	pub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("key %s has no usable public value", h.KeyID)
	}
	sig, err := base64.RawURLEncoding.DecodeString(h.Signature)
	if err != nil {
		return fmt.Errorf("the signature is not base64url")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), HeadMessage(tenant, h.Seq, h.EntryHash), sig) {
		return fmt.Errorf("the signature does not verify under key %s", h.KeyID)
	}
	return nil
}

// checkCertified checks that the key's certificate is for this key and chained to root at the given
// time. A zero time means now.
func checkCertified(k Key, root *x509.CertPool, at time.Time) error {
	if len(k.X5C) == 0 {
		return fmt.Errorf("it carries no certificate, so nothing says who holds it")
	}
	certs := make([]*x509.Certificate, 0, len(k.X5C))
	for i, raw := range k.X5C {
		der, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("certificate %d is not base64: %w", i, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("certificate %d does not parse: %w", i, err)
		}
		certs = append(certs, c)
	}
	leaf, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("its certificate is not for an Ed25519 key")
	}
	pub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || !leaf.Equal(ed25519.PublicKey(pub)) {
		return fmt.Errorf("its certificate is for a different key")
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: root, Intermediates: intermediates, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("its certificate does not chain to the root: %w", err)
	}
	return nil
}
