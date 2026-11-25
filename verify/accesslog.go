package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The access transparency log is one Merkle tree per region holding every privileged act on any of its tenants:
//
//	leaf      = "authfi.access-transparency.leaf.v1" then each field as a 4-byte big-endian length and its bytes:
//	            salt, log_id, tenant_id, tenant_seq, prev_leaf_hash, recorded_at, class, action, actor, resource,
//	            justification, tape_seq, tape_entry_hash
//	leaf_hash = hex(sha256(0x00 || leaf))
//	tree head = "authfi.access-transparency.tree-head.v1" LF log_id LF tree_size LF root_hash LF timestamp, Ed25519
//
// tenant_seq and tape_seq are decimal, and tape_seq is empty when the act has no tape entry. A tenant's entries are
// chained inside the shared tree: prev_leaf_hash is the leaf_hash of the tenant's entry before, empty for its first.
const (
	// AccessFormat names the access transparency proof bundle and is versioned with it.
	AccessFormat = "authfi.access-transparency.proof.v1"
	// AccessLeafPrefix starts every leaf, and versions it.
	AccessLeafPrefix = "authfi.access-transparency.leaf.v1"
	// TreeHeadPrefix names what a signed tree head says, and versions it. It has newlines, so it is never a JWS
	// signing input, and it differs from HeadPrefix, so a tape head cannot pass as a tree head.
	TreeHeadPrefix = "authfi.access-transparency.tree-head.v1"
	// UseAccessTransparency is the key use that may sign tree heads, and nothing else.
	UseAccessTransparency = "access_transparency"
	// maxLeafField bounds one field of a leaf, so a leaf cannot be made large enough to matter.
	maxLeafField = 1 << 16
)

// AccessEntry is one privileged act on the tenant, with the proof that the log holds it. Hashes are lowercase hex.
type AccessEntry struct {
	LeafIndex     int64    `json:"leaf_index"`
	TenantSeq     int64    `json:"tenant_seq"`
	PrevLeafHash  string   `json:"prev_leaf_hash"`
	Salt          string   `json:"salt"`
	RecordedAt    string   `json:"recorded_at"`
	Class         string   `json:"class"`
	Action        string   `json:"action"`
	Actor         string   `json:"actor"`
	Resource      string   `json:"resource"`
	Justification string   `json:"justification,omitempty"`
	TapeSeq       int64    `json:"tape_seq,omitempty"`
	TapeEntryHash string   `json:"tape_entry_hash,omitempty"`
	LeafHash      string   `json:"leaf_hash"`
	Inclusion     []string `json:"inclusion"`
}

// TreeHead is a signed head of the log. Signature is base64url without padding; RootHash is lowercase hex.
type TreeHead struct {
	LogID     string `json:"log_id"`
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	Timestamp string `json:"timestamp"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

// Consistency proves that the bundle's head extends an earlier head of FromSize leaves and root FromRoot.
type Consistency struct {
	FromSize int64    `json:"from_size"`
	FromRoot string   `json:"from_root"`
	Proof    []string `json:"proof"`
}

// AccessBundle is a tenant's entries in the log, with the head they are proven against.
type AccessBundle struct {
	Format      string        `json:"format"`
	LogID       string        `json:"log_id"`
	TenantID    string        `json:"tenant_id"`
	GeneratedAt string        `json:"generated_at,omitempty"`
	Head        TreeHead      `json:"head"`
	Entries     []AccessEntry `json:"entries"`
	Consistency []Consistency `json:"consistency,omitempty"`
	Keys        []Key         `json:"keys"`
	Notes       []string      `json:"notes,omitempty"`
}

// AccessOptions are what the person checking brings: the pinned root and the tree heads they saved earlier.
type AccessOptions struct {
	Root  *x509.CertPool
	Saved []TreeHead
}

// AccessReport is the outcome of VerifyAccessLog. OK is false once anything in Failures is set.
type AccessReport struct {
	OK bool
	// TreeSize is the size of the head the entries are proven against.
	TreeSize int64
	// Entries is how many entries were checked, and Included how many of them the head proves.
	Entries, Included int
	// FromSeq and ToSeq bound the tenant positions checked; 0 when there were none.
	FromSeq, ToSeq int64
	// ChainStartsAtGenesis is true when the first entry is the tenant's first ever.
	ChainStartsAtGenesis bool
	// Certified is true when a root was given and the head's key chained to it.
	Certified bool
	// SavedChecked is how many saved heads were proven consistent with the bundle's head.
	SavedChecked int
	Failures     []string
	Notes        []string
}

// AccessLeaf is the exact bytes hashed for entry e of the tenant in log logID.
func AccessLeaf(logID, tenant string, e AccessEntry) []byte {
	tapeSeq := ""
	if e.TapeSeq != 0 {
		tapeSeq = strconv.FormatInt(e.TapeSeq, 10)
	}
	fields := []string{e.Salt, logID, tenant, strconv.FormatInt(e.TenantSeq, 10), e.PrevLeafHash, e.RecordedAt,
		e.Class, e.Action, e.Actor, e.Resource, e.Justification, tapeSeq, e.TapeEntryHash}
	out := []byte(AccessLeafPrefix)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

// AccessLeafHash is the hex leaf hash of entry e, or an error when a field is too long to be a leaf.
func AccessLeafHash(logID, tenant string, e AccessEntry) (string, error) {
	for _, f := range []string{e.Salt, e.PrevLeafHash, e.RecordedAt, e.Class, e.Action, e.Actor, e.Resource, e.Justification, e.TapeEntryHash} {
		if len(f) > maxLeafField {
			return "", fmt.Errorf("a field of the entry is longer than %d bytes", maxLeafField)
		}
	}
	return hex.EncodeToString(HashLeaf(AccessLeaf(logID, tenant, e))), nil
}

// TreeHeadMessage is the exact bytes signed for a tree head.
func TreeHeadMessage(logID string, size int64, rootHash, timestamp string) []byte {
	return []byte(TreeHeadPrefix + "\n" + logID + "\n" + strconv.FormatInt(size, 10) + "\n" + rootHash + "\n" + timestamp)
}

// ParseTreeHeadMessage reads a tree head message back into its log id, size, root and time, refusing any other
// shape: a log id or timestamp with a newline, a negative size, a root that is not 32 bytes of lowercase hex, or a
// timestamp that is not RFC 3339 in UTC.
func ParseTreeHeadMessage(msg []byte) (logID string, size int64, root []byte, at time.Time, err error) {
	parts := strings.Split(string(msg), "\n")
	if len(parts) != 5 || parts[0] != TreeHeadPrefix || parts[1] == "" {
		return "", 0, nil, time.Time{}, fmt.Errorf("not a tree head")
	}
	size, err = strconv.ParseInt(parts[2], 10, 64)
	if err != nil || size < 0 || strconv.FormatInt(size, 10) != parts[2] {
		return "", 0, nil, time.Time{}, fmt.Errorf("the tree size is not a canonical number")
	}
	root, err = decodeHash(parts[3])
	if err != nil {
		return "", 0, nil, time.Time{}, err
	}
	at, err = time.Parse(time.RFC3339, parts[4])
	if err != nil || at.UTC().Format(time.RFC3339) != parts[4] {
		return "", 0, nil, time.Time{}, fmt.Errorf("the timestamp is not RFC 3339 in UTC, to the second")
	}
	return parts[1], size, root, at, nil
}

// decodeHash reads a 32-byte hash written as lowercase hex.
func decodeHash(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return nil, fmt.Errorf("%q is not a 32-byte hash in lowercase hex", s)
	}
	return b, nil
}

// decodeHashes reads each element of a proof.
func decodeHashes(in []string) ([][]byte, error) {
	out := make([][]byte, 0, len(in))
	for _, s := range in {
		b, err := decodeHash(s)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// CheckTreeHead checks h's signature under the access transparency key it names in keys, and returns that key and
// the head's root and time.
func CheckTreeHead(h TreeHead, keys []Key) (Key, []byte, time.Time, error) {
	if h.Algorithm != "Ed25519" {
		return Key{}, nil, time.Time{}, fmt.Errorf("signed with %q; only Ed25519 is accepted", h.Algorithm)
	}
	msg := TreeHeadMessage(h.LogID, h.TreeSize, h.RootHash, h.Timestamp)
	if _, _, _, _, err := ParseTreeHeadMessage(msg); err != nil {
		return Key{}, nil, time.Time{}, err
	}
	k, err := keyFor(keys, h.KeyID, UseAccessTransparency, "a tree head")
	if err != nil {
		return Key{}, nil, time.Time{}, err
	}
	pub, err := publicKey(k)
	if err != nil {
		return Key{}, nil, time.Time{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(h.Signature)
	if err != nil {
		return Key{}, nil, time.Time{}, fmt.Errorf("the signature is not base64url")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return Key{}, nil, time.Time{}, fmt.Errorf("the signature does not verify under key %s", h.KeyID)
	}
	_, _, root, at, _ := ParseTreeHeadMessage(msg)
	return k, root, at, nil
}

// VerifyAccessLog checks b: every entry's leaf, the tenant's chain of entries, each entry's inclusion under the
// signed head, the head's key, and that every head the person saved is the same log as the bundle's head.
func VerifyAccessLog(b AccessBundle, o AccessOptions) AccessReport {
	r := AccessReport{Entries: len(b.Entries), TreeSize: b.Head.TreeSize}
	fail := func(format string, args ...any) { r.Failures = append(r.Failures, fmt.Sprintf(format, args...)) }
	for _, n := range b.Notes {
		r.Notes = append(r.Notes, "the maker of this bundle says: "+n)
	}
	if b.Format != AccessFormat {
		fail("the bundle's format is %q, this verifier reads %q", b.Format, AccessFormat)
	}
	if b.TenantID == "" || b.LogID == "" {
		fail("the bundle names no tenant or no log")
	}
	if b.Head.LogID != b.LogID {
		fail("the head is of log %q, the bundle of log %q", b.Head.LogID, b.LogID)
	}

	headKey, root, headAt, err := CheckTreeHead(b.Head, b.Keys)
	if err != nil {
		fail("the tree head: %v", err)
	}
	headOK := err == nil

	checkAccessEntries(b, root, headOK, &r, fail)
	if headOK {
		checkHeadKey(headKey, headAt, o.Root, &r, fail)
		checkSavedHeads(b, root, o.Saved, &r, fail)
	}
	r.OK = len(r.Failures) == 0
	return r
}

// checkAccessEntries checks each entry's leaf and chain link, and its inclusion when the head verified.
func checkAccessEntries(b AccessBundle, root []byte, headOK bool, r *AccessReport, fail func(string, ...any)) {
	seen := make(map[int64]bool, len(b.Entries))
	for i, e := range b.Entries {
		if i == 0 {
			r.FromSeq = e.TenantSeq
			r.ChainStartsAtGenesis = e.TenantSeq == 1 && e.PrevLeafHash == ""
		} else {
			before := b.Entries[i-1]
			if e.TenantSeq != before.TenantSeq+1 {
				fail("the tenant's entries jump from position %d to %d: entries are missing", before.TenantSeq, e.TenantSeq)
			}
			if e.PrevLeafHash != before.LeafHash {
				fail("the tenant's entry %d does not link to the one before it", e.TenantSeq)
			}
		}
		r.ToSeq = e.TenantSeq
		if e.TenantSeq == 1 && e.PrevLeafHash != "" {
			fail("the tenant's first entry links to an entry before it")
		}
		got, err := AccessLeafHash(b.LogID, b.TenantID, e)
		if err != nil {
			fail("the tenant's entry %d: %v", e.TenantSeq, err)
			continue
		}
		if got != e.LeafHash {
			fail("the tenant's entry %d says something other than what was hashed: the entry was changed", e.TenantSeq)
			continue
		}
		if seen[e.LeafIndex] {
			fail("two entries claim leaf %d", e.LeafIndex)
			continue
		}
		seen[e.LeafIndex] = true
		if !headOK {
			continue
		}
		leaf, _ := hex.DecodeString(e.LeafHash)
		proof, err := decodeHashes(e.Inclusion)
		if err == nil {
			err = VerifyInclusion(e.LeafIndex, b.Head.TreeSize, leaf, proof, root)
		}
		if err != nil {
			fail("the tenant's entry %d is not in the log the head signs: %v", e.TenantSeq, err)
			continue
		}
		r.Included++
	}
	if len(b.Entries) > 0 && !r.ChainStartsAtGenesis {
		r.Notes = append(r.Notes, fmt.Sprintf("the tenant's entries before position %d are not in this bundle", r.FromSeq))
	}
}

// checkHeadKey checks the head key's certificate when a root is pinned.
func checkHeadKey(k Key, at time.Time, root *x509.CertPool, r *AccessReport, fail func(string, ...any)) {
	if root == nil {
		r.Notes = append(r.Notes, "no root was given, so the head's signature was checked but not who holds the key")
		return
	}
	if err := checkCertified(k, root, at); err != nil {
		fail("%s key %s: %v", UseAccessTransparency, k.Kid, err)
		return
	}
	r.Certified = true
}

// checkSavedHeads proves every head the person saved is an earlier state of the bundle's log, and checks every
// consistency proof the bundle carries.
func checkSavedHeads(b AccessBundle, root []byte, saved []TreeHead, r *AccessReport, fail func(string, ...any)) {
	proofs := make(map[int64]Consistency, len(b.Consistency))
	for _, c := range b.Consistency {
		if err := checkConsistency(c, b.Head.TreeSize, root); err != nil {
			fail("the bundle's consistency proof from %d leaves: %v", c.FromSize, err)
			continue
		}
		proofs[c.FromSize] = c
	}
	made, madeErr := time.Parse(time.RFC3339, b.GeneratedAt)
	for _, s := range saved {
		if s.LogID != b.LogID {
			r.Notes = append(r.Notes, fmt.Sprintf("the head you saved of size %d is of log %q, not this bundle's", s.TreeSize, s.LogID))
			continue
		}
		_, savedRoot, savedAt, err := CheckTreeHead(s, b.Keys)
		if err != nil {
			fail("the head you saved of size %d: %v", s.TreeSize, err)
			continue
		}
		switch {
		case s.TreeSize == b.Head.TreeSize:
			if s.RootHash != b.Head.RootHash {
				fail("the head you saved of size %d names another root than this bundle's: the log shows you a different history", s.TreeSize)
				continue
			}
		case s.TreeSize > b.Head.TreeSize:
			if madeErr == nil && !savedAt.After(made) {
				fail("you hold a head of size %d signed before this bundle was made, and the bundle's head is smaller: the log was rolled back", s.TreeSize)
			} else {
				r.Notes = append(r.Notes, fmt.Sprintf("the head you saved of size %d is newer than this bundle: download a newer bundle to check it", s.TreeSize))
			}
			continue
		default:
			c, ok := proofs[s.TreeSize]
			if !ok {
				r.Notes = append(r.Notes, fmt.Sprintf("the bundle carries no consistency proof from size %d: download it again asking for that size", s.TreeSize))
				continue
			}
			if c.FromRoot != hex.EncodeToString(savedRoot) {
				fail("the bundle's proof from size %d starts at another root than the head you saved: the log shows you a different history", s.TreeSize)
				continue
			}
		}
		r.SavedChecked++
	}
}

// checkConsistency checks one consistency proof against the bundle's head.
func checkConsistency(c Consistency, size int64, root []byte) error {
	from, err := decodeHash(c.FromRoot)
	if err != nil {
		return err
	}
	proof, err := decodeHashes(c.Proof)
	if err != nil {
		return err
	}
	return VerifyConsistency(c.FromSize, size, from, root, proof)
}
