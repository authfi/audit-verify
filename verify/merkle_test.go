package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// The reference tree is RFC 9162's definitions written out directly (MTH, PATH, PROOF), over the whole list of
// leaves. It is slow on purpose: the verifier is checked against the text of the RFC, not against itself.

func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func refMTH(d [][]byte) []byte {
	switch len(d) {
	case 0:
		return EmptyRoot()
	case 1:
		return HashLeaf(d[0])
	}
	k := largestPowerOfTwoBelow(len(d))
	return HashChildren(refMTH(d[:k]), refMTH(d[k:]))
}

func refPath(m int, d [][]byte) [][]byte {
	if len(d) <= 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(len(d))
	if m < k {
		return append(refPath(m, d[:k]), refMTH(d[k:]))
	}
	return append(refPath(m-k, d[k:]), refMTH(d[:k]))
}

func refSubproof(m int, d [][]byte, b bool) [][]byte {
	n := len(d)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{refMTH(d)}
	}
	k := largestPowerOfTwoBelow(n)
	if m <= k {
		return append(refSubproof(m, d[:k], b), refMTH(d[k:]))
	}
	return append(refSubproof(m-k, d[k:], false), refMTH(d[:k]))
}

func refProof(m int, d [][]byte) [][]byte { return refSubproof(m, d, true) }

func testLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte("leaf " + strconv.Itoa(i))
	}
	return out
}

func flip(b []byte) []byte {
	c := bytes.Clone(b)
	c[0] ^= 1
	return c
}

func TestEveryInclusionProofOfTheReferenceTreeVerifies(t *testing.T) {
	for n := 1; n <= 70; n++ {
		d := testLeaves(n)
		root := refMTH(d)
		for m := 0; m < n; m++ {
			proof := refPath(m, d)
			leaf := HashLeaf(d[m])
			if err := VerifyInclusion(int64(m), int64(n), leaf, proof, root); err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			if err := VerifyInclusion(int64(m), int64(n), flip(leaf), proof, root); !errors.Is(err, ErrProof) {
				t.Fatalf("n=%d m=%d: a changed leaf verified", n, m)
			}
			if err := VerifyInclusion(int64(m), int64(n), leaf, proof, flip(root)); !errors.Is(err, ErrProof) {
				t.Fatalf("n=%d m=%d: another root verified", n, m)
			}
			if n > 1 {
				if err := VerifyInclusion(int64((m+1)%n), int64(n), leaf, proof, root); !errors.Is(err, ErrProof) {
					t.Fatalf("n=%d m=%d: the leaf verified at another index", n, m)
				}
				if err := VerifyInclusion(int64(m), int64(n), leaf, proof[:len(proof)-1], root); !errors.Is(err, ErrProof) {
					t.Fatalf("n=%d m=%d: a shortened proof verified", n, m)
				}
				bad := append([][]byte{}, proof...)
				bad[0] = flip(bad[0])
				if err := VerifyInclusion(int64(m), int64(n), leaf, bad, root); !errors.Is(err, ErrProof) {
					t.Fatalf("n=%d m=%d: a changed proof verified", n, m)
				}
			}
			if err := VerifyInclusion(int64(m), int64(n), leaf, append(proof, root), root); !errors.Is(err, ErrProof) {
				t.Fatalf("n=%d m=%d: a lengthened proof verified", n, m)
			}
		}
	}
}

func TestAnIndexOutsideTheTreeIsRefused(t *testing.T) {
	d := testLeaves(4)
	for _, idx := range []int64{-1, 4, 5} {
		if err := VerifyInclusion(idx, 4, HashLeaf(d[0]), refPath(0, d), refMTH(d)); !errors.Is(err, ErrProof) {
			t.Fatalf("index %d: err = %v", idx, err)
		}
	}
}

func TestEveryConsistencyProofOfTheReferenceTreeVerifies(t *testing.T) {
	for n := 1; n <= 70; n++ {
		d := testLeaves(n)
		root2 := refMTH(d)
		for m := 1; m <= n; m++ {
			root1 := refMTH(d[:m])
			proof := refProof(m, d)
			if err := VerifyConsistency(int64(m), int64(n), root1, root2, proof); err != nil {
				t.Fatalf("m=%d n=%d: %v", m, n, err)
			}
			if m == n {
				continue
			}
			if err := VerifyConsistency(int64(m), int64(n), flip(root1), root2, proof); !errors.Is(err, ErrProof) {
				t.Fatalf("m=%d n=%d: another first root verified", m, n)
			}
			if err := VerifyConsistency(int64(m), int64(n), root1, flip(root2), proof); !errors.Is(err, ErrProof) {
				t.Fatalf("m=%d n=%d: another second root verified", m, n)
			}
			for i := range proof {
				bad := append([][]byte{}, proof...)
				bad[i] = flip(bad[i])
				if err := VerifyConsistency(int64(m), int64(n), root1, root2, bad); !errors.Is(err, ErrProof) {
					t.Fatalf("m=%d n=%d: a proof changed at %d verified", m, n, i)
				}
			}
			if err := VerifyConsistency(int64(m), int64(n), root1, root2, proof[:len(proof)-1]); !errors.Is(err, ErrProof) {
				t.Fatalf("m=%d n=%d: a shortened proof verified", m, n)
			}
			if err := VerifyConsistency(int64(m), int64(n), root1, root2, append(proof, root2)); !errors.Is(err, ErrProof) {
				t.Fatalf("m=%d n=%d: a lengthened proof verified", m, n)
			}
		}
	}
}

func TestAForkIsNotConsistent(t *testing.T) {
	d := testLeaves(9)
	forked := append(testLeaves(5), []byte("rewritten"), d[6], d[7], d[8])
	// The fork shares the first 5 leaves, so it is consistent from 5 and not from 6.
	if err := VerifyConsistency(5, 9, refMTH(d[:5]), refMTH(forked), refProof(5, forked)); err != nil {
		t.Fatalf("the shared prefix: %v", err)
	}
	if err := VerifyConsistency(7, 9, refMTH(d[:7]), refMTH(forked), refProof(7, forked)); !errors.Is(err, ErrProof) {
		t.Fatal("a tree that rewrote leaf 5 was found consistent with the original of 7 leaves")
	}
}

func TestConsistencyEdgesAreRefusedOrAccepted(t *testing.T) {
	d := testLeaves(3)
	r := refMTH(d)
	cases := []struct {
		name         string
		size1, size2 int64
		root1, root2 []byte
		proof        [][]byte
		ok           bool
	}{
		{"equal sizes, equal roots", 3, 3, r, r, nil, true},
		{"equal sizes, other roots", 3, 3, r, flip(r), nil, false},
		{"equal sizes with a proof", 3, 3, r, r, [][]byte{r}, false},
		{"from the empty tree", 0, 3, EmptyRoot(), r, nil, true},
		{"from the empty tree with a proof", 0, 3, EmptyRoot(), r, [][]byte{r}, false},
		{"a smaller second tree", 3, 2, r, r, nil, false},
		{"an empty proof", 1, 3, HashLeaf(d[0]), r, nil, false},
	}
	for _, c := range cases {
		err := VerifyConsistency(c.size1, c.size2, c.root1, c.root2, c.proof)
		if (err == nil) != c.ok {
			t.Fatalf("%s: err = %v", c.name, err)
		}
	}
}

// RFC 9162's empty tree root is the SHA-256 of the empty string.
func TestTheEmptyRootIsTheHashOfNothing(t *testing.T) {
	if got := hex.EncodeToString(EmptyRoot()); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty root = %s", got)
	}
}

// Known answers: RFC 9162's leaf of no bytes, and a node is the hash of 0x01 and its two children.
func TestTheHashPrefixesAreRFC9162s(t *testing.T) {
	if got := hex.EncodeToString(HashLeaf(nil)); got != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Fatalf("the hash of the empty leaf = %s", got)
	}
	l, r := HashLeaf([]byte("l")), HashLeaf([]byte("r"))
	want := sha256.Sum256(append(append([]byte{0x01}, l...), r...))
	if !bytes.Equal(HashChildren(l, r), want[:]) {
		t.Fatal("a node is not SHA-256(0x01 || left || right)")
	}
}

// A proof and root of a smaller tree, presented at a larger size, is a lie about the size and is refused.
func TestAProofOfASmallerTreeIsRefusedAtALargerSize(t *testing.T) {
	d := testLeaves(8)
	if err := VerifyInclusion(0, 8, HashLeaf(d[0]), refPath(0, d[:2]), refMTH(d[:2])); !errors.Is(err, ErrProof) {
		t.Fatalf("inclusion: err = %v", err)
	}
	if err := VerifyConsistency(1, 8, HashLeaf(d[0]), refMTH(d[:2]), refProof(1, d[:2])); !errors.Is(err, ErrProof) {
		t.Fatalf("consistency: err = %v", err)
	}
}

func TestConsistencyRefusesASmallerSecondTreeAndAnEmptyProof(t *testing.T) {
	d := testLeaves(5)
	r := refMTH(d)
	if err := VerifyConsistency(2, 1, r, r, nil); err == nil || !strings.Contains(err.Error(), "cannot extend") {
		t.Fatalf("a smaller second tree: err = %v", err)
	}
	for _, m := range []int64{1, 3} {
		if err := VerifyConsistency(m, 5, refMTH(d[:m]), r, nil); err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("an empty proof from %d: err = %v", m, err)
		}
	}
}
