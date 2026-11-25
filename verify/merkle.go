package verify

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// The Merkle tree of the access transparency log is RFC 9162's: a leaf hashes as SHA-256(0x00 || leaf), an
// interior node as SHA-256(0x01 || left || right), and the empty tree as SHA-256 of nothing.
const (
	leafHashPrefix = 0x00
	nodeHashPrefix = 0x01
)

// ErrProof is returned, wrapped, by every inclusion or consistency check that fails.
var ErrProof = errors.New("proof does not verify")

// HashLeaf is the RFC 9162 hash of one leaf's bytes.
func HashLeaf(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafHashPrefix})
	h.Write(leaf)
	return h.Sum(nil)
}

// HashChildren is the RFC 9162 hash of an interior node over its two children.
func HashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodeHashPrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// EmptyRoot is the root hash of a tree with no leaves.
func EmptyRoot() []byte {
	sum := sha256.Sum256(nil)
	return sum[:]
}

// VerifyInclusion checks that leafHash is the leaf at index of the tree of size whose root is root (RFC 9162 2.1.3.2).
func VerifyInclusion(index, size int64, leafHash []byte, proof [][]byte, root []byte) error {
	if index < 0 || index >= size {
		return fmt.Errorf("%w: leaf %d is not in a tree of %d leaves", ErrProof, index, size)
	}
	fn, sn := index, size-1
	r := leafHash
	for _, p := range proof {
		if sn == 0 {
			return fmt.Errorf("%w: the inclusion proof is longer than the tree is deep", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			r = HashChildren(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn, sn = fn>>1, sn>>1
				}
			}
		} else {
			r = HashChildren(r, p)
		}
		fn, sn = fn>>1, sn>>1
	}
	if sn != 0 {
		return fmt.Errorf("%w: the inclusion proof is shorter than the tree is deep", ErrProof)
	}
	if !bytes.Equal(r, root) {
		return fmt.Errorf("%w: the inclusion proof leads to another root", ErrProof)
	}
	return nil
}

// VerifyConsistency checks that the tree of size2 with root2 extends the tree of size1 with root1, so nothing
// the smaller tree held was changed or removed (RFC 9162 2.1.4.2).
func VerifyConsistency(size1, size2 int64, root1, root2 []byte, proof [][]byte) error {
	switch {
	case size1 < 0 || size2 < size1:
		return fmt.Errorf("%w: a tree of %d leaves cannot extend one of %d", ErrProof, size2, size1)
	case size1 == size2:
		if len(proof) != 0 {
			return fmt.Errorf("%w: two heads of one size need no proof", ErrProof)
		}
		if !bytes.Equal(root1, root2) {
			return fmt.Errorf("%w: two heads of size %d name different roots", ErrProof, size1)
		}
		return nil
	case size1 == 0:
		if len(proof) != 0 {
			return fmt.Errorf("%w: the empty tree needs no proof", ErrProof)
		}
		return nil
	case len(proof) == 0:
		return fmt.Errorf("%w: the consistency proof is empty", ErrProof)
	}
	path := proof
	if size1&(size1-1) == 0 {
		path = append([][]byte{root1}, proof...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn, sn = fn>>1, sn>>1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return fmt.Errorf("%w: the consistency proof is longer than the tree is deep", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			fr, sr = HashChildren(c, fr), HashChildren(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn, sn = fn>>1, sn>>1
				}
			}
		} else {
			sr = HashChildren(sr, c)
		}
		fn, sn = fn>>1, sn>>1
	}
	if sn != 0 {
		return fmt.Errorf("%w: the consistency proof is shorter than the tree is deep", ErrProof)
	}
	if !bytes.Equal(fr, root1) {
		return fmt.Errorf("%w: the proof does not lead back to the smaller tree's root", ErrProof)
	}
	if !bytes.Equal(sr, root2) {
		return fmt.Errorf("%w: the proof does not lead to the larger tree's root", ErrProof)
	}
	return nil
}
