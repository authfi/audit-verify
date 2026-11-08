// Package vectors describes the test vectors of the verifier: fixed inputs, each with the result a correct
// checker must give. The data sits beside this file; vectors_test.go runs every vector against the verifier and
// regenerates the deterministic ones to prove the files are what the generator makes.
//
// A vector has a stable id, "<kind letter><number>": T tape, H head, R receipt, C config, K chain, A attest,
// S ssh, L revoked list. An id is never reused or renumbered, because other documents cite it as
// "<item>:<id>", for example A4:R1 in the grading plan. ids.lock lists every id ever issued.
package vectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Format is the manifest's own version. A change to a bundle shape that old vectors cannot express adds
// vectors and bumps it; old vectors stay and must keep passing.
const Format = 1

// Kinds maps a kind to the letter its ids start with.
var Kinds = map[string]byte{
	"tape": 'T', "head": 'H', "receipt": 'R', "config": 'C',
	"chain": 'K', "attest": 'A', "ssh": 'S', "revoked-list": 'L',
}

var idPattern = regexp.MustCompile(`^[THRCKASL][1-9][0-9]*$`)

// Manifest is manifest.json.
type Manifest struct {
	Format int `json:"format"`
	// VerifierMin is the first verifier release that must give every expected result.
	VerifierMin string `json:"verifier_min"`
	// At is the instant a run uses wherever a check is made "now", so a vector does not rot when a test
	// certificate in it expires.
	At      string   `json:"at"`
	Vectors []Vector `json:"vectors"`
}

// Vector is one fixed input and its expected result.
type Vector struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Input names the files, relative to the manifest, by role ("bundle", "heads", ...).
	Input map[string]string `json:"input"`
	// Args are the extra command-line arguments of a run, beside --at, which every run passes.
	Args   []string `json:"args,omitempty"`
	Expect Expect   `json:"expect"`
	// Why is one line: what this vector proves, or which refusal it is.
	Why string `json:"why"`
}

// Expect is the result a correct checker gives. A failing vector states a stable reason code and a phrase the
// verifier's failure line must contain, so a checker that fails for the wrong reason is red.
type Expect struct {
	Result          string `json:"result"` // "pass" or "fail"
	Reason          string `json:"reason,omitempty"`
	FailureContains string `json:"failure_contains,omitempty"`
}

var reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Load reads dir/manifest.json and checks that it is well formed: the id scheme, one kind letter per kind, no
// duplicate, every input present, every failing vector with a reason.
func Load(dir string) (Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest.json: %w", err)
	}
	return m, m.Check(dir)
}

// Check reports the first thing wrong with the manifest.
func (m Manifest) Check(dir string) error {
	if m.Format != Format {
		return fmt.Errorf("manifest format %d, this reader knows %d", m.Format, Format)
	}
	if m.VerifierMin == "" || m.At == "" {
		return fmt.Errorf("verifier_min and at are required")
	}
	seen := map[string]bool{}
	for _, v := range m.Vectors {
		if !idPattern.MatchString(v.ID) {
			return fmt.Errorf("vector id %q is not <kind letter><number>", v.ID)
		}
		letter, ok := Kinds[v.Kind]
		if !ok {
			return fmt.Errorf("%s: unknown kind %q", v.ID, v.Kind)
		}
		if v.ID[0] != letter {
			return fmt.Errorf("%s: kind %q takes ids that start with %c", v.ID, v.Kind, letter)
		}
		if seen[v.ID] {
			return fmt.Errorf("vector id %s is used twice", v.ID)
		}
		seen[v.ID] = true
		if strings.TrimSpace(v.Why) == "" {
			return fmt.Errorf("%s: no why", v.ID)
		}
		if len(v.Input) == 0 {
			return fmt.Errorf("%s: no input", v.ID)
		}
		for role, name := range v.Input {
			if filepath.IsAbs(name) || strings.Contains(name, "..") {
				return fmt.Errorf("%s: input %s leaves the vectors directory", v.ID, role)
			}
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				return fmt.Errorf("%s: input %s: %w", v.ID, role, err)
			}
		}
		switch v.Expect.Result {
		case "pass":
			if v.Expect.Reason != "" || v.Expect.FailureContains != "" {
				return fmt.Errorf("%s: a passing vector states no reason", v.ID)
			}
		case "fail":
			if !reasonPattern.MatchString(v.Expect.Reason) || v.Expect.FailureContains == "" {
				return fmt.Errorf("%s: a failing vector needs a reason code and the phrase the failure must contain", v.ID)
			}
		default:
			return fmt.Errorf("%s: result %q is neither pass nor fail", v.ID, v.Expect.Result)
		}
	}
	return nil
}

// Cite splits a citation such as "A4:R1" into the item and the vector id. The item is a plan id, a letter and
// a number; the id is a vector id.
func Cite(s string) (item, id string, err error) {
	item, id, ok := strings.Cut(s, ":")
	if !ok || !regexp.MustCompile(`^[A-G][1-9][0-9]*$`).MatchString(item) || !idPattern.MatchString(id) {
		return "", "", fmt.Errorf("%q is not <item>:<vector id>, for example A4:R1", s)
	}
	return item, id, nil
}

// Find returns the vector with the id, for a document that cites it.
func (m Manifest) Find(id string) (Vector, bool) {
	for _, v := range m.Vectors {
		if v.ID == id {
			return v, true
		}
	}
	return Vector{}, false
}
