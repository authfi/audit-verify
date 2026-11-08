package vectors_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/authfi/audit-verify/internal/vectorgen"
	"github.com/authfi/audit-verify/vectors"
	"github.com/authfi/audit-verify/verify"
)

func load(t *testing.T) vectors.Manifest {
	t.Helper()
	m, err := vectors.Load(".")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Every vector gives the result its manifest states, and a failing one fails for the stated reason: a checker
// that fails for the wrong reason is red.
func TestEveryVectorGivesItsExpectedResult(t *testing.T) {
	m := load(t)
	if len(m.Vectors) == 0 {
		t.Fatal("the manifest lists no vector")
	}
	at, err := time.Parse(time.RFC3339, m.At)
	if err != nil {
		t.Fatal(err)
	}
	if !at.Equal(vectorgen.At) {
		t.Fatalf("the manifest runs at %s, the generator at %s", m.At, vectorgen.At)
	}
	for _, v := range m.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			r := run(t, v)
			joined := strings.Join(r.Failures, "\n")
			switch v.Expect.Result {
			case "pass":
				if !r.OK {
					t.Fatalf("expected a pass, failures: %s", joined)
				}
			case "fail":
				if r.OK {
					t.Fatalf("expected %s (%s) and the verifier passed it", v.Expect.Reason, v.Why)
				}
				if !strings.Contains(joined, v.Expect.FailureContains) {
					t.Fatalf("failed, but not for %s: want a failure containing %q, got:\n%s", v.Expect.Reason, v.Expect.FailureContains, joined)
				}
			}
		})
	}
}

// run gives the verifier the vector's bundle and the options its args name. "--unpinned" is the only arg the
// harness knows: it is the verifier's default today and an explicit flag from the release that pins the embedded
// root by default, so a vector that sets it keeps passing when that default changes. An arg it does not know
// fails the test rather than being ignored.
func run(t *testing.T, v vectors.Vector) verify.Report {
	t.Helper()
	raw, err := os.ReadFile(v.Input["bundle"])
	if err != nil {
		t.Fatal(err)
	}
	var b verify.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	for _, a := range v.Args {
		if a != "--unpinned" {
			t.Fatalf("%s: the harness does not know the arg %q", v.ID, a)
		}
	}
	return verify.Verify(b, verify.Options{})
}

// Every vector records how it is pinned, so it keeps its result when the default changes.
func TestEveryVectorSaysHowItIsPinned(t *testing.T) {
	for _, v := range load(t).Vectors {
		if len(v.Args) == 0 {
			t.Errorf("%s has no args; set --unpinned (or the pinning flag it needs)", v.ID)
		}
	}
}

// A refused vector must fail for its own reason: its phrase must not appear in another refused vector's failure
// lines. Otherwise a checker that gives vector A's failure for vector B's input would still pass B.
func TestAPhraseNamesOneRefusalOnly(t *testing.T) {
	m := load(t)
	failures := map[string]string{}
	for _, v := range m.Vectors {
		if v.Expect.Result == "fail" {
			failures[v.ID] = strings.Join(run(t, v).Failures, "\n")
		}
	}
	for _, a := range m.Vectors {
		if a.Expect.Result != "fail" {
			continue
		}
		for id, lines := range failures {
			if id != a.ID && strings.Contains(lines, a.Expect.FailureContains) {
				t.Errorf("the phrase of %s (%q) also appears in the failure of %s:\n%s", a.ID, a.Expect.FailureContains, id, lines)
			}
		}
	}
}

// The committed vectors are exactly what the generator makes, so anyone can rebuild them.
func TestCommittedVectorsAreWhatTheGeneratorMakes(t *testing.T) {
	for name, want := range vectorgen.Files() {
		got, err := os.ReadFile(filepath.FromSlash(name))
		if err != nil {
			t.Fatalf("%s: %v (run: go run ./tools/mkvectors)", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from a fresh run of the generator (run: go run ./tools/mkvectors)", name)
		}
	}
}

// Ids are never reused or renumbered: ids.lock lists every id ever issued, the manifest holds all of them, and
// a new id must be added to the lock in the same change.
func TestIdsAreNeverReusedOrDropped(t *testing.T) {
	m := load(t)
	raw, err := os.ReadFile("ids.lock")
	if err != nil {
		t.Fatal(err)
	}
	locked := strings.Fields(string(raw))
	if !sort.StringsAreSorted(locked) {
		t.Error("ids.lock is not sorted")
	}
	inManifest := map[string]bool{}
	for _, v := range m.Vectors {
		inManifest[v.ID] = true
	}
	inLock := map[string]bool{}
	for _, id := range locked {
		inLock[id] = true
		if !inManifest[id] {
			t.Errorf("%s was issued and the manifest no longer has it; an id is never dropped", id)
		}
	}
	for id := range inManifest {
		if !inLock[id] {
			t.Errorf("%s is in the manifest and not in ids.lock; add it", id)
		}
	}
}

// The grading plan cites A4:R1 and A4:R2; they must parse and exist.
func TestCitations(t *testing.T) {
	m := load(t)
	for _, cite := range []string{"A4:R1", "A4:R2"} {
		item, id, err := vectors.Cite(cite)
		if err != nil {
			t.Errorf("%s: %v", cite, err)
			continue
		}
		if item != "A4" {
			t.Errorf("item of %s is %s", cite, item)
		}
		if _, found := m.Find(id); !found {
			t.Errorf("%s is cited by the grading plan and the manifest has no %s", cite, id)
		}
	}
	for _, bad := range []string{"R1", "A4:", "A4:R0", "A4:X1", "a4:R1", "A4:R01", "H9:R1", "A4:R1:x"} {
		if _, _, err := vectors.Cite(bad); err == nil {
			t.Errorf("%q should not be a citation", bad)
		}
	}
}

// The checks on the manifest itself refuse a malformed one.
func TestAMalformedManifestIsRefused(t *testing.T) {
	good := load(t)
	cases := map[string]func(*vectors.Manifest){
		"id without a kind letter":    func(m *vectors.Manifest) { m.Vectors[0].ID = "1" },
		"id of another kind":          func(m *vectors.Manifest) { m.Vectors[0].ID = "R1" },
		"duplicate id":                func(m *vectors.Manifest) { m.Vectors[1].ID = m.Vectors[0].ID },
		"unknown kind":                func(m *vectors.Manifest) { m.Vectors[0].Kind = "bogus" },
		"missing input file":          func(m *vectors.Manifest) { m.Vectors[0].Input = map[string]string{"bundle": "tape/none.json"} },
		"input outside the directory": func(m *vectors.Manifest) { m.Vectors[0].Input = map[string]string{"bundle": "../go.mod"} },
		"failure without a reason":    func(m *vectors.Manifest) { m.Vectors[1].Expect.Reason = "" },
		"failure without a phrase":    func(m *vectors.Manifest) { m.Vectors[1].Expect.FailureContains = "" },
		"pass that states a reason":   func(m *vectors.Manifest) { m.Vectors[0].Expect.Reason = "x" },
		"neither pass nor fail":       func(m *vectors.Manifest) { m.Vectors[0].Expect.Result = "maybe" },
		"no why":                      func(m *vectors.Manifest) { m.Vectors[0].Why = " " },
		"unknown manifest format":     func(m *vectors.Manifest) { m.Format = 2 },
		"no verifier_min":             func(m *vectors.Manifest) { m.VerifierMin = "" },
	}
	for name, mutate := range cases {
		m := good
		m.Vectors = append([]vectors.Vector(nil), good.Vectors...)
		mutate(&m)
		if err := m.Check("."); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The reason codes are lower-case words, so another checker can compare them as plain strings.
func TestReasonCodesAreStable(t *testing.T) {
	re := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	for _, v := range load(t).Vectors {
		if v.Expect.Result == "fail" && !re.MatchString(v.Expect.Reason) {
			t.Errorf("%s: reason %q", v.ID, v.Expect.Reason)
		}
	}
}
