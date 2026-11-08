// Package repocheck holds tests about the repository itself rather than the verifier: the rules its workflows
// and release gate must keep. They fail the build, so a rule is not only a sentence in a README.
package repocheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// runnerLabel is the only runner label a workflow here may use: the self-hosted Go runner ci.yml already runs on.
// Nothing runs on a GitHub-hosted runner (CTO rule), and a job that asks for one never starts: the v1.2.0 Release
// run waited 24 hours for a runner that does not exist and was cancelled.
const runnerLabel = "authfi-ci-go"

var runsOn = regexp.MustCompile(`(?m)^\s*runs-on:\s*(.*?)\s*(#.*)?$`)

func workflows(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("../../.github/workflows/*.y*ml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	out := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(f)] = string(raw)
	}
	return out
}

func TestEveryJobRunsOnTheSelfHostedRunner(t *testing.T) {
	for name, body := range workflows(t) {
		jobs := runsOn.FindAllStringSubmatch(body, -1)
		if len(jobs) == 0 {
			t.Errorf("%s has no runs-on", name)
		}
		for _, m := range jobs {
			if m[1] != runnerLabel {
				t.Errorf("%s: runs-on %q; every job runs on %q", name, m[1], runnerLabel)
			}
		}
	}
}

func TestReleaseHasARehearsalThatNeedsNoTag(t *testing.T) {
	body := workflows(t)["release.yml"]
	for _, want := range []string{"workflow_dispatch:", "release --snapshot --clean", "github.ref_type == 'tag'"} {
		if !strings.Contains(body, want) {
			t.Errorf("release.yml lacks %q", want)
		}
	}
	// The rehearsal must not be able to publish: no write to contents and no release environment.
	i := strings.Index(body, "  rehearsal:")
	j := strings.Index(body, "  release:")
	if i < 0 || j < i {
		t.Fatal("release.yml has no rehearsal job before the release job")
	}
	rehearsal := body[i:j]
	for _, bad := range []string{"contents: write", "environment:", "attestations: write"} {
		if strings.Contains(rehearsal, bad) {
			t.Errorf("the rehearsal job holds %q; it must not be able to publish", bad)
		}
	}
}

// check runs scripts/check-release.sh against a changelog.
func check(t *testing.T, changelog string, args ...string) (string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the release gate is a bash script run on Linux runners")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(changelog), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{"../../scripts/check-release.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "CHANGELOG="+path)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

const changelog = `# Changelog

## Unreleased

### Added

- something not yet released

## 1.3.0

### Changed

- the default run

## [1.2.0] - 2026-10-01

- an older release

## 1.4.0
`

func TestReleaseGate(t *testing.T) {
	cases := []struct {
		name string
		args []string
		fail string // substring of the refusal; empty means it must pass
	}{
		{"a version with a changelog section passes", []string{"v1.3.0"}, ""},
		{"a bracketed section passes", []string{"v1.2.0"}, ""},
		{"a tag that is not a version", []string{"v1.3"}, "is not a version tag"},
		{"a pre-release suffix is not a release tag", []string{"v1.3.0-rc1"}, "is not a version tag"},
		{"a version with no changelog section", []string{"v1.9.0"}, "has no section for 1.9.0"},
		{"a dot in the version is not a wildcard", []string{"v1x3x0"}, "is not a version tag"},
		{"a section with no notes", []string{"v1.4.0"}, "with no notes"},
		{"Unreleased is not a release", []string{"vUnreleased"}, "is not a version tag"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := check(t, changelog, c.args...)
			if c.fail == "" {
				if err != nil {
					t.Fatalf("refused: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("passed, want a refusal containing %q\n%s", c.fail, out)
			}
			if !strings.Contains(out, c.fail) {
				t.Fatalf("refused for another reason: want %q in\n%s", c.fail, out)
			}
		})
	}
}
