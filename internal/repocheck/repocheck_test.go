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
	for _, want := range []string{"workflow_dispatch:", "release --snapshot --clean"} {
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

// jobBlock returns the text of one job of a workflow: from its key to the next job's key.
func jobBlock(t *testing.T, body, name string) string {
	t.Helper()
	_, jobs, ok := strings.Cut(body, "\njobs:\n")
	if !ok {
		t.Fatal("release.yml has no jobs")
	}
	header := regexp.MustCompile(`(?m)^  ([a-z][a-z-]*):[ \t]*$`)
	idx := header.FindAllStringSubmatchIndex(jobs, -1)
	for n, m := range idx {
		if jobs[m[2]:m[3]] != name {
			continue
		}
		end := len(jobs)
		if n+1 < len(idx) {
			end = idx[n+1][0]
		}
		return jobs[m[0]:end]
	}
	t.Fatalf("release.yml has no job %q", name)
	return ""
}

// A dispatch on a tag must not publish: the release job needs a tag push, the rehearsal a branch dispatch.
func TestOnlyATagPushPublishes(t *testing.T) {
	body := workflows(t)["release.yml"]
	if got := jobBlock(t, body, "release"); !strings.Contains(got, "if: github.event_name == 'push' && github.ref_type == 'tag'") {
		t.Errorf("the release job must run only on a tag push:\n%s", got)
	}
	if got := jobBlock(t, body, "rehearsal"); !strings.Contains(got, "if: github.event_name == 'workflow_dispatch' && github.ref_type == 'branch'") {
		t.Errorf("the rehearsal job must run only on a branch dispatch:\n%s", got)
	}
}

// The release job takes its notes from the same script as the gate: no second copy of the rule.
func TestReleaseJobUsesTheOneGate(t *testing.T) {
	body := workflows(t)["release.yml"]
	got := jobBlock(t, body, "release")
	if strings.Contains(got, "awk") || strings.Contains(got, "test -s") {
		t.Errorf("the release job extracts notes itself; it must call scripts/check-release.sh:\n%s", got)
	}
	if !strings.Contains(got, `scripts/check-release.sh "$TAG" "$GITHUB_SHA" "$RUNNER_TEMP/notes.md"`) {
		t.Errorf("the release job does not run the gate with the notes file:\n%s", got)
	}
}

func TestADotIsNotAWildcard(t *testing.T) {
	// Only 1x3x0 has a section. With an unescaped dot the section check passes for v1.3.0 and the refusal comes
	// later with the wrong message.
	out, err := check(t, "# Changelog\n\n## 1x3x0\n\n- notes\n", "v1.3.0")
	if err == nil || !strings.Contains(out, "has no section for 1.3.0") {
		t.Fatalf("v1.3.0 matched a 1x3x0 heading: err=%v\n%s", err, out)
	}
}

// gitRepo makes a repository whose origin/main is its first commit, and returns that commit and a later one.
func gitRepo(t *testing.T) (dir, onMain, offMain string) {
	t.Helper()
	dir = t.TempDir()
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "on main")
	onMain = git("rev-parse", "HEAD")
	git("update-ref", "refs/remotes/origin/main", onMain)
	git("commit", "-q", "--allow-empty", "-m", "not on main")
	offMain = git("rev-parse", "HEAD")
	return dir, onMain, offMain
}

func TestATagOffMainIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the release gate is a bash script run on Linux runners")
	}
	script, err := filepath.Abs("../../scripts/check-release.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir, onMain, offMain := gitRepo(t)
	changelog := filepath.Join(dir, "CHANGELOG.md")
	if err := os.WriteFile(changelog, []byte("## 1.3.0\n\n- notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(dir, "notes.md")
	run := func(sha string) (string, error) {
		cmd := exec.Command("bash", script, "v1.3.0", sha, notes)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CHANGELOG="+changelog)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(offMain); err == nil || !strings.Contains(out, "is not on main") {
		t.Fatalf("a commit that is not on main was not refused for that reason: err=%v\n%s", err, out)
	}
	if _, err := os.Stat(notes); err == nil {
		t.Error("the notes file was written for a refused tag")
	}
	if out, err := run(onMain); err != nil {
		t.Fatalf("a commit on main was refused: %v\n%s", err, out)
	}
	got, err := os.ReadFile(notes)
	if err != nil || !strings.Contains(string(got), "- notes") {
		t.Fatalf("the notes file lacks the section: %v %q", err, got)
	}
}
