package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/authfi/audit-verify/verify"
)

// runConfigCommand is `authfi-audit-verify config`: it checks a tenant's approved agent configuration against the
// pinned root, and returns the process exit code (0 pass, 1 fail, 2 could not run).
func runConfigCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "the configuration bundle: versions and states with their tokens")
	rootPath := fs.String("root", "", "the AuthFI root certificate (PEM) to pin")
	tapePath := fs.String("tape", "", "a proof bundle of the tenant's audit tape; optional")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	report, err := runConfig(*bundlePath, *rootPath, *tapePath)
	if err != nil {
		fmt.Fprintln(stderr, "could not check the configuration:", err)
		return 2
	}
	printConfig(stdout, report, *tapePath != "")
	if !report.OK {
		return 1
	}
	fmt.Fprintln(stdout, "result: PASS")
	return 0
}

func runConfig(bundlePath, rootPath, tapePath string) (verify.ConfigReport, error) {
	if bundlePath == "" || rootPath == "" {
		return verify.ConfigReport{}, errors.New("--bundle and --root are required")
	}
	var b verify.ConfigBundle
	if err := readJSON(bundlePath, &b); err != nil {
		return verify.ConfigReport{}, err
	}
	pem, err := os.ReadFile(rootPath)
	if err != nil {
		return verify.ConfigReport{}, err
	}
	o := verify.ConfigOptions{Root: x509.NewCertPool()}
	if !o.Root.AppendCertsFromPEM(pem) {
		return verify.ConfigReport{}, fmt.Errorf("%s holds no certificate", rootPath)
	}
	if tapePath != "" {
		var tape verify.Bundle
		if err := readJSON(tapePath, &tape); err != nil {
			return verify.ConfigReport{}, err
		}
		o.Tape = &tape
	}
	return verify.VerifyConfig(b, o), nil
}

func readJSON(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// printConfig says what the configuration checks found, one line to a problem.
func printConfig(w io.Writer, r verify.ConfigReport, tape bool) {
	fmt.Fprintf(w, "tenant:          %s\n", r.Tenant)
	fmt.Fprintf(w, "versions:        %d read, %d valid\n", r.Versions, r.ValidVersions)
	fmt.Fprintf(w, "states:          %d read, %d valid\n", r.States, r.ValidStates)
	fmt.Fprintf(w, "tenant settings: second approver required %t, %d CI keys (state seq %d)\n", r.NeedSecond, r.CIKeys, r.TenantSeq)
	for _, a := range r.Agents {
		source := "default"
		if a.Signed {
			source = fmt.Sprintf("signed, seq %d", a.StateSeq)
		}
		fmt.Fprintf(w, "agent %s: tier %s (%s), floor %d, newest version %d, in force %s\n",
			a.Agent, orNone(a.Mode), source, a.Floor, a.Newest, versionList(a.InForce))
	}
	if tape {
		fmt.Fprintf(w, "tape:            %d agents' newest approved version matches\n", r.TapeAgents)
	}
	for _, n := range r.Notes {
		fmt.Fprintln(w, "note:", n)
	}
	for _, f := range r.Failures {
		fmt.Fprintln(w, "FAILED:", f)
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func versionList(vs []int64) string {
	if len(vs) == 0 {
		return "none"
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, ", ")
}
