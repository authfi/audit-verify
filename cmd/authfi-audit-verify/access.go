package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/authfi/audit-verify/verify"
)

// runAccessCommand is `authfi-audit-verify access`: it checks a tenant's entries in the access transparency log and
// returns the process exit code (0 pass, 1 fail, 2 could not run).
func runAccessCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("access", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "the access transparency bundle, as downloaded")
	rootPath := fs.String("root", "", "the AuthFI root certificate (PEM) to pin; optional")
	headsPath := fs.String("heads", "", "tree heads you saved earlier, one JSON object per line; optional")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	report, err := runAccess(*bundlePath, *rootPath, *headsPath)
	if err != nil {
		fmt.Fprintln(stderr, "could not check the bundle:", err)
		return 2
	}
	fmt.Fprintf(stdout, "entries checked: %d (tenant positions %d to %d)\n", report.Entries, report.FromSeq, report.ToSeq)
	fmt.Fprintf(stdout, "in the log:      %d of them, under a signed head of %d entries\n", report.Included, report.TreeSize)
	fmt.Fprintf(stdout, "saved heads:     %d proven the same log\n", report.SavedChecked)
	if *rootPath != "" {
		fmt.Fprintf(stdout, "key certified:   %t\n", report.Certified)
	}
	for _, n := range report.Notes {
		fmt.Fprintln(stdout, "note:", n)
	}
	for _, f := range report.Failures {
		fmt.Fprintln(stdout, "FAILED:", f)
	}
	if !report.OK {
		return 1
	}
	fmt.Fprintln(stdout, "result: PASS")
	return 0
}

func runAccess(bundlePath, rootPath, headsPath string) (verify.AccessReport, error) {
	if bundlePath == "" {
		return verify.AccessReport{}, errors.New("--bundle is required")
	}
	var b verify.AccessBundle
	if err := readJSON(bundlePath, &b); err != nil {
		return verify.AccessReport{}, err
	}
	var o verify.AccessOptions
	if rootPath != "" {
		pem, err := os.ReadFile(rootPath)
		if err != nil {
			return verify.AccessReport{}, err
		}
		o.Root = x509.NewCertPool()
		if !o.Root.AppendCertsFromPEM(pem) {
			return verify.AccessReport{}, fmt.Errorf("%s holds no certificate", rootPath)
		}
	}
	if headsPath != "" {
		saved, err := readTreeHeads(headsPath)
		if err != nil {
			return verify.AccessReport{}, err
		}
		o.Saved = saved
	}
	return verify.VerifyAccessLog(b, o), nil
}

// readTreeHeads reads saved tree heads, one JSON object to a line; blank lines are skipped.
func readTreeHeads(path string) ([]verify.TreeHead, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []verify.TreeHead
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var h verify.TreeHead
		if err := json.Unmarshal(sc.Bytes(), &h); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, h)
	}
	return out, sc.Err()
}
