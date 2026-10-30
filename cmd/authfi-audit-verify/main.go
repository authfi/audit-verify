// Command authfi-audit-verify checks a proof bundle of an AuthFI audit tape, on your own machine. It
// holds no secret and calls nothing.
//
//	authfi-audit-verify --bundle proof.json [--root authfi-root.pem] [--heads saved-heads.ndjson]
//
// It exits 0 when the bundle passes, 1 when it fails, and 2 when it could not run.
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/authfi/audit-verify/verify"
)

func main() {
	bundlePath := flag.String("bundle", "", "the proof bundle, as downloaded")
	rootPath := flag.String("root", "", "the AuthFI root certificate (PEM) to pin; optional")
	headsPath := flag.String("heads", "", "heads you saved from a log stream, one JSON object per line; optional")
	flag.Parse()

	report, err := run(*bundlePath, *rootPath, *headsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not check the bundle:", err)
		os.Exit(2)
	}
	fmt.Printf("entries checked: %d (positions %d to %d)\n", report.Entries, report.FromSeq, report.ToSeq)
	fmt.Printf("signed up to:    %d (%d newer entries not signed yet)\n", report.SignedTo, report.Unsigned)
	fmt.Printf("saved heads:     %d matched\n", report.SavedChecked)
	if *rootPath != "" {
		fmt.Printf("key certified:   %t\n", report.Certified)
	}
	for _, n := range report.Notes {
		fmt.Println("note:", n)
	}
	for _, f := range report.Failures {
		fmt.Println("FAILED:", f)
	}
	if !report.OK {
		os.Exit(1)
	}
	fmt.Println("result: PASS")
}

// savedHead reads one line of saved heads: a line exported from a log stream, or a head on its own. Other
// events on an exported file are skipped, so the file can be the export as it arrived.
func savedHead(line []byte) (verify.Head, bool, error) {
	var row struct {
		verify.Head
		Action   string       `json:"action"`
		Metadata *verify.Head `json:"metadata"`
	}
	if err := json.Unmarshal(line, &row); err != nil {
		return verify.Head{}, false, err
	}
	if row.Action == "" {
		return row.Head, true, nil
	}
	if row.Action != "audit.chain_head.signed" || row.Metadata == nil {
		return verify.Head{}, false, nil
	}
	return *row.Metadata, true, nil
}

func run(bundlePath, rootPath, headsPath string) (verify.Report, error) {
	var o verify.Options
	if bundlePath == "" {
		return verify.Report{}, errors.New("--bundle is required")
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return verify.Report{}, err
	}
	var b verify.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return verify.Report{}, fmt.Errorf("%s: %w", bundlePath, err)
	}
	if rootPath != "" {
		pem, err := os.ReadFile(rootPath)
		if err != nil {
			return verify.Report{}, err
		}
		o.Root = x509.NewCertPool()
		if !o.Root.AppendCertsFromPEM(pem) {
			return verify.Report{}, fmt.Errorf("%s holds no certificate", rootPath)
		}
	}
	if headsPath != "" {
		f, err := os.Open(headsPath)
		if err != nil {
			return verify.Report{}, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if len(sc.Bytes()) == 0 {
				continue
			}
			h, ok, err := savedHead(sc.Bytes())
			if err != nil {
				return verify.Report{}, fmt.Errorf("%s: %w", headsPath, err)
			}
			if ok {
				o.Saved = append(o.Saved, h)
			}
		}
		if err := sc.Err(); err != nil {
			return verify.Report{}, err
		}
	}
	return verify.Verify(b, o), nil
}
