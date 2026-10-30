package main

import "testing"

func TestSavedHeadReadsAnExportAsItArrived(t *testing.T) {
	for name, tc := range map[string]struct {
		line string
		ok   bool
		seq  int64
	}{
		"an exported head": {`{"action":"audit.chain_head.signed","metadata":{"seq":7,"entry_hash":"h"}}`, true, 7},
		"a head alone":     {`{"seq":9,"entry_hash":"h"}`, true, 9},
		"another event":    {`{"action":"user.login","metadata":{"seq":3}}`, false, 0},
	} {
		h, ok, err := savedHead([]byte(tc.line))
		if err != nil || ok != tc.ok || h.Seq != tc.seq {
			t.Errorf("%s: head = %+v, ok = %v, err = %v", name, h, ok, err)
		}
	}
	if _, _, err := savedHead([]byte("not json")); err == nil {
		t.Error("a bad line was accepted")
	}
}
