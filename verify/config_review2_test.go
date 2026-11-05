package verify

import (
	"testing"
)

// The same table as the gateway's loader test (TestReview2LooseningFollowsTheSettingAtTheTimeProposed): the setting on from
// 1000 to 1999 and off from 2000 on, the agent at strict from 900, and one person's (or two people's) loosening to tools
// proposed at the time in the case. Both sides must give the same answer.
func TestReview2LooseningFollowsTheSettingAtTheTimeProposed(t *testing.T) {
	base := baseTime.Unix()
	cases := []struct {
		name     string
		at       int64
		people   int
		loosened bool
	}{
		{"before the setting went on", 999, 1, true},
		{"the same second the setting went on", 1000, 1, false},
		{"while it is on", 1500, 1, false},
		{"the last second it was on", 1999, 1, false},
		{"the second it went off (inclusive)", 2000, 1, true},
		{"after it went off", 2500, 1, true},
		{"on, with two people", 1500, 2, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newTW(t)
			w.addVersion(w.versionClaims(agentA, 1, 0), actOpts{}, w.alice.signer(), w.bob.signer())
			s1 := w.stateClaims(agentA, 1, "strict", 0)
			s1["proposed_at"] = base + 900
			w.addState(s1, actOpts{}, w.alice.signer())
			on := w.tenantClaims(1, true)
			on["proposed_at"] = base + 1000
			w.addState(on, actOpts{}, w.alice.signer())
			off := w.tenantClaims(2, false)
			off["proposed_at"] = base + 2000
			w.addState(off, actOpts{}, w.alice.signer(), w.bob.signer())
			s2 := w.stateClaims(agentA, 2, "tools", 0)
			s2["proposed_at"] = base + c.at
			signers := []signerFn{w.alice.signer()}
			if c.people == 2 {
				signers = append(signers, w.bob.signer())
			}
			w.addState(s2, actOpts{}, signers...)
			r := w.verify()
			if c.loosened {
				mustPass(t, r)
			} else {
				wantConfigFailure(t, r, "two people must approve while the second-approver setting is on")
			}
		})
	}
}

// The floor never falls, with the setting on or off, with one person or two.
func TestReview2AFloorNeverFalls(t *testing.T) {
	for _, on := range []bool{false, true} {
		for _, people := range []int{1, 2} {
			w := newTW(t)
			if on {
				w.secondOn()
			}
			w.addVersion(w.versionClaims(agentA, 1, 0), actOpts{}, w.alice.signer(), w.bob.signer())
			w.addState(w.stateClaims(agentA, 1, "strict", 1), actOpts{}, w.alice.signer(), w.bob.signer())
			signers := []signerFn{w.alice.signer()}
			if people == 2 {
				signers = append(signers, w.bob.signer())
			}
			w.addState(w.stateClaims(agentA, 2, "strict", 0), actOpts{}, signers...)
			wantConfigFailure(t, w.verify(), "a floor only goes up")
		}
	}
}

// A tenant act proposed before the one it follows: the gateway's loader does not believe it. The verifier must not either, or
// it would judge an agent's act by a setting the gateway never held (here: the setting is on from 1000, a backdated act turns
// it off with two people, and an agent's loosening proposed between them with one person would pass the verifier).
func TestReview2ATenantActProposedBeforeThePreviousIsNotBelieved(t *testing.T) {
	w := newTW(t)
	base := baseTime.Unix()
	w.addVersion(w.versionClaims(agentA, 1, 0), actOpts{}, w.alice.signer(), w.bob.signer())
	s1 := w.stateClaims(agentA, 1, "strict", 0)
	s1["proposed_at"] = base + 900
	w.addState(s1, actOpts{}, w.alice.signer())
	on := w.tenantClaims(1, true)
	on["proposed_at"] = base + 1000
	w.addState(on, actOpts{}, w.alice.signer())
	off := w.tenantClaims(2, false)
	off["proposed_at"] = base + 500
	w.addState(off, actOpts{}, w.alice.signer(), w.bob.signer())
	s2 := w.stateClaims(agentA, 2, "tools", 0)
	s2["proposed_at"] = base + 1200
	w.addState(s2, actOpts{}, w.alice.signer())
	r := w.verify()
	if r.OK {
		t.Fatalf("passed: %+v", r)
	}
	wantConfigFailure(t, r, "proposed before the act it follows")
}

// Keeping the tier (raising only the floor) is not a loosening: one person may do it while the setting is on, and so may a
// first state equal to the tier an agent with a version already has (tools).
func TestReview2KeepingTheTierIsNotALooseningWhileTheSettingIsOn(t *testing.T) {
	w := newTW(t)
	w.addState(w.tenantClaims(1, true), actOpts{}, w.alice.signer())
	w.addVersion(w.versionClaims(agentA, 1, 0), actOpts{}, w.alice.signer(), w.bob.signer())
	w.addState(w.stateClaims(agentA, 1, "tools", 0), actOpts{}, w.alice.signer())
	w.addState(w.stateClaims(agentA, 2, "tools", 1), actOpts{}, w.alice.signer())
	w.addState(w.stateClaims(agentA, 3, "strict", 1), actOpts{}, w.alice.signer())
	w.addState(w.stateClaims(agentA, 4, "strict", 1), actOpts{}, w.alice.signer())
	mustPass(t, w.verify())
}
