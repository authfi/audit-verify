package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The receipt is a JWS in compact form, carried in the member "receipt" of a tape entry's metadata:
//
//	header    {"alg":"EdDSA","typ":"authfi-receipt+jwt","kid":...}
//	payload   v, tid, rid, ph, req, did, pgen, pbasis, pmatch, cpv, verdict, reason, agent, obo, tool, class,
//	          mandate, appr, args, out, res, drid, iat
//	signature Ed25519 over base64url(header) "." base64url(payload), by a key whose use is "receipt"
//
// A decision receipt (ph "decision") rides an mcp.decision.receipt entry and states the verdict on one call
// before it ran. The call's own mcp.tool.call entry names it in receipt_id and, for an allow, carries the
// outcome receipt (ph "outcome", drid = the decision's rid) with the digest of the result. A held-class rule
// decision (ph "rule") rides an mcp.decision.receipt entry and is not tied to a call.
const (
	// ReceiptType is the JWS typ of a receipt. Any other typ, such as an approved configuration's, is refused.
	ReceiptType = "authfi-receipt+jwt"
	// ReceiptVersion is the only claim set this verifier reads.
	ReceiptVersion = 1

	// ActionToolCall, ActionModelCall and ActionDecisionReceipt are the tape actions receipts ride on. A tool call's
	// resource is mcp_tool:<tool> and a model call's is model:<provider>/<model>, which is also the receipt's tool.
	ActionToolCall = "mcp.tool.call"
	// ActionToolCalled is how the audit service stores a tool call: it rewrites the published name to the
	// past tense before it hashes the entry, so the tape never holds ActionToolCall. Both are tool calls.
	ActionToolCalled      = "mcp.tool.called"
	ActionModelCall       = "mcp.model.call"
	ActionDecisionReceipt = "mcp.decision.receipt"

	toolResourcePrefix  = "mcp_tool:"
	modelResourcePrefix = "model:"

	// ReceiptSkew is how far a receipt's issue time may be from the recorded time of the entry that carries it.
	// Receipts are recorded within moments of being signed, so a receipt dated years away was not signed for this
	// position.
	ReceiptSkew = time.Hour
	// DecisionSettle is how long an allowed decision may go with no call record before it is counted: the call
	// may still be running, and its record is written when it ends.
	DecisionSettle = 10 * time.Minute

	phDecision = "decision"
	phOutcome  = "outcome"
	phRule     = "rule"

	verdictAllow = "allow"
	verdictDeny  = "deny"

	// ReceiptLag is how many positions from the edge of a window a call may sit before a missing decision
	// receipt counts as failing. A receipt and its call are recorded close together but not in a fixed order,
	// so near an edge the receipt may lie just outside the window.
	ReceiptLag = 100
)

// claims are the receipt claims this verifier checks. The others are signed and so cannot be changed, but
// binding them to anything on the tape is not a check made here.
type claims struct {
	V       int    `json:"v"`
	TID     string `json:"tid"`
	RID     string `json:"rid"`
	PH      string `json:"ph"`
	Req     string `json:"req"`
	Verdict string `json:"verdict"`
	Agent   string `json:"agent"`
	Tool    string `json:"tool"`
	Out     string `json:"out"`
	DRID    string `json:"drid"`
	IAT     int64  `json:"iat"`
}

type receiptHeader struct {
	Alg  string          `json:"alg"`
	Typ  string          `json:"typ"`
	Kid  string          `json:"kid"`
	Crit json.RawMessage `json:"crit"`
}

// parseReceipt checks one compact receipt: its header, its signature under a receipt key of the bundle, and
// that it is version 1 and for this tenant. The payload is read only after the signature holds.
func parseReceipt(compact, tenant string, keys []Key) (claims, Key, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return claims{}, Key{}, fmt.Errorf("it is not a compact JWS")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims{}, Key{}, fmt.Errorf("its header is not base64url")
	}
	var h receiptHeader
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return claims{}, Key{}, fmt.Errorf("its header is not JSON: %w", err)
	}
	if h.Typ != ReceiptType {
		return claims{}, Key{}, fmt.Errorf("its typ is %q, a receipt is %q", h.Typ, ReceiptType)
	}
	if h.Alg != "EdDSA" {
		return claims{}, Key{}, fmt.Errorf("signed with %q; only EdDSA is accepted", h.Alg)
	}
	if len(h.Crit) != 0 {
		return claims{}, Key{}, fmt.Errorf("its header lists critical extensions this verifier does not know")
	}
	k, err := keyFor(keys, h.Kid, UseReceipt, "a receipt")
	if err != nil {
		return claims{}, Key{}, err
	}
	pub, err := publicKey(k)
	if err != nil {
		return claims{}, Key{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims{}, Key{}, fmt.Errorf("its signature is not base64url")
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return claims{}, Key{}, fmt.Errorf("its signature does not verify under key %s", h.Kid)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, Key{}, fmt.Errorf("its payload is not base64url")
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return claims{}, Key{}, fmt.Errorf("its payload is not a receipt: %w", err)
	}
	switch {
	case c.V != ReceiptVersion:
		return claims{}, Key{}, fmt.Errorf("it is version %d, this verifier reads version %d", c.V, ReceiptVersion)
	case c.TID != tenant:
		return claims{}, Key{}, fmt.Errorf("it is for tenant %q, not this bundle's tenant", c.TID)
	case c.RID == "":
		return claims{}, Key{}, fmt.Errorf("it has no receipt id")
	case c.IAT <= 0:
		return claims{}, Key{}, fmt.Errorf("it says when it was issued with no usable time")
	}
	return c, k, nil
}

// entryMeta is the tape entry's metadata as the flat object the audit writer makes of it.
func entryMeta(e Entry) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(e.Metadata), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// sameAgent reports whether the receipt's agent is the entry's actor. The tape types a principal
// ("agent:abc") where a receipt may carry the bare id, so only what follows the type is compared.
func sameAgent(actor, agent string) bool {
	if agent == "" {
		return false
	}
	return actor == agent || (!strings.Contains(agent, ":") && actor == "agent:"+agent)
}

// isCallAction reports whether a tape action is a governed call, under either spelling of a tool call.
func isCallAction(action string) bool {
	return action == ActionToolCall || action == ActionToolCalled || action == ActionModelCall
}

// callKind names the kind of a governed call, with a tool call's two spellings as one.
func callKind(action string) string {
	if action == ActionToolCalled {
		return ActionToolCall
	}
	return action
}

// sameCall checks that a receipt speaks about the call this entry records.
func sameCall(c claims, e Entry, m map[string]any) error {
	prefix := toolResourcePrefix
	if e.Action == ActionModelCall {
		prefix = modelResourcePrefix
	}
	req := str(m, "request_id")
	if req == "" {
		return fmt.Errorf("the call carries no request id, so no receipt can be tied to it")
	}
	if c.Req != req {
		return fmt.Errorf("it is for request %q, the call is request %q", c.Req, req)
	}
	if tool := strings.TrimPrefix(e.Resource, prefix); tool == e.Resource || c.Tool != tool {
		return fmt.Errorf("it is for tool %q, the call is %q", c.Tool, e.Resource)
	}
	if !sameAgent(e.Actor, c.Agent) {
		return fmt.Errorf("it is for agent %q, the call was made by %q", c.Agent, e.Actor)
	}
	return nil
}

// toolCall is a governed call on the tape: its entry's index, metadata and the decision receipt it names.
type toolCall struct {
	i   int
	m   map[string]any
	rid string
}

// unavailable reports whether the gateway marked this call as refused for want of a receipt it could not sign.
func (c toolCall) unavailable() bool { return str(c.m, "receipt_unavailable") == "true" }

// checkReceipts runs the receipt checks over the entries of b, adding what it finds to r and the keys it
// used to used. Bundles with no governed call and no receipt pass through it unchanged.
//
//	R1  every receipt verifies under a receipt key of the bundle, is for this tenant and is version 1
//	R2  a call's receipt_id names a decision receipt for that very call, and an allow carries its outcome
//	R3  every call has a decision receipt, except calls made before receipts began
//	R4  a receipt id is never two different receipts, and receipts ride only the entries meant for them
func checkReceipts(b Bundle, r *Report, fail func(string, ...any), used usedKeys) {
	var calls []toolCall
	decisions := map[string]claims{}
	outcomes := map[int]claims{}
	seen := map[string]string{} // rid -> the receipt as it first appeared

	for i, e := range b.Entries {
		isCall, isDecision := isCallAction(e.Action), e.Action == ActionDecisionReceipt
		if !isCall && !isDecision && !strings.Contains(e.Metadata, `"receipt"`) {
			continue
		}
		m, err := entryMeta(e)
		if err != nil {
			if isCall {
				fail("position %d: a governed call whose metadata is not JSON, so its receipt cannot be read", e.Seq)
			}
			continue
		}
		if isCall {
			calls = append(calls, toolCall{i, m, str(m, "receipt_id")})
		}
		raw, has := m["receipt"]
		if !has {
			continue
		}
		if !isCall && !isDecision {
			fail("position %d: a receipt on a %s entry; receipts ride %s, %s and %s entries only", e.Seq, e.Action, ActionDecisionReceipt, ActionToolCall, ActionModelCall)
			continue
		}
		compact, ok := raw.(string)
		if !ok || compact == "" {
			fail("position %d: the receipt member is not a receipt", e.Seq)
			continue
		}
		c, k, err := parseReceipt(compact, b.TenantID, b.Keys)
		if err != nil {
			fail("position %d: the receipt: %v", e.Seq, err)
			continue
		}
		if isCall && c.PH != phOutcome {
			fail("position %d: a %q receipt on a tool call; only its outcome belongs there", e.Seq, c.PH)
			continue
		}
		if isDecision && c.PH != phDecision && c.PH != phRule {
			fail("position %d: a %q receipt on a decision entry", e.Seq, c.PH)
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.RecordedAt)
		if err != nil {
			fail("position %d: the entry's recorded time %q is not a time, so the receipt cannot be placed", e.Seq, e.RecordedAt)
			continue
		}
		if skew := time.Unix(c.IAT, 0).Sub(at); skew > ReceiptSkew || skew < -ReceiptSkew {
			fail("position %d: receipt dated far from its tape position: issued %s, recorded %s", e.Seq, time.Unix(c.IAT, 0).UTC().Format(time.RFC3339), e.RecordedAt)
			continue
		}
		first, dup := seen[c.RID]
		if dup && first != compact {
			fail("position %d: receipt id %s is two different receipts", e.Seq, c.RID)
			continue
		}
		if !dup {
			r.Receipts++
		}
		seen[c.RID] = compact
		used.note(k, time.Unix(c.IAT, 0))
		switch {
		case isCall:
			outcomes[i] = c
		case c.PH == phDecision:
			decisions[c.RID] = c
		}
	}
	bindCalls(b, r, fail, calls, decisions, outcomes)
}

// bindCalls checks R2 and R3 for every governed call.
func bindCalls(b Bundle, r *Report, fail func(string, ...any), calls []toolCall, decisions map[string]claims, outcomes map[int]claims) {
	// A call without a receipt id is from before receipts only while no earlier call in the window has one.
	// Tool calls and model calls began carrying receipts separately, so each kind has its own beginning.
	began := map[string]int{}
	for _, c := range calls {
		if _, ok := began[callKind(b.Entries[c.i].Action)]; !ok && c.rid != "" {
			began[callKind(b.Entries[c.i].Action)] = c.i
		}
	}
	atEdge := func(seq int64) bool {
		return (!r.ChainStartsAtGenesis && seq-r.FromSeq < ReceiptLag) || r.ToSeq-seq < ReceiptLag
	}
	for _, c := range calls {
		e := b.Entries[c.i]
		r.Calls++
		atCall := func(f string, a ...any) { fail("position %d: %s", e.Seq, fmt.Sprintf(f, a...)) }
		if c.rid == "" && c.unavailable() {
			if str(c.m, "decision") != verdictDeny {
				r.ReceiptsMissing++
				atCall("an allowed call is marked as refused for want of a receipt")
				continue
			}
			r.RefusedForWantOfReceipt++
			continue
		}
		if c.rid == "" {
			start, started := began[callKind(e.Action)]
			if !started || c.i < start {
				r.CallsBeforeReceipts++
				continue
			}
			r.ReceiptsMissing++
			atCall("a governed call with no receipt, after receipts began for %s at position %d", callKind(e.Action), b.Entries[start].Seq)
			continue
		}
		d, ok := decisions[c.rid]
		if !ok {
			if atEdge(e.Seq) {
				r.CallsAtEdge++
				continue
			}
			r.ReceiptsMissing++
			atCall("receipt missing: the call names decision receipt %s and no verified one is in the bundle", c.rid)
			continue
		}
		bindCall(e, c.m, d, outcomes[c.i], atCall)
	}
	countOrphanDecisions(b, r, calls, decisions)
	if r.CallsBeforeReceipts > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d governed calls predate receipts", r.CallsBeforeReceipts))
	}
	if r.RefusedForWantOfReceipt > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d governed calls were refused by the gateway for want of a receipt it could not sign, so they have none", r.RefusedForWantOfReceipt))
	}
	if r.DecisionsWithoutCall > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d allowed decisions have no call record: the call may not have completed", r.DecisionsWithoutCall))
	}
	if r.CallsAtEdge > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d governed calls near the edge of this window have their decision receipt outside it: ask for a wider window to check them", r.CallsAtEdge))
	}
}

// bindCall checks R2 for one call: its decision receipt speaks about this call and agrees with what the tape
// says was decided, and an allow carries the outcome receipt that belongs to it.
func bindCall(e Entry, m map[string]any, d, outcome claims, fail func(string, ...any)) {
	if err := sameCall(d, e, m); err != nil {
		fail("the decision receipt is not for this call: %v", err)
		return
	}
	decision := str(m, "decision")
	if (decision != verdictAllow && decision != verdictDeny) || d.Verdict != decision {
		fail("the tape records %q and the decision receipt says %q", decision, d.Verdict)
		return
	}
	if outcome.RID == "" {
		if decision == verdictAllow {
			fail("an allowed call carries no outcome receipt")
		}
		return
	}
	if outcome.DRID != d.RID {
		fail("the outcome receipt belongs to decision %q, this call's is %q", outcome.DRID, d.RID)
		return
	}
	if err := sameCall(outcome, e, m); err != nil {
		fail("the outcome receipt is not for this call: %v", err)
		return
	}
	if decision == verdictAllow && outcome.Out != str(m, "outcome") {
		fail("the tape records the outcome %q and the outcome receipt says %q", str(m, "outcome"), outcome.Out)
	}
}

// countOrphanDecisions counts the allowed decisions no call entry names and that are old enough, against the end of
// the window, for their call to have been recorded. A call refused after its allow is signed leaves such a decision
// beside the refusal's own, and a call that never finished leaves one with nothing. Either is a note, not a failure:
// the verifier cannot tell them from a call record that was lost, so it counts them for the person checking.
func countOrphanDecisions(b Bundle, r *Report, calls []toolCall, decisions map[string]claims) {
	if len(b.Entries) == 0 {
		return
	}
	end, err := time.Parse(time.RFC3339Nano, b.Entries[len(b.Entries)-1].RecordedAt)
	if err != nil {
		return
	}
	named := make(map[string]bool, len(calls))
	for _, c := range calls {
		named[c.rid] = true
	}
	for rid, d := range decisions {
		if d.Verdict == verdictAllow && !named[rid] && time.Unix(d.IAT, 0).Before(end.Add(-DecisionSettle)) {
			r.DecisionsWithoutCall++
		}
	}
}
