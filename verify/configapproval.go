package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	approvalDomain = "authfi-agent-config-approval-v1:"
	ciDomain       = "authfi-agent-config-ci-approval-v1\n"

	kindSudo    = "sudo"
	kindCI      = "ci"
	kindPasskey = "passkey" // no longer accepted; named so the refusal can say why

	// sudoStatement is the sentence every sudo approval carries, word for word.
	sudoStatement = "confirmed by sudo (Confirm it's you) within the project's sudo window; no passkey of the person signed this act"

	maxSudoWindow = 14400 // seconds; the longest sudo window a project can have
	sudoSkew      = 2     // seconds of clock skew allowed either side
)

// sudoMethods are the proofs that set auth_time and may back an approval. A bare password is not one.
var sudoMethods = map[string]bool{"mfa": true, "hwk": true, "email_confirm": true, "passkey_basic": true,
	"pwd_confirmed": true, "fed_reauth": true}

// unsignedClaims are left out of the body the approvers sign: who approved, and when the key countersigned.
var unsignedClaims = []string{"approvals", "approved_by", "second_approver", "approved_at"}

// canonicalBody is the claims without the unsigned ones, encoded the way encoding/json does with HTML escaping off:
// keys sorted, numbers as written, no trailing newline.
func canonicalBody(claims map[string]any) ([]byte, error) {
	body := make(map[string]any, len(claims))
	for k, v := range claims {
		body[k] = v
	}
	for _, k := range unsignedClaims {
		delete(body, k)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// actDigest is what the approvers signed for the act whose claims these are: sha256 of the domain prefix naming
// the act's kind, then the canonical body.
func actDigest(typ string, claims map[string]any) ([32]byte, error) {
	var kind string
	switch typ {
	case ConfigVersionType:
		kind = "version\n"
	case ConfigStateType:
		kind = "state\n"
	default:
		return [32]byte{}, fmt.Errorf("typ %q is not an agent configuration act", typ)
	}
	body, err := canonicalBody(claims)
	if err != nil {
		return [32]byte{}, err
	}
	return digestOf(approvalDomain+kind, body), nil
}

// approval is one entry of an act's approvals. The fields not of its kind are empty.
type approval struct {
	Kind, By, Kid, Alg, Pub, Sig string
	key                          crypto.PublicKey

	// sudo
	Method                         []string
	AuthTime, WindowS, ConfirmedAt int64
	Sess, Digest, Statement        string
}

// person reports whether the approval is a person's: only a sudo confirmation is.
func (a approval) person() bool { return a.Kind == kindSudo }

// parseApprovals reads the approvals claim. It checks the shape (count, kinds, who) and the encodings, and parses
// the public keys; it does not check a signature, a digest or a sudo window against the act.
func parseApprovals(claims map[string]any) ([]approval, []string) {
	raw, ok := claims["approvals"].([]any)
	if !ok || len(raw) == 0 {
		return nil, []string{"it carries no approvals, so no person approved it"}
	}
	if len(raw) > 2 {
		return nil, []string{fmt.Sprintf("it carries %d approvals; at most two are allowed", len(raw))}
	}
	var out []approval
	var problems []string
	for i, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("approval %d is not an object", i))
			continue
		}
		a, errs := parseApproval(m)
		for _, e := range errs {
			problems = append(problems, fmt.Sprintf("approval %d: %s", i, e))
		}
		out = append(out, a)
	}
	if len(problems) > 0 {
		return out, problems
	}
	if len(out) == 2 {
		a, b := out[0], out[1]
		switch {
		case strings.EqualFold(a.By, b.By):
			problems = append(problems, fmt.Sprintf("both approvals are by %s: one approver counts once", a.By))
		case a.Kid != "" && a.Kid == b.Kid:
			problems = append(problems, fmt.Sprintf("both approvals are by credential %s", a.Kid))
		case a.Pub != "" && a.Pub == b.Pub:
			problems = append(problems, "both approvals are by the same public key")
		}
	}
	return out, problems
}

func parseApproval(m map[string]any) (approval, []string) {
	str := func(k string) string { s, _ := claimString(m, k); return s }
	a := approval{Kind: str("kind"), By: str("by"), Kid: str("kid"), Alg: str("alg"), Pub: str("pub"), Sig: str("sig")}
	var problems []string
	switch a.Kind {
	case kindSudo:
		return parseSudo(m, a)
	case kindPasskey:
		return a, []string{`kind "passkey" is no longer accepted: a person approves by sudo confirmation, not by a passkey signature`}
	case kindCI:
		if !strings.HasPrefix(a.By, "ci:") || len(a.By) == len("ci:") {
			problems = append(problems, fmt.Sprintf("a ci approval is by a CI key (ci:<name>), not %q", a.By))
		}
	default:
		return a, []string{fmt.Sprintf("kind %q is not sudo or ci", a.Kind)}
	}
	if a.Kid == "" {
		problems = append(problems, "it names no credential")
	}
	pub, err := parsePublicKey(a.Pub)
	if err != nil {
		return a, append(problems, err.Error())
	}
	a.key = pub
	if err := keyMatchesAlg(pub, a.Alg); err != nil {
		problems = append(problems, err.Error())
	}
	return a, problems
}

// parseSudo reads a sudo approval and applies the rules that need only the approval itself (contract rules 1, 2, 3
// and 5). checkSudo applies rule 4 and the time relations to the act.
func parseSudo(m map[string]any, a approval) (approval, []string) {
	var problems []string
	if !strings.HasPrefix(a.By, "user:") || len(a.By) == len("user:") {
		problems = append(problems, fmt.Sprintf("a sudo approval is by a person (user:<id>), not %q", a.By))
	}
	a.Statement, _ = claimString(m, "statement")
	if a.Statement != sudoStatement {
		problems = append(problems, "its statement is not the fixed sudo statement")
	}
	if raw, ok := m["method"].([]any); !ok {
		problems = append(problems, "it names no method")
	} else {
		strong := false
		for _, r := range raw {
			s, ok := r.(string)
			if !ok {
				problems = append(problems, "a method is not a string")
				continue
			}
			a.Method = append(a.Method, s)
			strong = strong || sudoMethods[s]
		}
		switch {
		case len(raw) < 1 || len(raw) > 8:
			problems = append(problems, fmt.Sprintf("it names %d methods; 1 to 8 are allowed", len(raw)))
		case !strong:
			problems = append(problems, fmt.Sprintf("its methods %q include none that may approve (a bare password never does)", a.Method))
		}
	}
	var ok1, ok2, ok3 bool
	a.AuthTime, ok1 = claimInt(m, "auth_time")
	a.WindowS, ok2 = claimInt(m, "window_s")
	a.ConfirmedAt, ok3 = claimInt(m, "confirmed_at")
	switch {
	case !ok1 || !ok2 || !ok3:
		problems = append(problems, "auth_time, window_s and confirmed_at must be integers")
	case a.AuthTime <= 0:
		problems = append(problems, "auth_time is not a time")
	case a.WindowS <= 0 || a.WindowS > maxSudoWindow:
		problems = append(problems, fmt.Sprintf("window_s %d is outside 1 to %d", a.WindowS, maxSudoWindow))
	case a.ConfirmedAt < a.AuthTime-sudoSkew:
		problems = append(problems, "it was confirmed before the person authenticated")
	case a.ConfirmedAt-a.AuthTime > a.WindowS+sudoSkew:
		problems = append(problems, "the sudo window had expired when it was confirmed (sudo expired)")
	}
	a.Sess, _ = claimString(m, "sess")
	if b, err := hex.DecodeString(a.Sess); err != nil || len(b) != 16 {
		problems = append(problems, "sess is not 32 hex characters")
	}
	a.Digest, _ = claimString(m, "digest")
	for _, k := range []string{"kid", "alg", "pub", "sig"} {
		if _, present := m[k]; present {
			problems = append(problems, fmt.Sprintf("a sudo approval carries no %s: it is not a signature", k))
		}
	}
	return a, problems
}

// checkSudo checks that a sudo approval names this very act and was confirmed between the act's proposal and its
// countersign.
func checkSudo(a approval, d [32]byte, proposedAt, approvedAt int64) error {
	if a.Digest != hex.EncodeToString(d[:]) {
		return fmt.Errorf("the confirmation names another act: its digest is not this act's digest")
	}
	if a.ConfirmedAt < proposedAt-sudoSkew {
		return fmt.Errorf("it was confirmed before the act was proposed")
	}
	if a.ConfirmedAt > approvedAt+sudoSkew {
		return fmt.Errorf("it was confirmed after the act was countersigned")
	}
	return nil
}

// parsePublicKey reads a PKIX DER public key in base64url.
func parsePublicKey(s string) (crypto.PublicKey, error) {
	der, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(der) == 0 {
		return nil, fmt.Errorf("its public key is not base64url")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("its public key is not a PKIX key: %w", err)
	}
	return pub, nil
}

// keyMatchesAlg checks that the algorithm a CI approval names is allowed and fits the key.
func keyMatchesAlg(pub crypto.PublicKey, alg string) error {
	switch alg {
	case "ES256":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return fmt.Errorf("alg ES256 needs a P-256 key")
		}
	case "EdDSA":
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return fmt.Errorf("alg EdDSA needs an Ed25519 key")
		}
	default:
		return fmt.Errorf("alg %q is not accepted (ES256 or EdDSA)", alg)
	}
	return nil
}

// verifyWith verifies sig over msg: ES256 signs sha256(msg), EdDSA signs msg.
func verifyWith(pub crypto.PublicKey, alg string, msg, sig []byte) error {
	switch alg {
	case "ES256":
		k, ok := pub.(*ecdsa.PublicKey)
		h := sha256.Sum256(msg)
		if !ok || !ecdsa.VerifyASN1(k, h[:], sig) {
			return fmt.Errorf("the signature does not verify")
		}
	case "EdDSA":
		k, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, msg, sig) {
			return fmt.Errorf("the signature does not verify")
		}
	default:
		return fmt.Errorf("alg %q is not accepted", alg)
	}
	return nil
}

// ciKey is a CI key a tenant registered in a state act.
type ciKey struct {
	ID, Name, Alg, Pub string
	key                crypto.PublicKey
}

// checkCI checks a CI approval: the key is one the tenant registered, and signed the digest under the CI domain.
func checkCI(a approval, d [32]byte, keys []ciKey) error {
	var reg *ciKey
	for i := range keys {
		if keys[i].ID == a.Kid {
			reg = &keys[i]
		}
	}
	if reg == nil {
		return fmt.Errorf("CI key %s is not registered in the tenant's settings", a.Kid)
	}
	if reg.Pub != a.Pub || reg.Alg != a.Alg {
		return fmt.Errorf("CI key %s is registered with another key or algorithm", a.Kid)
	}
	if a.By != "ci:"+reg.Name {
		return fmt.Errorf("CI key %s is registered as %q, the approval says %q", a.Kid, reg.Name, a.By)
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Sig)
	if err != nil || len(sig) == 0 {
		return fmt.Errorf("the signature is not base64url")
	}
	return verifyWith(a.key, a.Alg, append([]byte(ciDomain), d[:]...), sig)
}
