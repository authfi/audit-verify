package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const (
	approvalDomain = "authfi-agent-config-approval-v1:"
	ciDomain       = "authfi-agent-config-ci-approval-v1\n"

	kindPasskey = "passkey"
	kindCI      = "ci"

	flagUP = 0x01
	flagUV = 0x04

	minRSABits = 2048
)

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
	Kind, By, Kid, Alg, Pub string
	RP, Origin, AD, CD, Sig string
	key                     crypto.PublicKey
}

// person reports whether the approval is a person's: only a passkey assertion is.
func (a approval) person() bool { return a.Kind == kindPasskey }

// parseApprovals reads the approvals claim. It checks the shape (count, kinds, who) and the encodings, and parses
// the public keys; it does not check a signature.
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
		case a.By == b.By:
			problems = append(problems, fmt.Sprintf("both approvals are by %s: one approver counts once", a.By))
		case a.Kid == b.Kid:
			problems = append(problems, fmt.Sprintf("both approvals are by credential %s", a.Kid))
		case a.Pub == b.Pub:
			problems = append(problems, "both approvals are by the same public key")
		}
	}
	return out, problems
}

func parseApproval(m map[string]any) (approval, []string) {
	str := func(k string) string { s, _ := claimString(m, k); return s }
	a := approval{Kind: str("kind"), By: str("by"), Kid: str("kid"), Alg: str("alg"), Pub: str("pub"),
		RP: str("rp"), Origin: str("origin"), AD: str("ad"), CD: str("cd"), Sig: str("sig")}
	var problems []string
	switch a.Kind {
	case kindPasskey:
		if !strings.HasPrefix(a.By, "user:") || len(a.By) == len("user:") {
			problems = append(problems, fmt.Sprintf("a passkey approval is by a person (user:<id>), not %q", a.By))
		}
	case kindCI:
		if !strings.HasPrefix(a.By, "ci:") || len(a.By) == len("ci:") {
			problems = append(problems, fmt.Sprintf("a ci approval is by a CI key (ci:<name>), not %q", a.By))
		}
	default:
		return a, []string{fmt.Sprintf("kind %q is not passkey or ci", a.Kind)}
	}
	if a.Kid == "" {
		problems = append(problems, "it names no credential")
	}
	pub, err := parsePublicKey(a.Pub)
	if err != nil {
		return a, append(problems, err.Error())
	}
	a.key = pub
	if err := keyMatchesAlg(pub, a.Alg, a.Kind); err != nil {
		problems = append(problems, err.Error())
	}
	return a, problems
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

// keyMatchesAlg checks that the algorithm the approval names is one allowed for its kind and fits the key.
func keyMatchesAlg(pub crypto.PublicKey, alg, kind string) error {
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
	case "RS256":
		k, ok := pub.(*rsa.PublicKey)
		if kind != kindPasskey {
			return fmt.Errorf("alg RS256 is for a passkey, not a CI key")
		}
		if !ok || k.N.BitLen() < minRSABits {
			return fmt.Errorf("alg RS256 needs an RSA key of at least %d bits", minRSABits)
		}
	default:
		return fmt.Errorf("alg %q is not accepted (ES256, RS256 or EdDSA)", alg)
	}
	return nil
}

// challenge is the digest as a WebAuthn challenge: base64url without padding.
func challenge(d [32]byte) string { return base64.RawURLEncoding.EncodeToString(d[:]) }

// checkPasskey checks a passkey approval against the act's digest with the standard library: the assertion
// is a WebAuthn "get" whose challenge is the digest, from an origin under the relying party, made with the user
// present and verified, and the signature over authenticatorData || sha256(clientDataJSON) verifies.
func checkPasskey(a approval, d [32]byte) error {
	cdRaw, err := base64.RawURLEncoding.DecodeString(a.CD)
	if err != nil || len(cdRaw) == 0 {
		return fmt.Errorf("the client data is not base64url")
	}
	cd, err := strictObject(cdRaw)
	if err != nil {
		return fmt.Errorf("the client data %w", err)
	}
	if t, _ := claimString(cd, "type"); t != "webauthn.get" {
		return fmt.Errorf("the client data is not a webauthn.get assertion")
	}
	if c, _ := claimString(cd, "challenge"); c != challenge(d) {
		return fmt.Errorf("the assertion's challenge is not this act's digest")
	}
	if o, _ := claimString(cd, "origin"); o != a.Origin {
		return fmt.Errorf("the assertion's origin is not the origin the approval states")
	}
	if cross, present := cd["crossOrigin"]; present && cross != false {
		return fmt.Errorf("the assertion was made cross-origin")
	}
	if err := originUnder(a.Origin, a.RP); err != nil {
		return err
	}
	ad, err := base64.RawURLEncoding.DecodeString(a.AD)
	if err != nil || len(ad) < 37 {
		return fmt.Errorf("the authenticator data is not base64url of at least 37 bytes")
	}
	if rp := sha256.Sum256([]byte(a.RP)); !bytes.Equal(ad[:32], rp[:]) {
		return fmt.Errorf("the authenticator data is for another relying party than %q", a.RP)
	}
	if ad[32]&flagUP == 0 {
		return fmt.Errorf("the authenticator did not report the user present")
	}
	if ad[32]&flagUV == 0 {
		return fmt.Errorf("the authenticator did not verify the user")
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Sig)
	if err != nil || len(sig) == 0 {
		return fmt.Errorf("the signature is not base64url")
	}
	cdHash := sha256.Sum256(cdRaw)
	msg := append(append([]byte{}, ad...), cdHash[:]...)
	return verifyWith(a.key, a.Alg, msg, sig)
}

// originUnder checks that origin is an https origin whose host is the relying party id or a subdomain of it.
func originUnder(origin, rp string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("the origin %q is not an https origin", origin)
	}
	if rp == "" || rp != strings.ToLower(rp) {
		return fmt.Errorf("the relying party id %q is not a lowercase host name", rp)
	}
	host := u.Hostname()
	if host != rp && !strings.HasSuffix(host, "."+rp) {
		return fmt.Errorf("the origin %q is not under the relying party %q", origin, rp)
	}
	return nil
}

// verifyWith verifies sig over msg: ES256 and RS256 sign sha256(msg), EdDSA signs msg.
func verifyWith(pub crypto.PublicKey, alg string, msg, sig []byte) error {
	switch alg {
	case "ES256":
		k, ok := pub.(*ecdsa.PublicKey)
		h := sha256.Sum256(msg)
		if !ok || !ecdsa.VerifyASN1(k, h[:], sig) {
			return fmt.Errorf("the signature does not verify")
		}
	case "RS256":
		k, ok := pub.(*rsa.PublicKey)
		h := sha256.Sum256(msg)
		if !ok || rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) != nil {
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
