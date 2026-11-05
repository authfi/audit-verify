package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// An approved agent configuration is a set of acts. Each act is a compact JWS the tenant's agent_config key signed
// after a person (or a CI key) approved it, and it carries the approvals that authorise it:
//
//	version  typ "authfi-agent-config+jwt"        the profiles one agent is allowed to run, numbered by ver
//	state    typ "authfi-agent-config-state+jwt"  an agent's tier and floor, or the tenant's settings and CI keys
//
// The approvals are over a digest of the act's claims, so the key's signature is only the countersignature: what a
// person approved is checked here from the claims, with the pinned root as the only trust. The rules are in
// configapproval.go (digest and approvals) and configrules.go (who may approve what).
const (
	// ConfigVersionType and ConfigStateType are the JWS typ of the two acts.
	ConfigVersionType = "authfi-agent-config+jwt"
	ConfigStateType   = "authfi-agent-config-state+jwt"
	// ConfigKeyUse is the use a custody certificate states for the key that signs these acts.
	ConfigKeyUse = "agent_config"

	configVersionClaims = 2
	configStateClaims   = 1
	// configClockSkew is how far past the verifier's clock an act may claim to have been countersigned.
	configClockSkew = 5 * time.Minute
	maxConfigToken  = 4 << 20
	maxChainCerts   = 4

	scopeAgent  = "agent"
	scopeTenant = "tenant"
	tenantAgent = "*"

	modeWatch  = "watch"
	modeTools  = "tools"
	modeStrict = "strict"

	// ConfigApprovedAction is the tape action the gateway files when it signs a version.
	ConfigApprovedAction = "mcp.agent_config.approved"
)

// The certificate policies a custody certificate states: the key is held by AuthFI's KMS (1) or inside an HSM (2).
// A certificate that states the subject-held policy (3) is a workload's and never vouches for a signing key.
const (
	policyHSMCustody  = "1.3.6.1.4.1.67322.1.1"
	policyHSMResident = "1.3.6.1.4.1.67322.1.2"
	policySubjectHeld = "1.3.6.1.4.1.67322.1.3"
)

// ConfigVersionRow and ConfigStateRow are the rows of a bundle. Only the token is believed: the other columns are
// what the bundle's maker says, and the token must agree with them.
type ConfigVersionRow struct {
	Agent string `json:"agent"`
	Ver   int64  `json:"ver"`
	Token string `json:"token"`
}

// ConfigStateRow is one state act of the bundle. Agent is "*" (or empty) for the tenant's own act.
type ConfigStateRow struct {
	Scope string `json:"scope"`
	Agent string `json:"agent"`
	Seq   int64  `json:"seq"`
	Token string `json:"token"`
}

// ConfigBundle is every version and state act a tenant holds.
type ConfigBundle struct {
	Tenant   string             `json:"tenant"`
	Versions []ConfigVersionRow `json:"versions"`
	States   []ConfigStateRow   `json:"states"`
}

// ConfigOptions are what the person checking brings.
type ConfigOptions struct {
	// Root is the pinned trust anchor. Required: without it nothing says whose key signed.
	Root *x509.CertPool
	// Now is the verifier's clock; zero means the time of the call.
	Now time.Time
	// Tape, when set, is a proof bundle of the tenant's audit tape. The newest version it records as approved for
	// each agent must be the bundle's newest.
	Tape *Bundle
}

// AgentConfig is what the bundle says about one agent.
type AgentConfig struct {
	Agent string
	// Newest is the highest valid version; 0 when none is.
	Newest int64
	// InForce are the valid versions at or above Floor, ascending.
	InForce []int64
	// Floor is the highest of the newest valid state's floor and every valid version's floor.
	Floor int64
	// StateSeq is the newest valid state's seq; 0 when there is none, and Mode is then the default tier.
	StateSeq int64
	Mode     string
	// Signed is whether Mode comes from a signed state rather than the default.
	Signed bool
}

// ConfigReport is the outcome of VerifyConfig. OK is false once anything in Failures is set.
type ConfigReport struct {
	OK     bool
	Tenant string
	// Versions and States are the tokens read; ValidVersions and ValidStates passed every check.
	Versions, ValidVersions int
	States, ValidStates     int
	// TenantSeq is the newest valid tenant state; 0 when there is none, and the settings are then the defaults.
	TenantSeq  int64
	NeedSecond bool
	CIKeys     int
	Agents     []AgentConfig
	// TapeAgents is how many agents' newest approved version matched the tape's.
	TapeAgents int
	Failures   []string
	Notes      []string
}

// jwsParts is a compact JWS split and decoded, its signature not yet checked.
type jwsParts struct {
	signingInput string
	header       map[string]any
	payload      []byte
	sig          []byte
}

// splitJWS decodes the three parts of a compact JWS. Nothing in it is believed yet.
func splitJWS(token string) (jwsParts, error) {
	if len(token) > maxConfigToken {
		return jwsParts{}, fmt.Errorf("the token is larger than %d bytes", maxConfigToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwsParts{}, fmt.Errorf("it is not a compact JWS")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return jwsParts{}, fmt.Errorf("its header is not base64url")
	}
	header, err := strictObject(rawHeader)
	if err != nil {
		return jwsParts{}, fmt.Errorf("its header: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwsParts{}, fmt.Errorf("its payload is not base64url")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return jwsParts{}, fmt.Errorf("its signature is not base64url")
	}
	return jwsParts{parts[0] + "." + parts[1], header, payload, sig}, nil
}

// strictObject decodes a JSON object into a map, with numbers kept as written, and refuses one that repeats a key at
// its top level: readers disagree about which of two values a repeated key means.
func strictObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("is not JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("is not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("is not JSON: %w", err)
		}
		key, _ := kt.(string)
		if seen[key] {
			return nil, fmt.Errorf("repeats the key %q", key)
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, fmt.Errorf("is not JSON: %w", err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("is not JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("has data after the object")
	}
	var m map[string]any
	d2 := json.NewDecoder(bytes.NewReader(raw))
	d2.UseNumber()
	if err := d2.Decode(&m); err != nil {
		return nil, fmt.Errorf("is not JSON: %w", err)
	}
	return m, nil
}

func claimString(m map[string]any, k string) (string, bool) {
	s, ok := m[k].(string)
	return s, ok
}

// claimInt reads an integer claim, written as an integer.
func claimInt(m map[string]any, k string) (int64, bool) {
	n, ok := m[k].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	return v, err == nil
}

// proveActKey checks the key behind an act: the header's x5c chains to the pinned root as it stood at the moment the
// act was countersigned, the leaf certifies the key that signed, and its subject says it is this tenant's
// agent_config key with this kid. It returns the public key. A header with no x5c is refused: nothing then says
// whose key signed.
func proveActKey(h map[string]any, tenant string, at time.Time, root *x509.CertPool) (ed25519.PublicKey, error) {
	kid, _ := claimString(h, "kid")
	if kid == "" {
		return nil, fmt.Errorf("its header names no key")
	}
	raw, ok := h["x5c"].([]any)
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("its header carries no x5c, so nothing says who holds the key")
	}
	if len(raw) > maxChainCerts {
		return nil, fmt.Errorf("its x5c lists %d certificates, at most %d are read", len(raw), maxChainCerts)
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for i, r := range raw {
		s, _ := r.(string)
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("x5c certificate %d is not base64", i)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c certificate %d does not parse: %w", i, err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("its certificate is not for an Ed25519 key")
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("its certificate is not a signing certificate")
	}
	if ou := leaf.Subject.OrganizationalUnit; len(ou) != 1 || ou[0] != "tenant "+tenant {
		return nil, fmt.Errorf("its certificate is not for this tenant")
	}
	if leaf.Subject.CommonName != ConfigKeyUse+" signing key "+kid {
		return nil, fmt.Errorf("its certificate is for another key use or kid, not %s key %s", ConfigKeyUse, kid)
	}
	if !stateCustody(leaf) {
		return nil, fmt.Errorf("its certificate does not state that AuthFI custody holds the key")
	}
	pool := x509.NewCertPool()
	for _, c := range certs[1:] {
		pool.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: root, Intermediates: pool, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, fmt.Errorf("its certificate does not chain to the root at %s: %w", at.UTC().Format(time.RFC3339), err)
	}
	for _, chain := range chains {
		if custodyCAs(chain) {
			return pub, nil
		}
	}
	return nil, fmt.Errorf("a certificate between its key and the root does not state AuthFI custody")
}

// stateCustody reports whether c states one of the two custody policies and not the subject-held one.
func stateCustody(c *x509.Certificate) bool {
	custody := false
	for _, p := range c.PolicyIdentifiers {
		switch p.String() {
		case policyHSMCustody, policyHSMResident:
			custody = true
		case policySubjectHeld:
			return false
		}
	}
	return custody
}

// custodyCAs reports whether every CA strictly between the leaf and the root states custody.
func custodyCAs(chain []*x509.Certificate) bool {
	if len(chain) < 2 {
		return false
	}
	for _, ca := range chain[1 : len(chain)-1] {
		if !stateCustody(ca) {
			return false
		}
	}
	return true
}

// sortedKeys returns the keys of a set in order.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// digestOf is sha256(prefix || canonical body); see canonicalDigest.
func digestOf(prefix string, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write(body)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}
