package verify

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// act is one version or state act that has passed the checks that need only the act itself: the key, the
// signature, the digest and the passkey approvals. What depends on other acts is checked after, in order.
type act struct {
	typ        string
	digest     [32]byte
	approvals  []approval
	proposedAt int64
	approvedAt int64
	agent      string

	// version
	ver, floor int64
	hosts      map[string]bool // host tools, as name NUL sha256

	// state
	scope      string
	seq        int64
	mode       string
	needSecond bool
	ciKeys     []ciKey
}

func (a *act) persons() int {
	n := 0
	for _, ap := range a.approvals {
		if ap.person() {
			n++
		}
	}
	return n
}

func validAgentID(s string) bool {
	rest := strings.TrimPrefix(s, "agt_")
	if rest == s || rest == "" {
		return false
	}
	for _, c := range rest {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func modeRank(m string) int {
	switch m {
	case modeWatch:
		return 0
	case modeTools:
		return 1
	case modeStrict:
		return 2
	}
	return -1
}

// readAct checks one token on its own. The payload is read only after the signature holds under a key whose
// certificate chains to the pinned root, judged at the moment the act says it was countersigned.
func readAct(token, wantTyp, tenant string, o ConfigOptions, now time.Time) (*act, []string) {
	jws, err := splitJWS(token)
	if err != nil {
		return nil, []string{err.Error()}
	}
	if alg, _ := claimString(jws.header, "alg"); alg != "EdDSA" {
		return nil, []string{fmt.Sprintf("signed with %q; only EdDSA is accepted", alg)}
	}
	if typ, _ := claimString(jws.header, "typ"); typ != wantTyp {
		return nil, []string{fmt.Sprintf("its typ is %q, expected %q", typ, wantTyp)}
	}
	if _, has := jws.header["crit"]; has {
		return nil, []string{"its header lists critical extensions this verifier does not know"}
	}
	claims, err := strictObject(jws.payload)
	if err != nil {
		return nil, []string{"its payload " + err.Error()}
	}
	approvedAt, ok := claimInt(claims, "approved_at")
	if !ok || approvedAt <= 0 {
		return nil, []string{"it says when it was countersigned with no usable time"}
	}
	at := time.Unix(approvedAt, 0)
	if at.After(now.Add(configClockSkew)) {
		return nil, []string{"it was countersigned in the future, so its key cannot be judged"}
	}
	pub, err := proveActKey(jws.header, tenant, at, o.Root)
	if err != nil {
		return nil, []string{err.Error()}
	}
	if !ed25519.Verify(pub, []byte(jws.signingInput), jws.sig) {
		return nil, []string{"its signature does not verify under its key"}
	}

	a := &act{typ: wantTyp, approvedAt: approvedAt}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	wantV := int64(configVersionClaims)
	if wantTyp == ConfigStateType {
		wantV = configStateClaims
	}
	if v, ok := claimInt(claims, "v"); !ok || v != wantV {
		add("its claims are version %v, this verifier reads version %d", claims["v"], wantV)
	}
	if tid, _ := claimString(claims, "tid"); tid != tenant {
		add("it is for tenant %q, not this bundle's tenant", tid)
	}
	if p, ok := claimInt(claims, "proposed_at"); !ok || p <= 0 {
		add("it says when it was proposed with no usable time")
	} else {
		a.proposedAt = p
	}
	a.agent, _ = claimString(claims, "agent")

	d, err := actDigest(wantTyp, claims)
	if err != nil {
		add("%v", err)
		return a, problems
	}
	a.digest = d

	approvals, perrs := parseApprovals(claims)
	a.approvals = approvals
	problems = append(problems, perrs...)
	if len(perrs) == 0 {
		problems = append(problems, checkApprovers(claims, approvals)...)
		for i, ap := range approvals {
			if ap.Kind != kindPasskey {
				continue
			}
			if err := checkPasskey(ap, d); err != nil {
				add("approval %d by %s: %v", i, ap.By, err)
			}
		}
	}

	if wantTyp == ConfigVersionType {
		problems = append(problems, readVersionClaims(a, claims)...)
	} else {
		problems = append(problems, readStateClaims(a, claims)...)
	}
	return a, problems
}

// checkApprovers checks that the names the act states are the approvers: approved_by is the first approval's, and
// second_approver the second's, or empty when there is no second.
func checkApprovers(claims map[string]any, approvals []approval) []string {
	var problems []string
	by, _ := claimString(claims, "approved_by")
	second, _ := claimString(claims, "second_approver")
	if by != approvals[0].By {
		problems = append(problems, fmt.Sprintf("approved_by is %q, the first approval is by %q", by, approvals[0].By))
	}
	wantSecond := ""
	if len(approvals) == 2 {
		wantSecond = approvals[1].By
	}
	if second != wantSecond {
		problems = append(problems, fmt.Sprintf("second_approver is %q, the second approval is by %q", second, wantSecond))
	}
	return problems
}

func readVersionClaims(a *act, claims map[string]any) []string {
	var problems []string
	if !validAgentID(a.agent) {
		problems = append(problems, fmt.Sprintf("agent %q is not an agent id", a.agent))
	}
	if v, ok := claimInt(claims, "ver"); !ok || v < 1 {
		problems = append(problems, "ver is not a version number")
	} else {
		a.ver = v
	}
	if f, ok := claimInt(claims, "floor"); !ok || f < 0 || (a.ver > 0 && f > a.ver) {
		problems = append(problems, "floor is not 0 or a version up to this one")
	} else {
		a.floor = f
	}
	hosts, err := hostTools(claims["profiles"])
	if err != nil {
		problems = append(problems, err.Error())
	}
	a.hosts = hosts
	return problems
}

// hostTools reads the profiles claim and returns the host tools in it, by name and definition hash.
func hostTools(raw any) (map[string]bool, error) {
	profiles, ok := raw.([]any)
	if !ok || len(profiles) == 0 {
		return nil, fmt.Errorf("it holds no profiles")
	}
	hosts := map[string]bool{}
	for i, p := range profiles {
		pm, ok := p.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("profile %d is not an object", i)
		}
		tools, _ := pm["tools"].([]any)
		for j, t := range tools {
			tm, ok := t.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("tool %d of profile %d is not an object", j, i)
			}
			name, _ := claimString(tm, "name")
			sum, _ := claimString(tm, "sha256")
			host, isBool := tm["host"].(bool)
			if name == "" || sum == "" || (tm["host"] != nil && !isBool) {
				return nil, fmt.Errorf("tool %d of profile %d lacks a name, a definition hash or a host flag", j, i)
			}
			if host {
				hosts[name+"\x00"+sum] = true
			}
		}
	}
	return hosts, nil
}

func readStateClaims(a *act, claims map[string]any) []string {
	var problems []string
	a.scope, _ = claimString(claims, "scope")
	if s, ok := claimInt(claims, "seq"); !ok || s < 1 {
		problems = append(problems, "seq is not a sequence number")
	} else {
		a.seq = s
	}
	switch a.scope {
	case scopeAgent:
		if !validAgentID(a.agent) {
			problems = append(problems, fmt.Sprintf("agent %q is not an agent id", a.agent))
		}
		a.mode, _ = claimString(claims, "mode")
		if modeRank(a.mode) < 0 {
			problems = append(problems, fmt.Sprintf("mode %q is not watch, tools or strict", a.mode))
		}
		if f, ok := claimInt(claims, "floor"); !ok || f < 0 {
			problems = append(problems, "floor is not a version number or 0")
		} else {
			a.floor = f
		}
	case scopeTenant:
		if a.agent != tenantAgent {
			problems = append(problems, fmt.Sprintf("a tenant act names agent %q, not *", a.agent))
		}
		need, ok := claims["need_second"].(bool)
		if !ok {
			problems = append(problems, "need_second is not true or false")
		}
		a.needSecond = need
		keys, errs := readCIKeys(claims["ci_keys"])
		problems = append(problems, errs...)
		a.ciKeys = keys
	default:
		problems = append(problems, fmt.Sprintf("scope %q is not agent or tenant", a.scope))
	}
	for _, ap := range a.approvals {
		if ap.Kind == kindCI {
			problems = append(problems, "a state act is approved by people, not by a CI key")
			break
		}
	}
	return problems
}

func readCIKeys(raw any) ([]ciKey, []string) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, []string{"ci_keys is not a list"}
	}
	var keys []ciKey
	var problems []string
	seen := map[string]bool{}
	for i, r := range list {
		m, ok := r.(map[string]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("ci_keys[%d] is not an object", i))
			continue
		}
		k := ciKey{}
		k.ID, _ = claimString(m, "id")
		k.Name, _ = claimString(m, "name")
		k.Alg, _ = claimString(m, "alg")
		k.Pub, _ = claimString(m, "pub")
		pub, err := parsePublicKey(k.Pub)
		switch {
		case k.ID == "" || k.Name == "":
			problems = append(problems, fmt.Sprintf("ci_keys[%d] has no id or name", i))
		case seen[k.ID]:
			problems = append(problems, fmt.Sprintf("ci key id %q appears twice", k.ID))
		case err != nil:
			problems = append(problems, fmt.Sprintf("ci key %s: %v", k.ID, err))
		case (k.Alg != "ES256" && k.Alg != "EdDSA") || keyMatchesAlg(pub, k.Alg, kindCI) != nil:
			problems = append(problems, fmt.Sprintf("ci key %s: alg %q does not fit the key", k.ID, k.Alg))
		default:
			k.key = pub
			keys = append(keys, k)
		}
		seen[k.ID] = true
	}
	return keys, problems
}

// configRun is the state of one run.
type configRun struct {
	b   ConfigBundle
	o   ConfigOptions
	now time.Time
	r   *ConfigReport

	tenantRows []ConfigStateRow
	agentRows  map[string][]ConfigStateRow

	tenantActs []*act            // valid tenant acts, ascending seq
	versions   map[string][]*act // valid versions by agent, ascending ver
	states     map[string][]*act // valid agent states by agent, ascending seq
}

func (c *configRun) fail(format string, args ...any) {
	c.r.Failures = append(c.r.Failures, fmt.Sprintf(format, args...))
}

// tenantAt is the newest valid tenant act proposed no later than t; nil when none was, and the defaults apply.
func (c *configRun) tenantAt(t int64) *act {
	var best *act
	for _, a := range c.tenantActs {
		if a.proposedAt <= t && (best == nil || a.seq > best.seq) {
			best = a
		}
	}
	return best
}

// VerifyConfig checks every act of b against the pinned root and the rules for who may approve what.
func VerifyConfig(b ConfigBundle, o ConfigOptions) ConfigReport {
	r := ConfigReport{Tenant: b.Tenant, Versions: len(b.Versions), States: len(b.States)}
	c := &configRun{b: b, o: o, now: o.Now, r: &r, versions: map[string][]*act{}, states: map[string][]*act{}}
	if c.now.IsZero() {
		c.now = time.Now()
	}
	switch {
	case b.Tenant == "":
		c.fail("the bundle names no tenant")
	case o.Root == nil:
		c.fail("no root was given, so nothing says whose key signed")
	default:
		if len(b.Versions)+len(b.States) == 0 {
			r.Notes = append(r.Notes, "the bundle holds no acts, so there is nothing to check")
		}
		c.groupStates()
		c.tenantStates()
		c.versionActs()
		c.agentStates()
		c.summarise()
		if o.Tape != nil {
			c.checkTape(*o.Tape)
		}
	}
	r.OK = len(r.Failures) == 0
	return r
}

// groupStates files the state rows by (scope, agent) in seq order and checks their numbering.
func (c *configRun) groupStates() {
	var tenant []ConfigStateRow
	agents := map[string][]ConfigStateRow{}
	for _, row := range c.b.States {
		switch {
		case row.Scope == scopeTenant && (row.Agent == "" || row.Agent == tenantAgent):
			tenant = append(tenant, row)
		case row.Scope == scopeAgent && validAgentID(row.Agent):
			agents[row.Agent] = append(agents[row.Agent], row)
		default:
			c.fail("state row (scope %q, agent %q, seq %d) names no tenant act and no agent", row.Scope, row.Agent, row.Seq)
		}
	}
	c.numbered("the tenant's states", tenant)
	for agent, rows := range agents {
		c.numbered("agent "+agent+" states", rows)
	}
	c.tenantRows, c.agentRows = tenant, agents
}

// numbered sorts rows by seq and reports a first seq other than 1, a repeat or a gap: an act removed from the
// middle or the start of the record, or one of two acts that took the same place.
func (c *configRun) numbered(what string, rows []ConfigStateRow) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Seq < rows[j].Seq })
	for i, row := range rows {
		switch {
		case i == 0 && row.Seq != 1:
			c.fail("%s begin at seq %d: the acts before it are missing", what, row.Seq)
		case i > 0 && row.Seq == rows[i-1].Seq:
			c.fail("%s hold seq %d twice: only one act can have that place", what, row.Seq)
		case i > 0 && row.Seq != rows[i-1].Seq+1:
			c.fail("%s jump from seq %d to %d: acts are missing", what, rows[i-1].Seq, row.Seq)
		}
	}
}

// stateAgrees checks the token's own scope, agent and seq against the row that carries it. A token filed under a
// number other than the one it signed is an old act put in a newer one's place.
func (c *configRun) stateAgrees(row ConfigStateRow, a *act) []string {
	var problems []string
	wantAgent := row.Agent
	if row.Scope == scopeTenant {
		wantAgent = tenantAgent
	}
	if a.scope != row.Scope || a.agent != wantAgent {
		problems = append(problems, fmt.Sprintf("the row says scope %q agent %q, the act is for scope %q agent %q", row.Scope, wantAgent, a.scope, a.agent))
	}
	if a.seq != row.Seq {
		problems = append(problems, fmt.Sprintf("the row is seq %d, the act signed seq %d: a replayed act", row.Seq, a.seq))
	}
	return problems
}

func (c *configRun) tenantStates() {
	var prev *act
	for _, row := range c.tenantRows {
		label := fmt.Sprintf("tenant state seq %d", row.Seq)
		a, problems := readAct(row.Token, ConfigStateType, c.b.Tenant, c.o, c.now)
		if a != nil && len(problems) == 0 {
			problems = c.stateAgrees(row, a)
		}
		if a != nil && len(problems) == 0 {
			problems = c.tenantRules(a, prev)
		}
		if len(problems) > 0 {
			c.report(label, problems)
			continue
		}
		c.tenantActs = append(c.tenantActs, a)
		c.r.ValidStates++
		prev = a
	}
}

func (c *configRun) report(label string, problems []string) {
	for _, p := range problems {
		c.fail("%s: %s", label, p)
	}
}

// tenantRules checks a tenant act against the one before it. Turning the second-approver setting off, or adding a
// CI key while it is on, loosens, and needs two people.
func (c *configRun) tenantRules(a, prev *act) []string {
	if prev == nil || !prev.needSecond {
		return nil
	}
	var why string
	switch {
	case !a.needSecond:
		why = "turns the second-approver setting off"
	default:
		old := map[string]string{}
		for _, k := range prev.ciKeys {
			old[k.ID] = k.Alg + "/" + k.Pub
		}
		for _, k := range a.ciKeys {
			if old[k.ID] != k.Alg+"/"+k.Pub {
				why = "adds the CI key " + k.ID + " while the second-approver setting is on"
				break
			}
		}
	}
	if why != "" && a.persons() < 2 {
		return []string{fmt.Sprintf("it %s and carries %d person's approval; two people must approve", why, a.persons())}
	}
	return nil
}

func (c *configRun) versionActs() {
	byAgent := map[string][]ConfigVersionRow{}
	for _, row := range c.b.Versions {
		byAgent[row.Agent] = append(byAgent[row.Agent], row)
	}
	agents := make([]string, 0, len(byAgent))
	for agent := range byAgent {
		agents = append(agents, agent)
	}
	sort.Strings(agents)
	for _, agent := range agents {
		rows := byAgent[agent]
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Ver < rows[j].Ver })
		for i, row := range rows {
			label := fmt.Sprintf("version %d of %s", row.Ver, agent)
			if i > 0 && row.Ver == rows[i-1].Ver {
				c.fail("%s: the agent holds version %d twice", label, row.Ver)
				continue
			}
			if i > 0 && row.Ver != rows[i-1].Ver+1 {
				c.r.Notes = append(c.r.Notes, fmt.Sprintf("agent %s has no version between %d and %d in this bundle", agent, rows[i-1].Ver, row.Ver))
			}
			a, problems := readAct(row.Token, ConfigVersionType, c.b.Tenant, c.o, c.now)
			if a != nil && len(problems) == 0 {
				problems = c.versionAgrees(row, a)
			}
			if a != nil && len(problems) == 0 {
				problems = c.versionRules(a)
			}
			if len(problems) > 0 {
				c.report(label, problems)
				continue
			}
			c.versions[agent] = append(c.versions[agent], a)
			c.r.ValidVersions++
		}
	}
}

func (c *configRun) versionAgrees(row ConfigVersionRow, a *act) []string {
	var problems []string
	if a.agent != row.Agent {
		problems = append(problems, fmt.Sprintf("the row is for agent %q, the act for %q", row.Agent, a.agent))
	}
	if a.ver != row.Ver {
		problems = append(problems, fmt.Sprintf("the row is version %d, the act signed version %d", row.Ver, a.ver))
	}
	return problems
}

// versionRules checks a version against the tenant's settings as they stood when it was proposed: its CI
// approvals are by keys the tenant had registered, and a first version, or one adding a host tool no earlier valid
// version had, has two people's approval when the tenant asked for that.
func (c *configRun) versionRules(a *act) []string {
	var problems []string
	t := c.tenantAt(a.proposedAt)
	var keys []ciKey
	need := false
	if t != nil {
		keys, need = t.ciKeys, t.needSecond
	}
	for i, ap := range a.approvals {
		if ap.Kind == kindCI {
			if err := checkCI(ap, a.digest, keys); err != nil {
				problems = append(problems, fmt.Sprintf("approval %d by %s: %v", i, ap.By, err))
			}
		}
	}
	if !need {
		return problems
	}
	earlier := c.versions[a.agent]
	var why string
	if len(earlier) == 0 {
		why = "is the agent's first version"
	} else {
		known := map[string]bool{}
		for _, e := range earlier {
			for h := range e.hosts {
				known[h] = true
			}
		}
		var added []string
		for h := range a.hosts {
			if !known[h] {
				added = append(added, strings.Replace(h, "\x00", "@", 1))
			}
		}
		sort.Strings(added)
		if len(added) > 0 {
			why = "adds the host tool " + added[0]
		}
	}
	if why != "" && a.persons() < 2 {
		problems = append(problems, fmt.Sprintf("it %s and the tenant requires a second approver, but it carries %d person's approval", why, a.persons()))
	}
	return problems
}

func (c *configRun) agentStates() {
	for _, agent := range sortedKeysSeen(c.agentRows) {
		var prev *act
		for _, row := range c.agentRows[agent] {
			label := fmt.Sprintf("state seq %d of %s", row.Seq, agent)
			a, problems := readAct(row.Token, ConfigStateType, c.b.Tenant, c.o, c.now)
			if a != nil && len(problems) == 0 {
				problems = c.stateAgrees(row, a)
			}
			if a != nil && len(problems) == 0 {
				problems = c.agentRules(a, prev)
			}
			if len(problems) > 0 {
				c.report(label, problems)
				continue
			}
			c.states[agent] = append(c.states[agent], a)
			c.r.ValidStates++
			prev = a
		}
	}
}

// agentRules checks an agent's state against the one before it. The tier falling (watch, tools, strict, in that
// order) or the floor falling loosens, and needs two people. With no state before, the tier in force is tools
// when the agent has a version, so a first state of watch loosens.
func (c *configRun) agentRules(a, prev *act) []string {
	baseline, baseFloor := 0, int64(0)
	switch {
	case prev != nil:
		baseline, baseFloor = modeRank(prev.mode), prev.floor
	case len(c.versions[a.agent]) > 0:
		baseline = modeRank(modeTools)
	}
	var why string
	switch {
	case modeRank(a.mode) < baseline:
		why = "lowers the tier"
	case a.floor < baseFloor:
		why = fmt.Sprintf("lowers the floor from %d to %d", baseFloor, a.floor)
	}
	if why != "" && a.persons() < 2 {
		return []string{fmt.Sprintf("it %s and carries %d person's approval; two people must approve", why, a.persons())}
	}
	return nil
}

// summarise reports the newest state and the versions in force for each agent, and the tenant's settings.
func (c *configRun) summarise() {
	r := c.r
	if n := len(c.tenantActs); n > 0 {
		t := c.tenantActs[n-1]
		r.TenantSeq, r.NeedSecond, r.CIKeys = t.seq, t.needSecond, len(t.ciKeys)
	}
	seen := map[string]bool{}
	for agent := range c.versions {
		seen[agent] = true
	}
	for agent := range c.states {
		seen[agent] = true
	}
	for _, agent := range sortedKeys(seen) {
		ac := AgentConfig{Agent: agent, Mode: modeTools}
		vs := c.versions[agent]
		if sts := c.states[agent]; len(sts) > 0 {
			s := sts[len(sts)-1]
			ac.StateSeq, ac.Mode, ac.Floor, ac.Signed = s.seq, s.mode, s.floor, true
		} else if len(vs) == 0 {
			ac.Mode = ""
		}
		for _, v := range vs {
			if v.floor > ac.Floor {
				ac.Floor = v.floor
			}
		}
		for _, v := range vs {
			ac.Newest = v.ver
			if v.ver >= ac.Floor {
				ac.InForce = append(ac.InForce, v.ver)
			}
		}
		r.Agents = append(r.Agents, ac)
	}
}

// checkTape compares the newest version the tape records as approved for each agent with the bundle's newest. A
// tape ahead of the bundle is a rolled-back tail: the bundle was cut before a later approval, or a later version
// was taken out of it.
func (c *configRun) checkTape(tape Bundle) {
	if tape.TenantID != c.b.Tenant {
		c.fail("the tape is for tenant %q, the bundle for %q", tape.TenantID, c.b.Tenant)
		return
	}
	for _, f := range Verify(tape, Options{Root: c.o.Root}).Failures {
		c.fail("the tape: %s", f)
	}
	type seen struct {
		ver        int64
		approvedBy string
		seq        int64
	}
	newest := map[string]seen{}
	for _, e := range tape.Entries {
		if e.Action != ConfigApprovedAction {
			continue
		}
		m, err := entryMeta(e)
		if err != nil {
			c.fail("the tape, position %d: an approved-version event whose metadata is not JSON", e.Seq)
			continue
		}
		ver, ok := eventInt(m["ver"])
		agent := strings.TrimPrefix(e.Resource, "agent:")
		if !ok || ver < 1 || agent == "" {
			c.fail("the tape, position %d: an approved-version event with no usable agent or ver", e.Seq)
			continue
		}
		if prev, ok := newest[agent]; !ok || e.Seq > prev.seq {
			by, _ := claimString(m, "approved_by")
			newest[agent] = seen{ver, by, e.Seq}
		}
	}
	genesis := len(tape.Entries) > 0 && tape.Entries[0].PrevHash == ""
	bundle := map[string]AgentConfig{}
	for _, ac := range c.r.Agents {
		bundle[ac.Agent] = ac
	}
	for _, agent := range sortedKeysSeen(newest) {
		t, ac := newest[agent], bundle[agent]
		switch {
		case t.ver > ac.Newest:
			c.fail("agent %s: the tape records version %d approved (position %d) and the bundle's newest is %d: the bundle may be rolled back", agent, t.ver, t.seq, ac.Newest)
		case t.ver < ac.Newest:
			c.fail("agent %s: the bundle holds version %d and the tape's newest approved version is %d (position %d): that version was not approved on the tape", agent, ac.Newest, t.ver, t.seq)
		default:
			if by := c.approvedBy(agent, t.ver); by != t.approvedBy {
				c.fail("agent %s: the tape says version %d was approved by %q, the act says %q", agent, t.ver, t.approvedBy, by)
				continue
			}
			c.r.TapeAgents++
		}
	}
	for _, ac := range c.r.Agents {
		if _, ok := newest[ac.Agent]; ok || ac.Newest == 0 {
			continue
		}
		if genesis {
			c.fail("agent %s: the bundle holds version %d and the tape, which starts at its beginning, records no approved version", ac.Agent, ac.Newest)
		} else {
			c.r.Notes = append(c.r.Notes, fmt.Sprintf("agent %s: the tape window records no approved version, which may lie before it", ac.Agent))
		}
	}
}

// approvedBy is the first approver of the agent's valid version ver.
func (c *configRun) approvedBy(agent string, ver int64) string {
	for _, v := range c.versions[agent] {
		if v.ver == ver {
			return v.approvals[0].By
		}
	}
	return ""
}

func sortedKeysSeen[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// eventInt reads a number the tape stores as text, or as a JSON number.
func eventInt(v any) (int64, bool) {
	switch x := v.(type) {
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	case float64:
		return int64(x), float64(int64(x)) == x
	}
	return 0, false
}
