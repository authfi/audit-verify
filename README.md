# audit-verify

Check an AuthFI audit record yourself, on your own machine. The verifier holds no secret, makes no network
call and imports only the Go standard library, so you don't have to take AuthFI's word for what it says.

## Install

```sh
go install github.com/authfi/audit-verify/cmd/authfi-audit-verify@latest
```

## Check a record

Open **Audit** in the AuthFI console and choose **Download proof**. Then run:

```sh
authfi-audit-verify --bundle proof.json
```

To also check who holds the signing key, pin the AuthFI root certificate:

```sh
authfi-audit-verify --bundle proof.json --root roots/authfi-root-ca-r1.pem
```

To check the record against the signed heads you received on a log stream, give it your export. Other events
in the file are skipped, so you can pass it as it arrived:

```sh
authfi-audit-verify --bundle proof.json --heads saved-heads.ndjson
```

The command exits `0` when the bundle passes, `1` when it fails and `2` when it could not run. When the tape
holds governed MCP tool calls it also prints how many decision receipts verified and how many are missing, and
any receipt that fails exits `1`.

## What each check tells you

| Check | What it catches |
|---|---|
| Entries link to each other and match their hashes | An entry was changed or removed from inside the window |
| A signed head matches the entry at its position | The record was rewritten after that position was signed |
| `--root`: the signing key's certificate chains to the root | Someone else's key signed the head |
| `--heads`: heads you saved match the bundle | The record was rewritten, even by someone holding the signing key |
| Each receipt verifies under a `receipt` key of the bundle | A receipt was forged, altered, signed by the wrong key, or made for another tenant |
| Each governed call names a receipt for that very call | A receipt was copied onto another call's entry, or its verdict contradicts the tape |
| Every governed call has a receipt | A receipt was left off the tape |

A head you keep outside AuthFI is the strongest of these, because no one can change your copy.

A pass says the record is intact. It can't say an entry was true when it was written, or anything about
entries outside the bundle.

## The format

The format is simple enough to check in any language.

```text
entry_hash  = hex(sha256(prev_hash US id US actor US action US resource US recorded_at US metadata))
head signed = "authfi.audit.chain-head.v1" LF tenant LF seq LF entry_hash, with Ed25519
```

`US` is the byte `0x1F` and `LF` is `0x0A`. `recorded_at` and `metadata` are the exact strings in the bundle. A
bundle's `format` field is `authfi.audit.proof.v1`, and a signature is base64url without padding.

## Decision receipts

Each decision the MCP gateway makes about a tool call is a receipt: a statement signed with the tenant's
`receipt` key, which is a different key from the one that signs the tape's heads, so neither can forge the
other's. A receipt is a JWS in compact form and rides in the member `receipt` of an entry's metadata.

```text
header     {"alg":"EdDSA","typ":"authfi-receipt+jwt","kid":...}
payload    v, tid, rid, ph, req, did, pgen, pbasis, pmatch, cpv, verdict, reason, agent, obo, tool, class,
           mandate, appr, args, out, res, drid, iat
signature  Ed25519 over base64url(header) "." base64url(payload)
```

`v` is `1`, `tid` the tenant, `rid` the receipt's id, `ph` the phase (`decision`, `outcome` or `rule`), `req` the
request id, `args` and `res` digests of the arguments and the result, `drid` the decision receipt an outcome
belongs to and `iat` the issue time in unix seconds.

A decision receipt rides an `mcp.decision.receipt` entry. The call's own entry has `receipt_id` (the decision
receipt's `rid`) and `request_id` in its metadata and, for an allowed call, its outcome receipt in `receipt`. A
tool call is an `mcp.tool.call` entry (the audit service stores it as `mcp.tool.called`; both are read) with
resource `mcp_tool:<tool>`; a model call is an `mcp.model.call` entry
with resource `model:<provider>/<model>`, which is the receipt's `tool`. Both are checked the same way. A decision
nobody's call names (approval required, or an allow that was later refused) is a receipt on its own, not a failure.

The checks, with the keys the bundle lists:

1. **Each receipt.** `typ` and `alg` are exact, the key is in the bundle with `use` `receipt` and is not
   revoked, the signature verifies, the tenant is the bundle's and `v` is `1`. A head verifies only under an
   `audit_head` key (a key with no `use` is one) and a receipt only under a `receipt` key. With `--root`, every
   receipt key must chain to the root, judged at the moment the receipt was issued.
2. **Binding.** A call's `receipt_id` must be the `rid` of a decision receipt in the bundle for the same request,
   tool and agent, whose verdict is the `allow` or `deny` the tape records. An allowed call must carry an
   outcome receipt whose `drid` is that decision and whose `out` is the outcome the tape records.
3. **Completeness.** Every governed call in the window has a verified decision receipt. Calls made before
   receipts began (no `receipt_id`, and no earlier call in the window has one) are counted and noted, not
   failed. A call with a `receipt_id` whose receipt is not in the bundle fails as `receipt missing`, unless it is
   within 100 positions of the window's edge: the receipt may sit just outside, so it is noted and a wider
   window settles it.
4. **Time.** A receipt's `iat` must be within an hour of the recorded time of the entry that carries it, in
   either direction.
5. **Uniqueness and place.** A receipt id is never two different receipts, and receipts appear only on
   `mcp.decision.receipt`, `mcp.tool.call` and `mcp.model.call` entries.

The report also counts, as notes and never failures: governed calls the gateway refused because it could not sign
their receipt (the deny entry says `receipt_unavailable`, an allow saying so fails), and allowed decisions older
than ten minutes before the end of the window that no call entry names, where the call may not have completed.

**What a pass does not say.** That the gateway decided correctly, or that the policy it named was the right
one: a receipt is the gateway's signed statement of what it decided, not proof of why. It does not cover calls
that never reached the gateway, and a call made before receipts began carries none and is only counted. Notes
in the report say what was not checked. The `agent` claim is compared with the entry's actor after the principal's type prefix,
and the other claims (`obo`, `appr`, `class`, `args`, `res`) are signed but not matched to the tape.

## The root certificate

`roots/authfi-root-ca-r1.pem` is AuthFI Root CA R1. Its SHA-256 fingerprint is:

```text
D9:C2:A9:C7:0A:A8:53:AC:01:D3:B2:E3:D4:50:51:28:AB:28:E2:78:18:27:79:5D:25:C9:0A:CF:1D:BA:1B:54
```

## Use it as a library

```go
report := verify.Verify(bundle, verify.Options{Root: pool, Saved: heads})
```

Import `github.com/authfi/audit-verify/verify`. See the package documentation for the bundle's fields.

## License

Apache 2.0.
