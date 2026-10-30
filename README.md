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

The command exits `0` when the bundle passes, `1` when it fails and `2` when it could not run.

## What each check tells you

| Check | What it catches |
|---|---|
| Entries link to each other and match their hashes | An entry was changed or removed from inside the window |
| A signed head matches the entry at its position | The record was rewritten after that position was signed |
| `--root`: the signing key's certificate chains to the root | Someone else's key signed the head |
| `--heads`: heads you saved match the bundle | The record was rewritten, even by someone holding the signing key |

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
