# Changelog

All notable changes to this verifier. It follows [Semantic Versioning](https://semver.org).

## Unreleased

### Added

- Test vectors (`vectors/`). Fixed inputs with the result a correct checker must give, listed in `manifest.json`.
  Each has a stable id, `<kind letter><number>` (`T` tape, `H` head, `R` receipt, `C` config, `K` chain, `A` attest,
  `S` ssh, `L` revoked list), cited elsewhere as `<item>:<id>` such as `A4:R1`; an id is never reused, renumbered or
  dropped (`ids.lock`). A refused vector states a reason label and the phrase the failure must contain; no two refused vectors share a phrase, and every vector says it runs `--unpinned`. The first six
  (T1, T2, H1, H2, R1, R2) are made by `go run ./tools/mkvectors` from fixed seeds and a test fails if the committed
  files differ from a fresh run.
- Backfilled heads. A head signed after the fact, over a stretch the tape had no signed head for, is marked
  `backfilled` and signed under its own prefix (`authfi.audit.chain-head.backfill.v1`), so the mark cannot be added
  or cleared without breaking the signature. The report counts them (`Backfilled`) and says what they vouch for.
  Edits to the stretch are found exactly as for any other head. A verifier older than this version cannot check a
  backfilled head and reports it as not verifying; it is not a sign of tampering.

### Changed

- `config`: a person's approval of an agent configuration act is now sudo evidence ("Confirm it's you", the
  project's sudo window) and no longer a passkey assertion over the act's digest. The `passkey` approval kind is
  removed, with its WebAuthn, relying-party, origin, authenticator-data and signature checks; a `passkey` approval
  now fails with a clear reason. Two approvers are compared by name without regard to letter case, and by
  credential only where both carry one.
- What is no longer proven offline: that a person's hardware key signed the act's digest.
- What remains: the KMS agent-config key's countersign, chained to the pinned root; the digest recomputed from the
  act and matched to each approval; who confirmed, with which methods, when, and within which sudo window. CI
  approvals are unchanged, and so are the second-approver, loosening, numbering and tape rules.


## 1.1.0

### Added

- Verification of gateway decision receipts. Each receipt is signed by the tenant's receipt key, which is a
  different key from the one that signs the tape's heads. The report checks every receipt, binds each governed call
  to its decision, requires an outcome receipt on an allow, and counts calls with no receipt. Calls made before
  receipts began are noted, not failed.

## 1.0.1

### Fixed

- A head that was signed before its key's newest certificate was issued no longer fails the chain check. Key
  certificates are renewed and a bundle lists only the newest, so a window of older heads was reported as broken.

## 1.0.0

### Added

- `authfi-audit-verify`: checks an audit proof bundle offline. Entries link to each other and match their hashes,
  signed heads match the entries at their positions, `--root` pins the AuthFI root certificate, and `--heads`
  compares the bundle with heads you saved from a log stream.
- The `verify` package, for use as a library.
