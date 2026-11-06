# Changelog

All notable changes to this verifier. It follows [Semantic Versioning](https://semver.org).

## Unreleased

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
