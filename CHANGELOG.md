# Changelog

All notable changes to this verifier. It follows [Semantic Versioning](https://semver.org).

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
