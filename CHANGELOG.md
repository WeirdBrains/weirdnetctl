# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Passphrase-sealed Ed25519 key files (Argon2id, XChaCha20-Poly1305): `key new`, `show`, `check`.
- `key rotate`: a new root key and a rotation signed by both keys.
- `prefix` and `scheme`: sign registrations and withdrawals.
- `countersign`: root signatures for reserved records, transfer signatures for prefixes.
- `list`: build, sign and self-check the canonical list.
- `verify`: check records, lists and rotations against anchor keys.

[Unreleased]: https://github.com/WeirdBrains/weirdnetctl/compare/16eee278a6ad7b2547de45e1ca686ba67c00ee8b...HEAD
