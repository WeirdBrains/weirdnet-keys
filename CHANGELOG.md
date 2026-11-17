# Changelog

All notable changes to weirdnet-keys are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-17

### Added

- Age file reading (`agefile::decrypt`, `read_maybe_age`, `is_age`) accepts ASCII-armored
  files as well as binary ones, including text with leading whitespace before the armor
  marker.

## [0.1.0] - 2026-11-11

### Added

- 256-bit keys, BIP39 words, Shamir shards, HKDF and Argon2id derivation, XChaCha20-Poly1305
  sealing, X25519 agreement, HMAC, an envelope keyring with rotation, rekey and recovery,
  dark-shard sealing and age exports, under versioned label profiles.

[Unreleased]: https://github.com/WeirdBrains/weirdnet-keys/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/WeirdBrains/weirdnet-keys/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/WeirdBrains/weirdnet-keys/commit/bbf8e76
