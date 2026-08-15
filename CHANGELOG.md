# Changelog

All notable changes to the Truples Protocol Reference Implementation and Specifications will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2026-08-16

### Added
- **Symmetric KDF Chain Ratchet**: Implemented `ratchetMessageKey()` in `truples-crypto.js` using `HKDF-SHA256` to derive single-use message keys and advance the chain key, guaranteeing strict per-message Forward Secrecy.
- **Dynamic CSPRNG Salt**: Enforced dynamic 32-byte cryptographically secure random salt in `deriveRootAndChainKeys()`.
- **Automated Forward Secrecy Test**: Added Test Vector 3 in `tests/crypto.test.js` validating that historical message keys fail to decrypt ratcheted transmissions.

### Changed
- **Documentation Refinement**: Refined `README.md` and `01_cryptographic_specification.md` to remove competitive comparison tables and explicitly delineate client-side verified primitives versus server-side audit roadmaps.

---

## [2.0.0] - 2026-08-16

### Added
- Initial public release of Truples cryptographic core (`src/crypto/truples-crypto.js`).
- Automated cryptographic self-test suite (`tests/crypto.test.js`) covering ECDH P-384, AES-256-GCM, 96-bit IV freshness, 128-bit MAC tamper resistance, and memory zeroization.
- Core technical specifications for WebRTC P2P media mesh, panic matrix, and protocol threat model.
