# Security Policy & Cryptographic Assurance

## 1. Cryptographic Security Posture

**Truples** is architected around mathematically verifiable, end-to-end encrypted (E2EE) communication protocols. All cryptographic operations execute client-side utilizing standard W3C WebCrypto primitives (NIST P-384, HKDF-SHA256, AES-256-GCM).

### Core Security Guarantees:
- **Mutual Authenticated Key Exchange**: Mitigates Man-in-the-Middle (MITM) attacks via long-term P-384 ECDSA signatures over ephemeral P-384 ECDH exchange keys.
- **Strict Forward Secrecy (FS)**: Per-message symmetric KDF chain ratcheting prevents historical plaintext recovery even if current session state or long-term identity keys are compromised.
- **Post-Compromise Security (PCS)**: Automated asymmetric DH ratchet turns self-heal session security and permanently lock out historical state compromise attackers.
- **Replay & Rollback Invariance**: Enforced via 64-bit hardware monotonic counters, bounded replay caches, and 113-byte canonical binary AAD header bindings.
- **Zero-Retention Relay Infrastructure**: Ephemeral message payload transit where ciphertexts are permanently purged from relay caches immediately upon recipient receipt.

---

## 2. Independent Audit Status

> [!IMPORTANT]
> **Independent Audit Notice**: Truples has published its full cryptographic specification ([`docs/TRUPLES-RATCHET-SPEC.md`](docs/TRUPLES-RATCHET-SPEC.md)), machine-checked Tamarin Prover formal proofs ([`formal/PROOF_RESULTS.md`](formal/PROOF_RESULTS.md)), deterministic test vectors ([`vectors/deterministic_vectors.json`](vectors/deterministic_vectors.json)), and independent clean-room Rust conformance engine ([`implementations/rust/`](implementations/rust/)).  
> Formal third-party security audits by independent cryptographic research firms are currently planned in our operational roadmap.

---

## 3. Reporting a Security Vulnerability

If you discover a potential cryptographic vulnerability or security defect in the Truples protocol or reference implementations:

1. **Do NOT open a public GitHub issue.**
2. Email full technical details and proof-of-concept vectors to:  
   📧 **`security@truples.com`**
3. We operate under a **90-day coordinated vulnerability disclosure policy** and will respond within 48 hours with remediation tracking.
