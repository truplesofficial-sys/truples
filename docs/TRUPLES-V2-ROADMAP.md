# Truples Protocol Evolution: v2 Asynchronous & Post-Quantum Roadmap

This technical specification outlines the architectural roadmap for **Truples Protocol v2**, extending the verified **v1 Classical Double Ratchet Core (P-384 / HKDF / AES-GCM)** into asynchronous messaging, multi-device session management, and hybrid post-quantum cryptography.

---

## 1. Protocol Evolution Milestones

```text
┌────────────────────────────────────────────────────────────────────────┐
│ TRUPLES v1 (Production Core - FROZEN 🔒)                                │
│ - Synchronous Authenticated ECDH (P-384) + Directional KDF Chain       │
│ - AES-256-GCM + 113-Byte Canonical AAD Binding                         │
│ - Ephemeral DH Continuous Automated Turn-Taking (PCS & Temporal FS)    │
│ - Monotonic Anti-Rollback Storage Abstraction (Atomic CAS Commits)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ TRUPLES v2 (Asynchronous Multi-Device & Post-Quantum Evolution)        │
│ 1. Asynchronous X3DH Initial Key Agreement (Signed & One-Time PreKeys) │
│ 2. Sesame-Inspired Multi-Device Identity & Session Fanout Management   │
│ 3. Hybrid Post-Quantum KEM (NIST ML-KEM-768 / Kyber + P-384 ECDH)      │
│ 4. Hardware Attestation Token Binding (Android StrongBox & iOS Enclave)│
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Milestone 1: Asynchronous X3DH Key Agreement

To support offline first-message transmission without requiring concurrent real-time ECDH handshakes:
- **Identity Key ($IK$)**: Long-term P-384 ECDSA/ECDH identity.
- **Signed PreKey ($SPK$)**: Medium-term P-384 key signed by identity key, rotated weekly.
- **One-Time PreKeys ($OPK$)**: Pool of single-use ephemeral keys replenished by clients.
- **Triple/Quadruple DH Agreement**:
  $$\text{PRK} = \text{HKDF-Extract}(\text{Salt}, \text{DH}(IK_A, SPK_B) \mathbin{\Vert} \text{DH}(EK_A, IK_B) \mathbin{\Vert} \text{DH}(EK_A, SPK_B) \mathbin{\Vert} \text{DH}(EK_A, OPK_B))$$

---

## 3. Milestone 2: Multi-Device Session Management

- **Device Identity Isolation**: Each client device ($D_{A,1}, D_{A,2}$) provisions independent ratchet state machines.
- **Pairwise Device Sessions**: $N \times M$ encrypted pairwise double ratchets guaranteeing device-level forward secrecy.
- **Cryptographic Device Revocation**: Immediate key retirement upon device unlinking with retroactive state invalidation.

---

## 4. Milestone 3: Hybrid Post-Quantum Cryptography

- **Dual-Layer KEM Combination**:
  $$\text{SharedSecret}_{\text{Hybrid}} = \text{ECDH}(P384) \mathbin{\Vert} \text{Decapsulate}(\text{ML-KEM-768})$$
- Ensures that compromised elliptic curve discrete log algorithms (via Shor's algorithm on quantum computers) cannot retroactively decrypt captured transit traffic.
