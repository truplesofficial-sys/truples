# Signal PQXDH Specification Alignment & Truples Hybrid PQXDH Architecture

## 1. Overview & Objective

Truples implements a **Hybrid Post-Quantum Extended Diffie-Hellman Key Agreement Protocol** based on the architectural principles of the **Signal PQXDH Specification** to achieve **Post-Quantum Forward Secrecy** during session initialization.

While standard Double Ratchet protects ongoing conversations with symmetric KDF chains and ephemeral DH ratchet rotations (Post-Compromise Security), traditional initial key exchanges (X3DH) rely exclusively on discrete logarithms (ECDH). If a quantum adversary records ciphertext traffic today (*Harvest-Now-Decrypt-Later* attack), they could retroactively decrypt initial exchanges upon the realization of cryptographically relevant quantum computers (CRQCs).

**Truples Hybrid PQXDH eliminates this threat** by combining:
1. **Classical ECDH over NIST P-384** (high-security 192-bit classical security level, FIPS 186-4 / RFC 5903)
2. **NIST FIPS 203 ML-KEM-768 (Kyber-768)** (Category 3 lattice-based post-quantum key encapsulation)

---

## 2. Signal PQXDH Specification vs Truples Implementation: 1:1 Correspondence & Difference Matrix

The following table provides an exhaustive, item-by-item comparison between the official **Signal PQXDH Specification (v1)** and the **Truples Hybrid PQXDH** implementation:

| Protocol Parameter | Signal PQXDH (Official Specification) | Truples Hybrid PQXDH Implementation | Alignment Status & Technical Rationale |
| :--- | :--- | :--- | :--- |
| **Classical Asymmetric Curve** | Curve25519 / X25519 (256-bit) | NIST P-384 / secp384r1 (384-bit) | ⚠️ **Deliberate Design Decision**: Truples operates at NIST 192-bit classical security standard across all primitives via W3C WebCrypto API. |
| **Identity Authentication** | Ed25519 or XEd25519 Signatures | ECDSA over NIST P-384 with SHA-384 (FIPS 186-4) | ⚠️ **Deliberate Design Decision**: Standardized WebCrypto ECDSA P-384 signature algorithm. |
| **Signed Prekey (SPK)** | Curve25519 ECDH + Ed25519 Sig | NIST P-384 ECDH + ECDSA P-384 Sig | ⚠️ Aligned in role; uses P-384 curve for 192-bit classical margin. |
| **One-Time Prekey (OPK)** | Curve25519 ECDH (Optional) | NIST P-384 ECDH (Optional) | ⚠️ Aligned in role; uses P-384 curve. |
| **Post-Quantum KEM** | Kyber-1024 / ML-KEM-768 | NIST FIPS 203 ML-KEM-768 (Kyber-768) | ✅ **100% Aligned**: Category 3 Post-Quantum standard (AES-192 equivalent). |
| **PQ Signed Prekey (PQSPK)** | ML-KEM-768 public key (1,184 B) + Sig | ML-KEM-768 public key (1,184 B) + Sig | ✅ **100% Aligned**: Verified by ECDSA Identity key signature before KDF. |
| **PQ One-Time Prekey (PQOPK)** | ML-KEM-768 OPK (1,184 B) | ML-KEM-768 OPK (1,184 B) | ✅ **100% Aligned**: Supports optional one-time post-quantum prekeys. |
| **DH1 Computation** | $\text{ECDH}(IK_A, SPK_B)$ | $\text{ECDH}(IK_A, SPK_B)$ | ✅ **100% Aligned**: Mutual identity authentication. |
| **DH2 Computation** | $\text{ECDH}(EK_A, IK_B)$ | $\text{ECDH}(EK_A, IK_B)$ | ✅ **100% Aligned**: Forward secrecy against Bob compromise. |
| **DH3 Computation** | $\text{ECDH}(EK_A, SPK_B)$ | $\text{ECDH}(EK_A, SPK_B)$ | ✅ **100% Aligned**: Ephemeral forward secrecy. |
| **DH4 Computation** | $\text{ECDH}(EK_A, OPK_B)$ | $\text{ECDH}(EK_A, OPK_B)$ | ✅ **100% Aligned**: Ephemeral protection against replay. |
| **PQ Shared Secret ($ss_{pq}$)** | $\text{MLKEM.Encaps}(PQSPK_B)$ | $\text{MLKEM.Encaps}(PQSPK_B)$ | ✅ **100% Aligned**: Constant-time ML-KEM shared secret. |
| **PQ OPK Secret ($ss_{pq\_opk}$)** | $\text{MLKEM.Encaps}(PQOPK_B)$ | $\text{MLKEM.Encaps}(PQOPK_B)$ | ✅ **100% Aligned**: Additional per-session PQ entropy. |
| **Hybrid IKM Combination** | $F \mathbin{\Vert} DH_1 \dots DH_4 \mathbin{\Vert} ss_{pq} [\mathbin{\Vert} ss_{pq\_opk}]$ | $DH_1 \dots DH_4 \mathbin{\Vert} ss_{pq} [\mathbin{\Vert} ss_{pq\_opk}]$ | ℹ️ Truples utilizes direct high-entropy hybrid concatenation. |
| **KDF & Domain Separation** | HKDF-SHA512 (`info="PQXDH"`) | HKDF-SHA256 (`info="Truples-Hybrid-PQ-InitialKey"`, `salt="Truples-PQXDH-v1-Salt"`) | ℹ️ **Domain Separation Label**: Truples specific domain separation tags. |
| **Initial Double Ratchet Feed** | Initializes $RK$ and chain keys | Initializes $RK$, $CK_s$, $CK_r$ directly | ✅ **100% Aligned**: Provides post-quantum hardened root key to Double Ratchet. |

---

## 3. Threat Model & Security Invariants

| Security Property | Defense Mechanism | Invariant Guaranteed |
| :--- | :--- | :--- |
| **Harvest-Now-Decrypt-Later** | Hybrid ML-KEM-768 + P-384 | Secrecy holds even if classical ECDH is completely broken |
| **MITM Attack on Prekeys** | FIPS 186-4 ECDSA Identity Signatures | Forged prekeys or signatures abort before key derivation |
| **Chosen-Ciphertext Attack (IND-CCA2)** | Fujisaki-Okamoto Transform with Implicit Rejection | Malformed / tampered ciphertexts produce divergent pseudorandom rejection keys |
| **Active Network Bit-Flips** | AES-256-GCM 128-bit MAC + Implicit Rejection | Tampered ciphertexts trigger zero state corruption |
| **Replay & Out-of-Order** | Bounded Replay Cache + Skipped Keys Buffer | Seamless recovery on permuted packet arrival |

---

## 4. Side-Channel & Timing Analysis Disclosure (JavaScript Runtime)

> [!WARNING]
> **JavaScript Timing Leakage Disclaimer**: 
> While our ML-KEM-768 implementation is designed with constant-time algorithmic flow (avoiding secret-dependent data branches in polynomial/NTT operations and employing bitwise selection for Fujisaki-Okamoto rejection), standard JavaScript engines (V8, SpiderMonkey, JavaScriptCore) perform JIT optimizations and dynamic memory allocations that may introduce micro-architectural timing variations. 
> For absolute side-channel resistance against physical hardware-level power/cache attacks, independent cryptographic audits and native/WebAssembly constant-time implementations (such as the independent Rust engine) are recommended.
