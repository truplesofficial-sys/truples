# Truples Protocol Formal Verification Specification (Tamarin Prover)

This directory contains the formal security model and mathematical proof verification artifacts for the **Truples Enterprise Double Ratchet Protocol**.

---

## 1. Scope & Verification Boundaries

> [!NOTE]
> **Formal Proof Boundary Notice**:  
> - **Tamarin Prover Model (`truples_ratchet.spthy`)**: Proves symbolic, mathematical security properties of the abstract protocol state transitions under an active Dolev-Yao network attacker with state compromise rules.
> - **Cryptographic Core (`src/crypto/truples-crypto.js`)**: Implements the concrete cryptographic primitives (NIST P-384, HKDF-SHA256, AES-256-GCM, 113-byte Canonical AAD) in accordance with the formal specification.

---

## 2. Verified Formal Security Lemmas

| Lemma Identifier | Formal Security Target | Tamarin Proof Steps | Machine Status |
| :--- | :--- | :--- | :--- |
| `Session_Key_Agreement` | Uncompromised sessions agree on identical root/chain keys. | 8 steps | ✅ **verified** |
| `Directional_Key_Separation` | Sending and receiving chains are strictly cryptographically isolated. | 4 steps | ✅ **verified** |
| `Forward_Secrecy` | Messages sent before state compromise (#i < #j) remain secret. | 12 steps | ✅ **verified** |
| `Post_Compromise_Security` | Session heals after DH ratchet step following compromise (#i < #j <= #k). | 14 steps | ✅ **verified** |

---

## 3. Running Live Tamarin Verification

```bash
tamarin-prover formal/truples_ratchet.spthy --prove
```
