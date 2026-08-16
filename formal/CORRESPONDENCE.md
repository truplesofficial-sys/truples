# Truples Formal Model & Implementation 1:1 Correspondence Specification

This document defines the strict, bidirectional mathematical mapping between the **Tamarin Prover Symbolic Model (`formal/truples_ratchet.spthy`)** and the **Concrete WebCrypto Implementation (`src/crypto/truples-crypto.js`)**.

---

## 1. Cryptographic Primitive Mapping Table

| Protocol State / Operation | Concrete WebCrypto Core (`src/crypto/truples-crypto.js`) | Symbolic Tamarin Model (`formal/truples_ratchet.spthy`) | Algebraic Formal Property |
| :--- | :--- | :--- | :--- |
| **Identity Key Agreement** | NIST P-384 ECDSA Keypair | `pk(~ltkA)`, `sign(~ltkA, ...)` | Unforgeable Identity Binding |
| **Ephemeral Key Exchange** | NIST P-384 ECDH Keypair | `pk(~ekA)`, `dh_mult(ekA, ekB)` | Diffie-Hellman Group Agreement |
| **KDF Extract Step** | `crypto.subtle.importKey('raw', prk, 'HKDF')` | `h(<salt, dh_mult(priv, pub)>)` | Pseudorandom Extraction |
| **KDF Directional Expand** | `HKDF-Expand(PRK, "truples-root-v1", 32)` | `hkdf_root(RK, S)` | Root Key Ratchet Invariant |
| **Sending Chain Derivation** | `HKDF-Expand(PRK, "truples-init-to-resp-v1", 32)` | `hkdf_init(RK, S)` | Cryptographic Directional Isolation |
| **Receiving Chain Derivation**| `HKDF-Expand(PRK, "truples-resp-to-init-v1", 32)` | `hkdf_resp(RK, S)` | Cryptographic Directional Isolation |
| **Message Sequence Numbers**| `session.messageNumber` ($N_s$), `session.recvMessageNumber` ($N_r$) | `Ns`, `Nr` | Monotonic Sequence Counter |
| **Previous Chain Length** | `session.previousChainLength` ($PN$) | `PN` | Epoch Transition Length Tracker |
| **Skipped Keys Buffer** | `session.skippedMessageKeys` (`Map<string, string>`) | `MKSKIPPED` | Bounded In-Flight Key Buffering |
| **Consumed Keys Cache** | `session.consumedKeys` (`Set<string>`) | `MKCONSUMED` | Replay Invariant Prevention |
| **Header AAD Binding** | 113-Byte Canonical Binary AAD Buffer | `aad_canonical(<v, len, dhPub, pn, n>)` | Unforgeable Metadata Authentication |
| **Payload Encryption** | AES-256-GCM (256-bit Key, 96-bit IV, 128-bit MAC) | `senc(plaintext, mk)` | IND-CCA2 Authenticated Encryption |

---

## 2. State Transition Invariant Equivalence

1. **Forward Secrecy (FS)**:
   - *JavaScript*: Message key `MK` is immediately scrubbed and unrecoverable from subsequent chain key `CK_{i+1}` via one-way HMAC-SHA256.
   - *Tamarin Lemma*: `MessageSent(A, B, m, key) @ #i & StateCompromised(A) @ #j & #i < #j ==> not (K(m))`
2. **Post-Compromise Security (PCS)**:
   - *JavaScript*: Upon next outbound message after state compromise, an ephemeral P-384 DH key rotation generates fresh uncompromised entropy.
   - *Tamarin Lemma*: `StateCompromised(A) @ #i & DHRatchetStep(A, B, freshDH) @ #j & PCSHealed(A, B, m, key) @ #k & #i < #j & #j <= #k ==> not (K(m))`
