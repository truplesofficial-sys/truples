# Truples Enterprise Double Ratchet Protocol Specification

## 1. Abstract & Scope

This document specifies the **Truples Enterprise Double Ratchet Protocol**, a client-side cryptographic state machine providing **End-to-End Encryption (E2EE)**, **Strict Forward Secrecy (FS)**, **Post-Compromise Security (PCS)**, and **Header-Authenticated Cryptographic Binding**.

The protocol operates directly over standard cryptographic primitives via the W3C WebCrypto API and requires zero external cryptographic dependencies.

---

## 2. Cryptographic Primitives

| Primitive Role | Standard / Construction | Key Size / Parameter |
| :--- | :--- | :--- |
| **Post-Quantum KEM** | NIST FIPS 203 ML-KEM-768 (Kyber-768) | Category 3 (AES-192 equivalent quantum-security) |
| **Asymmetric Curve** | NIST P-384 (RFC 5903) | 384-bit Elliptic Curve |
| **Authenticated Key Exchange** | ECDSA over P-384 / SHA-384 (FIPS 186-4) | 384-bit Signature Verification |
| **Key Derivation Function** | HKDF with HMAC-SHA256 (RFC 5869) | 256-bit Output Digest |
| **Symmetric Cipher** | AES-256-GCM (NIST SP 800-38D) | 256-bit Key, 96-bit IV, 128-bit MAC Tag |
| **Public Key Fingerprinting** | Full SHA-256 Digest | 256-bit Canonical Identifier |

---

## 3. Protocol State Representation

A Double Ratchet session maintains the following discrete cryptographic state variables:

```text
SessionState = {
  RK:                  CryptoKey,     // Current Root Key (256-bit HMAC)
  CKs:                 CryptoKey,     // Sending Chain Key (256-bit HMAC)
  CKr:                 CryptoKey,     // Receiving Chain Key (256-bit HMAC)
  DHs:                 CryptoKeyPair, // Local Ephemeral DH Keypair (P-384)
  DHr:                 CryptoKey,     // Remote Ephemeral DH Public Key (P-384)
  Ns:                  uint32,        // Number of messages sent in current sending chain
  Nr:                  uint32,        // Number of messages received in current receiving chain
  PN:                  uint32,        // Length of previous sending chain
  MKSKIPPED:           Map<String, CryptoKey>, // Skipped message keys buffer [Fingerprint:Seq]
  MKSCONSUMED:         Map<String, Timestamp>, // Bounded Replay Cache (FIFO Eviction)
  dhRatchetTurnPending: Boolean      // Deferred local DH rotation trigger
}
```

---

## 4. State Transitions & Algorithms

### 4.0 Signal Hybrid Post-Quantum Key Agreement (PQXDH)

To defend against *Harvest-Now-Decrypt-Later* quantum adversaries, sessions are initiated via **Hybrid PQXDH**:

1. **Prekey Bundle Publication (Bob)**:
   - `IK_B`: Identity Key (P-384 ECDSA)
   - `SPK_B`: Signed Prekey (P-384 ECDH) + `Sig_IK(SPK_B)`
   - `PQSPK_B`: Post-Quantum Signed Prekey (ML-KEM-768) + `Sig_IK(PQSPK_B)`
   - Optional `OPK_B` (P-384 ECDH) and `PQOPK_B` (ML-KEM-768)

2. **Hybrid Key Encapsulation (Alice)**:
   - $DH_1 = \text{ECDH}(IK_A, SPK_B)$ (Mutual Identity Authentication)
   - $DH_2 = \text{ECDH}(EK_A, IK_B)$ (Ephemeral Forward Secrecy)
   - $DH_3 = \text{ECDH}(EK_A, SPK_B)$ (Ephemeral Forward Secrecy)
   - $DH_4 = \text{ECDH}(EK_A, OPK_B)$ (One-Time Prekey Protection, if present)
   - $(ct_{pq}, ss_{pq}) = \text{MLKEM.Encaps}(PQSPK_B)$ (Post-Quantum Security)
   - $(ct_{pq\_opk}, ss_{pq\_opk}) = \text{MLKEM.Encaps}(PQOPK_B)$ (if present)

3. **Master Secret & Root Key Derivation**:
   ```text
   IKM = DH1 || DH2 || DH3 [|| DH4] || ss_pq [|| ss_pq_opk]
   MasterSecret = HKDF(IKM = IKM, Salt = "Truples-PQXDH-v1-Salt", info = "Truples-Hybrid-PQ-InitialKey")
   RootKey = HKDF-Expand(MasterSecret, info = "Truples-Root-Key")
   SendingChainKey = HKDF-Expand(MasterSecret, info = "Truples-Chain-Initiator-To-Responder")
   ReceivingChainKey = HKDF-Expand(MasterSecret, info = "Truples-Chain-Responder-To-Initiator")
   ```

### 4.1 Canonical Header Serialization (AAD)

Every transmission encapsulates an unencrypted header cryptographically bound to the ciphertext via AES-GCM Additional Authenticated Data (AAD):

```text
CanonicalHeaderBytes = 
  [4-byte Version (0x00000001)] ||
  [4-byte PublicKeyLength (0x00000061)] ||
  [97-byte Uncompressed P-384 Point (0x04 || X || Y)] ||
  [4-byte PreviousChainLength (uint32)] ||
  [4-byte MessageNumber (uint32)]
```

### 4.2 Symmetric Ratchet Step (Message Key Derivation)

```text
Input: ChainKey
Output: (NextChainKey, MessageKey)

HKDF-Expand(PRK = ChainKey, info = "Truples-Chain-Step", length = 32) -> NextChainKey
HKDF-Expand(PRK = ChainKey, info = "Truples-Message-Key", length = 32) -> MessageKey
```

### 4.3 Asymmetric DH Ratchet Step (Turn-Taking)

When an inbound message contains a new `DHr`, the session executes an asymmetric ratchet step:

```text
1. SharedSecret = ECDH(LocalPrivateDH, RemotePublicDH)
2. NewRootKey = HKDF(IKM = SharedSecret, Salt = OldRootKey, info = "Truples-DH-Ratchet-Root-Step")
3. If Role == Initiator:
     NewSendingChainKey   = HKDF(IKM = SharedSecret, Salt = OldRootKey, info = "Truples-DH-Ratchet-Init-To-Resp")
     NewReceivingChainKey = HKDF(IKM = SharedSecret, Salt = OldRootKey, info = "Truples-DH-Ratchet-Resp-To-Init")
   Else:
     NewSendingChainKey   = HKDF(IKM = SharedSecret, Salt = OldRootKey, info = "Truples-DH-Ratchet-Resp-To-Init")
     NewReceivingChainKey = HKDF(IKM = SharedSecret, Salt = OldRootKey, info = "Truples-DH-Ratchet-Init-To-Resp")
```

### 4.4 Encrypted Session Snapshot & Anti-Rollback Storage

To guarantee persistence across application lifecycle transitions without exposing plaintext key material:

```text
EncryptedSnapshot = AES-256-GCM(
  Key = DeviceMasterKey,
  IV = 96-bit CSPRNG Nonce,
  Plaintext = JSON.stringify(SessionStateRaw),
  AAD = 64-bit Monotonic Version Counter
)
```

Restoration aborts with immediate error if `Snapshot.Version < MinimumExpectedVersion` (Anti-Rollback defense).

### 4.5 Verifiable 60-Digit Safety Number (Identity Pinning)

```text
1. Sort(IdentityKeyA.Raw, IdentityKeyB.Raw) -> (KeyFirst, KeySecond)
2. Digest = SHA-512^512(KeyFirst || KeySecond)
3. Derive 12 blocks of 5 decimal digits from 30 bytes of digest material
4. Format: "XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX"
```

---

## 5. Formal Security Invariants

1. **Strict Forward Secrecy (FS)**: Once a `MessageKey` is derived, the prior `ChainKey` is immediately zeroized in memory. Historical ciphertexts cannot be decrypted from compromised future chain keys.
2. **Post-Compromise Security (PCS)**: An adversary in full possession of past `(RK, CKs, CKr, DHs.private)` is permanently locked out once the compromised party executes their subsequent outbound DH turn-taking step.
3. **Key Independence**: For any two distinct sequence indices `i != j`, deriving `MessageKey_i` provides zero information regarding `MessageKey_j`.
4. **Header Authenticity**: Altering any bit of `dhPublicKey`, `previousChainLength`, or `messageNumber` causes immediate AES-GCM MAC validation rejection.
5. **Transactional Atomic Rollback**: Any failure in AAD verification or MAC tag validation instantly triggers state restoration to the pre-transaction snapshot, preventing state corruption and DoS attacks.
6. **Bounded Replay Rejection**: Message keys are strictly single-use; retransmitted ciphertexts are rejected via bounded key fingerprint tracking.
7. **Anti-Rollback State Preservation**: Stored session state snapshots cannot be replayed from historical versions or restored with invalid device master keys.
8. **Deterministic Identity Fingerprinting**: Safety numbers are strictly invariant under peer evaluation order (`SafetyNumber(A, B) == SafetyNumber(B, A)`).
