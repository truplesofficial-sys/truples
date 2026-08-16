# Truples Protocol Formal Specification (PROTOCOL_SPEC)

## 1. Abstract & Cryptographic Foundations

This document establishes the **authoritative cryptographic specification** for the Truples End-to-End Encryption Protocol Suite.

Every cryptographic construction, state transition, and invariant defined in this document is bound to a unique **Specification Identifier (`SPEC-*`)** and mapped directly to:
1. **JavaScript WebCrypto Implementation** (`src/crypto/`)
2. **Independent Rust Conformance Engine** (`implementations/rust/src/`)
3. **Machine-Checked Tamarin Formal Model** (`formal/truples_ratchet.spthy`)
4. **Deterministic Cross-Language Test Vectors** (`vectors/deterministic_vectors.json`)
5. **Continuous Integration Test Suites** (`tests/`)

---

## 2. Mathematical State Representation

A Double Ratchet session state $S$ is defined as a discrete tuple:

$$S = \langle RK, CK_s, CK_r, DH_s, DH_r, N_s, N_r, PN, MKSKIPPED, MKSCONSUMED, \text{pendingTurn} \rangle$$

Where:
* $RK \in \{0, 1\}^{256}$: Current Root Key (HMAC-SHA256 PRK)
* $CK_s \in \{0, 1\}^{256}$: Sending Chain Key
* $CK_r \in \{0, 1\}^{256}$: Receiving Chain Key
* $DH_s = (sk_{DH}, pk_{DH})$: Local ephemeral NIST P-384 keypair ($sk \in \mathbb{F}_q, pk \in E(\mathbb{F}_p)$)
* $DH_r \in E(\mathbb{F}_p)$: Remote peer's ephemeral NIST P-384 public key (97-byte uncompressed point $0x04 \mathbin{\Vert} X \mathbin{\Vert} Y$)
* $N_s \in [0, 2^{32}-1]$: Monotonic sequence counter for outbound message chain
* $N_r \in [0, 2^{32}-1]$: Monotonic sequence counter for inbound message chain
* $PN \in [0, 2^{32}-1]$: Previous outbound sending chain length
* $MKSKIPPED: (\text{Fingerprint} \times \mathbb{N}) \to \{0, 1\}^{256}$: Bounded buffer of skipped message keys
* $MKSCONSUMED: (\text{Fingerprint} \times \mathbb{N}) \to \text{Timestamp}$: Bounded FIFO replay protection cache (max 5,000 entries)
* $\text{pendingTurn} \in \{\text{true}, \text{false}\}$: Deferred outbound asymmetric rotation trigger

---

## 3. Protocol Operations & Specification Mapping

### 3.1 Double Ratchet State Machine (`SPEC-DR-*`)

#### `SPEC-DR-001` [Ephemeral Asymmetric Key Generation]
* **Definition**: Generate ephemeral keypair over NIST P-384 curve ($pk = sk \cdot G$).
* **JS Function**: `TruplesCryptoCore.generateECDHKeypair()`
* **Rust Function**: `TruplesEngine::generate_ecdh_keypair()`
* **Tamarin Rule**: `rule Generate_Identity_Key`, `rule Handshake_Init`
* **Test File**: `tests/crypto.test.js:Test 1`

#### `SPEC-DR-002` [Directional Chain KDF Derivation]
* **Definition**: Given $PRK = \text{HMAC-SHA256}(\text{salt}, \text{secret})$:
  $$RK = \text{HKDF-Expand}(PRK, \text{"Truples-Root-Key"}, 32)$$
  $$CK_{\text{init}\to\text{resp}} = \text{HKDF-Expand}(PRK, \text{"Truples-Chain-Initiator-To-Responder"}, 32)$$
  $$CK_{\text{resp}\to\text{init}} = \text{HKDF-Expand}(PRK, \text{"Truples-Chain-Responder-To-Initiator"}, 32)$$
  $$\text{Invariant: } CK_{\text{init}\to\text{resp}} \neq CK_{\text{resp}\to\text{init}} \quad (\text{Directional Isolation})$$
* **JS Function**: `TruplesCryptoCore.deriveRootAndChainKeys()`
* **Rust Function**: `compute_directional_kdf()`
* **Tamarin Rule / Lemma**: `rule Handshake_Resp`, `lemma Directional_Key_Separation`
* **Vector ID**: `VEC-KDF-DIR-002`
* **Test File**: `tests/crypto.test.js:Test 3`

#### `SPEC-DR-003` [Symmetric Message Key Ratchet]
* **Definition**: Advances sending or receiving chain by one step:
  $$CK_{i+1} = \text{HKDF-Expand}(CK_i, \text{"Truples-Chain-Step"}, 32)$$
  $$MK_i = \text{HKDF-Expand}(CK_i, \text{"Truples-Message-Key"}, 32)$$
  $$\text{Action: Zeroize } CK_i \text{ from memory immediately after step (Strict FS).}$$
* **JS Function**: `TruplesCryptoCore.ratchetMessageKey()`
* **Tamarin Rule / Lemma**: `rule Send_Message`, `lemma Forward_Secrecy`
* **Test File**: `tests/crypto.test.js:Test 4`

#### `SPEC-DR-004` [Asymmetric Ephemeral DH Ratchet Step & 5-Stage Turn-Taking]
* **Definition**: Upon receipt of new $DH_r$:
  $$ss = \text{ECDH}(sk_{DH}, DH_r)$$
  $$RK_{\text{new}} = \text{HKDF-Expand}(\text{HKDF-Extract}(RK_{\text{old}}, ss), \text{"Truples-Root-Key"}, 32)$$
  $$CK_{\text{recv}} = \text{HKDF-Expand}(\text{HKDF-Extract}(RK_{\text{old}}, ss), \text{"Truples-Chain-Responder-To-Initiator"}, 32)$$
  $$\text{Action: set } \text{pendingTurn} = \text{true}. \text{ On subsequent send(), rotate } sk_{DH} \text{ and commit } RK_{\text{healed}}.$$
* **JS Function**: `TruplesCryptoCore.executeDhRatchetStep()`, `DoubleRatchetSession.rotateLocalDhKeypair()`
* **Tamarin Rule / Lemma**: `rule Bob_Turn_Ephemeral_Rotation`, `rule Alice_Fresh_Turn_PCS_Restore`, `lemma Post_Compromise_Security`, `lemma Future_Message_Secrecy_After_Healing`
* **Test File**: `tests/crypto.test.js:Test 8`, `tests/adversarial/compromise_recovery_negative.test.js`

#### `SPEC-DR-005` [113-Byte Canonical AAD Binary Header Encoding]
* **Definition**: Canonical binary format authenticated via AES-256-GCM AAD:
  $$\text{AAD} = [N_s]_{4B} \mathbin{\Vert} [PN]_{4B} \mathbin{\Vert} [DH_s]_{97B} \mathbin{\Vert} [\text{"TRUP"}]_{4B} \mathbin{\Vert} [\text{"LES1"}]_{4B}$$
* **JS Function**: `canonicalEncodeHeader()`
* **Rust Function**: `main(): Canonical AAD validator`
* **Vector ID**: `VEC-AAD-001`
* **Test File**: `tests/crypto.test.js:Test 14`

#### `SPEC-DR-006` [Bounded Replay Cache & Atomic Rollback Defense]
* **Definition**: Any decryption attempt with key ID present in $MKSCONSUMED$ aborts with `Replay Attack Detected`. On MAC error, state reverts to pre-transaction snapshot.
* **JS Method**: `DoubleRatchetSession.recordConsumedKey()`, `DoubleRatchetSession.receive()`
* **Test File**: `tests/crypto.test.js:Test 15`, `tests/adversarial/malicious_server.test.js`

#### `SPEC-DR-007` [Out-of-Order Skipped Message Keys Buffer]
* **Definition**: Derives skipped message keys $MK_{i} \dots MK_{k-1}$ into $MKSKIPPED$ when $N_{\text{inbound}} > N_r$, capped at $\text{maxSkip}=1,000$.
* **JS Method**: `DoubleRatchetSession.receive()`
* **Test File**: `tests/crypto.test.js:Test 10`, `tests/crypto.test.js:Test 19`

#### `SPEC-DR-008` [60-Digit Lexicographically Sorted Identity Pinning]
* **Definition**: Computes 60 decimal digits via 512 rounds of SHA-512 over sorted raw public identity keys:
  $$\text{SafetyNumber} = \text{Format}_{12 \times 5}(\text{SHA512}^{512}(\min(IK_A, IK_B) \mathbin{\Vert} \max(IK_A, IK_B)))$$
* **JS Function**: `TruplesCryptoCore.computeSafetyNumber()`
* **Rust Function**: `compute_safety_number()`
* **Vector ID**: `VEC-SAFETY-003`
* **Test File**: `tests/crypto.test.js:Test 25`

---

### 3.2 Hybrid Post-Quantum Key Agreement (`SPEC-PQ-*`)

#### `SPEC-PQ-001` [NIST FIPS 203 ML-KEM-768 Primitive Execution]
* **Definition**: ML-KEM-768 key generation, encapsulation ($ct \in \{0, 1\}^{1088}, ss \in \{0, 1\}^{32}$), and decapsulation with constant-time Fujisaki-Okamoto implicit rejection.
* **JS Engine**: `TruplesPQKEM` (`src/crypto/truples-pqkem.js`)
* **Test File**: `tests/pqxdh/pqxdh_handshake.test.js:Test 1`

#### `SPEC-PQ-002` [Hybrid Multi-Secret Aggregation & Master Derivation]
* **Definition**: Combines classical DHs and post-quantum KEM secrets:
  $$\text{IKM} = DH_1 \mathbin{\Vert} DH_2 \mathbin{\Vert} DH_3 [\mathbin{\Vert} DH_4] \mathbin{\Vert} ss_{pq} [\mathbin{\Vert} ss_{pq\_opk}]$$
  $$\text{MasterSecret} = \text{HKDF}(\text{IKM}, \text{salt}=\text{"Truples-PQXDH-v1-Salt"}, \text{info}=\text{"Truples-Hybrid-PQ-InitialKey"})$$
* **JS Class**: `TruplesPQXDH.initiateHandshake()`, `TruplesPQXDH.respondHandshake()`
* **Test File**: `tests/pqxdh/pqxdh_handshake.test.js:Test 2, Test 3`

---

### 3.3 Multi-Device Session Management (`SPEC-SESAME-*`)

#### `SPEC-SESAME-001` [3-Tier Identity & Pairwise Isolation]
* **Definition**: User $\to$ Device $\to$ Session hierarchy. Key material strictly unique per device installation.
* **JS Class**: `SesameEngine`, `DeviceRecord` (`src/crypto/truples-sesame.js`)
* **Test File**: `tests/sesame/multi_device_sesame.test.js:Test 1`

#### `SPEC-SESAME-002` [Multi-Device Fan-Out Encryption & Sibling Self-Sync]
* **Definition**: Fans out individual ciphertexts to all active target devices and sibling self-devices for seamless multi-endpoint synchronization.
* **JS Method**: `SesameEngine.encryptMultiDeviceMessage()`
* **Test File**: `tests/sesame/multi_device_sesame.test.js:Test 2`

#### `SPEC-SESAME-003` [Device Revocation & Compromise Blast-Radius Isolation]
* **Definition**: Marking device `REVOKED` permanently terminates outbound routing and rejects inbound traffic. Compromise of device $D_1$ yields 0 lateral access to sibling device $D_2$.
* **JS Method**: `SesameEngine.revokePeerDevice()`, `SesameEngine.revokeSelfDevice()`
* **Test File**: `tests/sesame/multi_device_sesame.test.js:Test 4, Test 5`

---

## 4. Formal Security Claims Matrix

| Security Property | Spec Tag | Formal Model (Tamarin, Bounded Depth = 2) | JavaScript Engine | Rust Engine | CI Automated Test |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Strict Forward Secrecy** | `SPEC-DR-003` | `lemma Forward_Secrecy` | `ratchetMessageKey` | Verified | `tests/crypto.test.js` |
| **Post-Compromise Security** | `SPEC-DR-004` | `lemma Post_Compromise_Security` | `executeDhRatchetStep` | Verified | `tests/adversarial/server_compromise_e2e.test.js` |
| **Directional Separation** | `SPEC-DR-002` | `lemma Directional_Key_Separation` | `deriveRootAndChainKeys` | `compute_directional_kdf` | `tests/crypto.test.js` |
| **Header Authenticity (AAD)** | `SPEC-DR-005` | `rule Send_Message` (`MsgSent_AAD`) | `canonicalEncodeHeader` | Verified | `tests/adversarial/malicious_server.test.js` |
| **Replay Protection** | `SPEC-DR-006` | Mathematical Nonce Uniqueness | `recordConsumedKey` | Verified | `tests/crypto.test.js` |
| **Post-Quantum Forward Secrecy**| `SPEC-PQ-002` | Dual-Hybrid Proof Boundary | `TruplesPQXDH` | Cross-Vector | `tests/pqxdh/pqxdh_handshake.test.js` |
| **Multi-Device Isolation** | `SPEC-SESAME-001` | Pairwise State Partitioning | `SesameEngine` | Cross-Vector | `tests/sesame/multi_device_sesame.test.js` |
| **Anti-Rollback State Commit** | `SPEC-DR-006` | Monotonic Counter Invariant | `restoreFromEncryptedSnapshot`| Verified | `tests/crash/concurrent_snapshot.test.js` |
