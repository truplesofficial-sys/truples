# Truples Protocol & Architecture Specification

[![Status: Production Live](https://img.shields.io/badge/Status-Production%20Live-emerald.svg)](https://truples.com)
[![Crypto Tests: 7/7 Passing](https://img.shields.io/badge/Crypto%20Tests-7%2F7%20Passing-brightgreen.svg)](tests/crypto.test.js)
[![Cipher: AES--256--GCM](https://img.shields.io/badge/Cipher-AES--256--GCM%20(NIST%20SP%20800--38D)-blue.svg)](https://truples.com)
[![Auth Key Exchange: ECDH + ECDSA](https://img.shields.io/badge/Key%20Exchange-ECDH%20%2B%20ECDSA%20(P--384)-indigo.svg)](src/crypto/truples-crypto.js)
[![Forward Secrecy: KDF Chain Ratchet](https://img.shields.io/badge/Forward%20Secrecy-KDF%20Chain%20Ratchet%20(RFC%205869)-teal.svg)](src/crypto/truples-crypto.js)
[![Media: WebRTC DTLS/SRTP](https://img.shields.io/badge/Media-WebRTC%20DTLS%2FSRTP%20(RFC%203711)-orange.svg)](https://truples.com)
[![License: Proprietary Specification](https://img.shields.io/badge/License-Proprietary%20Spec-gray.svg)](LICENSE.md)

---

## 1. Executive Summary

**Truples** is an enterprise-grade, end-to-end encrypted (E2EE) communication platform architected around **client-side symmetric KDF chain ratcheting**, **MITM-resistant Authenticated Key Exchange (ECDH + ECDSA)**, an **ephemeral in-memory relay model (Zero-Retention)**, and **decentralized Peer-to-Peer (P2P) WebRTC media channels**.

This repository contains the complete technical specifications, cryptographic primitives, and a runnable reference implementation of the cryptographic core engine.

- 🌐 **Live Web Application**: [https://truples.com](https://truples.com)
- 🧪 **Reference Cryptographic Module**: [`src/crypto/truples-crypto.js`](src/crypto/truples-crypto.js)

---

## 2. Cryptographic Architecture & Primitives

Truples implements strict zero-knowledge, client-side encryption. Plaintext messages, media attachments, and private keys never leave local device boundaries without cryptographic encapsulation.

```
┌─────────────────────────────────────────────────────────────┐
│                    Client-Side Core (A)                     │
│  ┌──────────────────────┐      ┌─────────────────────────┐  │
│  │ Device Secure Store  │ ───► │ WebCrypto Engine (v2.3) │  │
│  └──────────────────────┘      └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                               │
               [ AES-256-GCM Encrypted Payload Stream ]
                               │
                               ▼
               ┌───────────────────────────────┐
               │  Zero-Knowledge Relay Server  │
               └───────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Client-Side Core (B)                     │
│  ┌──────────────────────┐      ┌─────────────────────────┐  │
│  │ Device Secure Store  │ ◄─── │ Decryption & MAC Verify │  │
│  └──────────────────────┘      └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Cryptographic Standards Inventory:
- **Symmetric Cipher**: `AES-256-GCM` (NIST SP 800-38D) with 96-bit CSPRNG IV & 128-bit MAC tag.
- **Authenticated Key Exchange (MITM Defense)**: `ECDH over NIST P-384` (RFC 5903) wired directly with `ECDSA P-384 / SHA-384` identity signatures (FIPS 186-4).
- **Key Derivation Function**: `HKDF` with `HMAC-SHA256` (RFC 5869) enforcing dynamic 32-byte CSPRNG salt.
- **Forward Secrecy**: Client-Side Symmetric KDF Chain Ratchet advancing per-message.
- **Runtime Compatibility**: Universal W3C WebCrypto API with zero Node `Buffer` dependencies (Native Vite & Browser compatible).

---

## 3. Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)

To guarantee strict Forward Secrecy at the client layer, Truples utilizes a symmetric KDF Chain Ratchet:

```
                  [ Authenticated Shared Secret (ECDH + ECDSA) ]
                                        │
                         HKDF-SHA256 (Dynamic CSPRNG Salt)
                                        │
                      ┌─────────────────┴─────────────────┐
                      ▼                                   ▼
                 [ Root Key ]                       [ Chain Key 0 ]
                                                          │
                                                    HKDF-SHA256
                                                    ┌─────┴─────┐
                                                    ▼           ▼
                                            [ Chain Key 1 ] [ Message Key 0 ] ──► Encrypts Message 0
                                                    │
                                              HKDF-SHA256
                                              ┌─────┴─────┐
                                              ▼           ▼
                                      [ Chain Key 2 ] [ Message Key 1 ] ──► Encrypts Message 1
```

### Security Properties:
1. **Per-Message Key Freshness**: Each message uses a distinct, single-use `MessageKey`.
2. **Strict Forward Secrecy**: Once a message key is derived, the previous chain state is zeroized. An adversary compromising a current key state cannot calculate past message keys.
3. **Random Salt Enclave**: Root and initial chain key derivations enforce 32-byte dynamic CSPRNG salt parameters.

### 3.1 Security Invariants (Formal Verification Guarantees):
- 🛡️ **Invariant 1 (Single-Use Message Keys)**: A `MessageKey` is strictly single-use and destroyed immediately after encryption/decryption.
- 🛡️ **Invariant 2 (Root Key Invalidation on DH Turn)**: A successful bidirectional DH Ratchet step permanently invalidates the previous `RootKey`.
- 🛡️ **Invariant 3 (Skipped Keys Boundary)**: Skipped message keys are strictly bounded, isolated in an ephemeral dictionary, and purged after expiry.
- 🛡️ **Invariant 4 (CSPRNG Nonce Isolation)**: An AES-GCM 96-bit IV is cryptographically unique and never reused under the same key.
- 🛡️ **Invariant 5 (Post-Compromise Security / Self-Healing)**: An adversary who compromises historical session keys cannot derive future messages once a new DH Ratchet turn occurs.
- 🛡️ **Invariant 6 (Zero Client-Side Identity Leakage)**: Ephemeral ECDH exchange payload contains zero persistent device or phone identity linkage.

---

## 4. WebRTC P2P Media Mesh (Voice & Video)

Truples utilizes a direct **Peer-to-Peer (P2P) WebRTC Mesh** topology for 1:1 and multi-party group communication, bypassing centralized Media Control Units (MCU) or Selective Forwarding Units (SFU).

```
       [ Client A ] <================ DTLS/SRTP ================> [ Client B ]
            ^                                                           ^
            |                                                           |
            +================= DTLS/SRTP ===============================+
                                   |
                                   v
                              [ Client C ]
```

### Media Protocol Specifications:
- **Signaling Layer**: WebSocket over TLS 1.3 (WSS) utilizing STOMP framing for SDP Offer/Answer exchanges and ICE candidate gathering.
- **Media Stream Encryption**: `DTLS 1.2 / 1.3` (RFC 6347) handshake with `SRTP` (RFC 3711) audio/video encryption.
- **Telephony Integration**: Android `ConnectionService` (Telecom Framework) and iOS `CallKit` for native OS call handling.

---

## 5. Multi-Tier Panic Defense Matrix

The Truples Panic Defense Matrix provides hardware and cryptographic safeguards in physical coercion scenarios:

```
[ PIN Input Challenge ]
          │
          ├──► "pw1" (Level 1) ──► Renders Functional Decoy Environment
          │
          ├──► "pw2" (Level 2) ──► Wipes WebCrypto Master Keys & Unlinks Local DB
          │
          └──► "pw3" (Level 3) ──► Low-Level Memory Scrubbing & Active Session Revocation
```

1. **🚨 Level 1 (Duress Decoy State)**: Unlocks a benign decoy partition containing synthetic benign data.
2. **🚨 Level 2 (Ephemeral Wipe)**: Instantly erases local WebCrypto master encryption keys and unlinks conversation stores from SQLite / IndexedDB.
3. **🚨 Level 3 (Hardware Zeroization)**: Executes memory buffer scrubbing and revokes active server session tokens.
4. **Side-Channel Mitigation**: Credential verification employs constant-time comparison primitives (`MessageDigest.isEqual`) to eliminate timing side-channel exploits.

---

## 6. Verification & Automated Test Suite

Evaluators and security researchers can independently execute the reference cryptographic test suite locally:

```bash
# Clone the repository
git clone https://github.com/truplesofficial-sys/truples.git
cd truples

# Run automated cryptographic validation suite
npm test
```

### Validated Test Vectors (`tests/crypto.test.js`):
- ✅ `ECDH P-384` ephemeral keypair generation (RFC 5903)
- ✅ `ECDSA P-384 / SHA-384` identity signing & anti-tamper verification (FIPS 186-4)
- ✅ **MITM-Resistant Authenticated Key Exchange** verifying ECDSA signature on remote ECDH public key
- ✅ **Symmetric KDF Chain Ratchet** ensuring distinct message keys per transmission and verifying forward secrecy
- ✅ `AES-256-GCM` 256-bit encryption & 128-bit MAC validation
- ✅ Per-message 96-bit CSPRNG IV freshness (No nonce reuse)
- ✅ Multi-pass typed array memory buffer scrubbing

---

## 7. Security Properties & Claim Boundaries

| Security Property | Implementation & Verification Status |
| :--- | :--- |
| **Client-Side E2EE** | ✅ **Implemented & Verifiable**: All messages are sealed via `AES-256-GCM` within client sandboxes prior to network transport. |
| **Authenticated Key Exchange**| ✅ **Implemented & Verifiable**: `deriveAuthenticatedRootAndChainKeys()` enforces `ECDSA` identity signature validation against MITM spoofing. |
| **Forward Secrecy** | ✅ **Implemented & Verifiable**: Each message advances a symmetric `HKDF-SHA256` chain ratchet, generating single-use message keys. |
| **Media Encryption** | ✅ **Implemented & Verifiable**: Real-time voice/video channels establish direct P2P `DTLS 1.3 / SRTP` connections. |
| **Zero-Retention Relay** | 📋 **Architectural Policy**: In-memory transit queues (Redis) purge ciphertexts upon recipient acknowledgment (`ACK`). Third-party white-box audit planned for formal certification. |

---

## 8. Technology Stack & Implementation Standards

| Component | Technologies & Standards | Technical Function |
| :--- | :--- | :--- |
| **Web Client** | React 18, Vite, WebCrypto API, Zustand | UI state management, hardware-accelerated client encryption |
| **Native Mobile** | Android (Java/Kotlin), iOS (Swift/Obj-C), Capacitor | OS Keystore/Keychain, Telecom `ConnectionService`, `CallKit` |
| **Relay Backend** | Java 17+, Spring Boot, Spring Security | Zero-knowledge WSS routing, session version validation |
| **Signaling Protocol** | WebSocket (WSS) over TLS 1.3, STOMP framing | Low-latency bi-directional messaging and ICE signaling |
| **Transient Buffer** | Redis (In-Memory volatile store) | Ephemeral transit buffer with strict Time-To-Live (TTL) |
| **Persistence Layer** | PostgreSQL (Relational Store) | Session versioning, device key binding, and audit telemetry |
| **Real-Time Media** | WebRTC (DTLS 1.2/1.3, SRTP), Coturn STUN/TURN | Direct P2P audio/video streaming (Optimized for 1:1 and small groups) |

---

## 9. Security Contact & Independent Audit Roadmap

- 📋 **Third-Party Audit Roadmap**: A formal third-party source code and infrastructure audit is scheduled as part of our production release milestones.
- ✉️ **Security Contact & Vulnerability Reports**: `security@truples.com`

---

Copyright (c) 2025 Truples Systems. All rights reserved.
