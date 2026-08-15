# Truples Protocol & Architecture Specification

[![Status: Production Live](https://img.shields.io/badge/Status-Production%20Live-emerald.svg)](https://truples.com)
[![Crypto Tests: 6/6 Passing](https://img.shields.io/badge/Crypto%20Tests-6%2F6%20Passing-brightgreen.svg)](tests/crypto.test.js)
[![Cipher: AES--256--GCM](https://img.shields.io/badge/Cipher-AES--256--GCM%20(NIST%20SP%20800--38D)-blue.svg)](https://truples.com)
[![Key Exchange: ECDH P--384](https://img.shields.io/badge/Key%20Exchange-ECDH%20P--384%20(RFC%205903)-purple.svg)](https://truples.com)
[![Forward Secrecy: KDF Chain Ratchet](https://img.shields.io/badge/Forward%20Secrecy-KDF%20Chain%20Ratchet%20(RFC%205869)-teal.svg)](src/crypto/truples-crypto.js)
[![Media: WebRTC DTLS/SRTP](https://img.shields.io/badge/Media-WebRTC%20DTLS%2FSRTP%20(RFC%203711)-orange.svg)](https://truples.com)
[![License: Proprietary Specification](https://img.shields.io/badge/License-Proprietary%20Spec-gray.svg)](LICENSE.md)

---

## 1. Executive Summary

**Truples** is an enterprise-grade, end-to-end encrypted (E2EE) communication platform architected around **client-side symmetric KDF chain ratcheting**, an **ephemeral in-memory relay model (Zero-Retention)**, and **decentralized Peer-to-Peer (P2P) WebRTC media channels**.

This repository contains the complete technical specifications, cryptographic primitives, and a runnable reference implementation of the cryptographic core engine.

- 🌐 **Live Web Application**: [https://truples.com](https://truples.com)
- 🧪 **Reference Cryptographic Module**: [`src/crypto/truples-crypto.js`](src/crypto/truples-crypto.js)
- 📜 **Version History**: [CHANGELOG.md](CHANGELOG.md)

---

## 2. Cryptographic Architecture & Primitives

Truples implements strict zero-knowledge, client-side encryption. Plaintext messages, media attachments, and private keys never leave local device boundaries without cryptographic encapsulation.

```
┌─────────────────────────────────────────────────────────────┐
│                    Client-Side Core (A)                     │
│  ┌──────────────────────┐      ┌─────────────────────────┐  │
│  │ Device Secure Store  │ ───► │ WebCrypto Engine (v2.1) │  │
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
- **Asymmetric Key Exchange**: `ECDH` over NIST P-384 / SECP384R1 (RFC 5903) and `RSA-OAEP-4096` (RFC 8017).
- **Key Derivation Function**: `HKDF` with `HMAC-SHA256` (RFC 5869) enforcing dynamic 32-byte CSPRNG salt.
- **Forward Secrecy**: Client-Side Symmetric KDF Chain Ratchet advancing per-message.
- **Random Number Generation**: Cryptographically Secure Pseudorandom Number Generator (CSPRNG) via WebCrypto `crypto.getRandomValues()`.

---

## 3. Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)

To guarantee strict Forward Secrecy at the client layer, Truples utilizes a symmetric KDF Chain Ratchet:

```
                      [ Initial Shared Secret (ECDH P-384) ]
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

## 5. Multi-Tier Panic Defense Matrix & Anti-Forensics

The Truples Panic Defense Matrix provides mathematically irreversible hardware and cryptographic safeguards in physical coercion or device seizure scenarios:

```
[ PIN Input Challenge ]
          │
          ├──► "pw1" (Level 1) ──► Renders Functional Decoy Environment
          │
          ├──► "pw2" (Level 2) ──► Wipes WebCrypto Master Keys & Unlinks Local DB
          │
          └──► "pw3" (Level 3) ──► Full Memory Zeroization & Active Session Revocation
```

1. **🚨 Level 1 (Duress Decoy State)**: Unlocks a benign decoy partition containing synthetic benign data.
2. **🚨 Level 2 (Ephemeral Wipe)**: Instantly erases local WebCrypto master encryption keys and unlinks conversation stores from SQLite / IndexedDB.
3. **🚨 Level 3 (Hardware Zeroization)**: Executes low-level memory zeroization and revokes active server session tokens.
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
- ✅ `HKDF-SHA256` symmetric root and initial chain key derivation with dynamic 32-byte CSPRNG salt
- ✅ **Symmetric KDF Chain Ratchet** ensuring distinct message keys per transmission and verifying forward secrecy
- ✅ `AES-256-GCM` 256-bit encryption & 128-bit MAC validation
- ✅ Per-message 96-bit CSPRNG IV freshness (No nonce reuse)
- ✅ 128-bit authentication tag tamper resistance
- ✅ Multi-pass memory buffer zeroization

---

## 7. Security Properties & Claim Boundaries

| Security Property | Implementation & Verification Status |
| :--- | :--- |
| **Client-Side E2EE** | ✅ **Implemented & Verifiable**: All messages are sealed via `AES-256-GCM` within client sandboxes prior to network transport. |
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
| **Persistence Layer** | PostgreSQL (`NUMERIC(20,2)` schema) | High-precision audit and ledger accounting |
| **Real-Time Media** | WebRTC (DTLS 1.2/1.3, SRTP), Coturn STUN/TURN | Direct peer-to-peer audio/video streaming |

---

## 9. Security Contact & Independent Audit Roadmap

- 📋 **Third-Party Audit Roadmap**: A formal third-party source code and infrastructure audit is scheduled as part of our production release milestones.
- ✉️ **Security Contact & Vulnerability Reports**: `security@truples.com`

---

Copyright (c) 2025 Truples Systems. All rights reserved.
