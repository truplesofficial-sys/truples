# Truples Protocol & Architecture Specification

[![Status: Production Live](https://img.shields.io/badge/Status-Production%20Live-emerald.svg)](https://truples.com)
[![Crypto Tests: 6/6 Passing](https://img.shields.io/badge/Crypto%20Tests-6%2F6%20Passing-brightgreen.svg)](tests/crypto.test.js)
[![Cipher: AES--256--GCM](https://img.shields.io/badge/Cipher-AES--256--GCM%20(NIST%20SP%20800--38D)-blue.svg)](https://truples.com)
[![Key Exchange: ECDH P--384](https://img.shields.io/badge/Key%20Exchange-ECDH%20P--384%20(RFC%205903)-purple.svg)](https://truples.com)
[![Forward Secrecy: KDF Chain Ratchet](https://img.shields.io/badge/Forward%20Secrecy-KDF%20Chain%20Ratchet%20(RFC%205869)-teal.svg)](src/crypto/truples-crypto.js)
[![License: Proprietary Specification](https://img.shields.io/badge/License-Proprietary%20Spec-gray.svg)](LICENSE.md)

---

## 1. Overview

**Truples** is an end-to-end encrypted (E2EE) communication platform designed around **client-side symmetric KDF chain ratcheting**, an **ephemeral in-memory relay model**, and **peer-to-peer (P2P) WebRTC media channels**.

This repository contains the **official protocol specifications**, **architecture documentation**, and a **runnable reference implementation of the client-side cryptographic core**.

- 🌐 **Live Web Application**: [https://truples.com](https://truples.com)
- 🧪 **Reference Cryptographic Module**: [`src/crypto/truples-crypto.js`](src/crypto/truples-crypto.js)
- 📜 **Version History**: [CHANGELOG.md](CHANGELOG.md)
- 📚 **Technical Whitepapers**:
  - [01. Cryptographic Primitives & Key Agreement](docs/01_cryptographic_specification.md)
  - [02. WebRTC P2P Media Mesh Architecture](docs/02_webrtc_media_mesh.md)
  - [03. Hardware Panic & Anti-Forensics Matrix](docs/03_panic_security_matrix.md)
  - [04. Security Architecture & Evaluation FAQ](docs/04_security_audit_faq.md)

---

## 2. Verification & Automated Test Suite

We believe cryptographic claims should be backed by executable, verifiable code. Evaluators can independently inspect and execute our reference cryptographic suite locally:

```bash
# Clone the repository
git clone https://github.com/truplesofficial-sys/truples.git
cd truples

# Run automated cryptographic validation suite
npm test
```

### Validated Test Vectors (`tests/crypto.test.js`):
1. **Key Agreement**: Ephemeral `ECDH P-384` keypair generation (RFC 5903).
2. **Key Derivation**: `HKDF-SHA256` symmetric root and initial chain key derivation with dynamic 32-byte CSPRNG salt.
3. **Forward Secrecy**: Symmetric KDF Chain Ratchet ensuring distinct message keys per transmission and verifying that past keys cannot decrypt future ratcheted payloads.
4. **Symmetric Encryption**: `AES-256-GCM` encryption with 128-bit MAC tag integrity validation.
5. **Nonce Isolation**: 96-bit CSPRNG initialization vector (IV) freshness preventing nonce reuse.
6. **Anti-Forensics**: Multi-pass binary memory zeroization of sensitive key buffers.

---

## 3. Core Architecture & Threat Model

```
┌─────────────────┐             Client-to-Client E2EE Tunnel            ┌─────────────────┐
│ Sender (Client) │ ◄═════════════════════════════════════════════════► │Receiver (Client)│
└────────┬────────┘                                                     └────────┬────────┘
         │               TLS 1.3 / WSS Authenticated Framing                     │
         └──────────────────────────► [ Relay Broker ] ◄─────────────────────────┘
                                 (In-Memory Transient Buffer)
```

### Security Properties & Claim Boundaries:

| Security Property | Implementation & Verification Status |
| :--- | :--- |
| **Client-Side E2EE** | ✅ **Implemented & Verifiable**: All messages are sealed via `AES-256-GCM` within client sandboxes prior to network transport. |
| **Forward Secrecy** | ✅ **Implemented & Verifiable**: Each message advances a symmetric `HKDF-SHA256` chain ratchet, generating single-use message keys. |
| **Media Encryption** | ✅ **Implemented & Verifiable**: Real-time voice/video channels establish direct P2P `DTLS 1.3 / SRTP` connections. |
| **Zero-Retention Relay** | 📋 **Architectural Policy**: In-memory transit queues (Redis) purge ciphertexts upon recipient acknowledgment (`ACK`). Third-party white-box audit planned for formal certification. |

---

## 4. Technology Stack & Implementation Standards

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

## 5. Security Contact & Independent Audit Roadmap

Truples is committed to transparent security practices:

- 📋 **Third-Party Audit Roadmap**: A formal third-party source code and infrastructure audit is scheduled as part of our production release milestones.
- ✉️ **Security Contact & Vulnerability Reports**: `security@truples.com`

---

Copyright (c) 2025 Truples Systems. All rights reserved.
