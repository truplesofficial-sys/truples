# Truples Protocol & Architecture Specification

[![Status: Production](https://img.shields.io/badge/Status-Production%20Live-emerald.svg)](https://truples.com)
[![Crypto Tests: 6/6 Passing](https://img.shields.io/badge/Crypto%20Tests-6%2F6%20Passing-brightgreen.svg)](tests/crypto.test.js)
[![Cipher: AES--256--GCM](https://img.shields.io/badge/Cipher-AES--256--GCM%20(NIST%20SP%20800--38D)-blue.svg)](https://truples.com)
[![Key Exchange: ECDH P--384](https://img.shields.io/badge/Key%20Exchange-ECDH%20P--384%20(RFC%205903)-purple.svg)](https://truples.com)
[![Forward Secrecy: KDF Chain Ratchet](https://img.shields.io/badge/Forward%20Secrecy-KDF%20Chain%20Ratchet%20(RFC%205869)-teal.svg)](src/crypto/truples-crypto.js)
[![Media: WebRTC DTLS/SRTP](https://img.shields.io/badge/Media-WebRTC%20DTLS%2FSRTP%20(RFC%203711)-orange.svg)](https://truples.com)
[![License: Proprietary Specification](https://img.shields.io/badge/License-Proprietary%20Spec-gray.svg)](LICENSE.md)

---

## 1. Executive Summary

**Truples** is an enterprise-grade, end-to-end encrypted (E2EE) communication platform architected around **client-side symmetric KDF chain ratcheting**, a **Zero-Retention ephemeral relay model**, and **decentralized Peer-to-Peer (P2P) WebRTC media channels**.

This repository contains the **official technical specifications**, **architecture whitepapers**, and a **runnable reference implementation of the cryptographic core engine**.

- 🌐 **Live Web Application**: [https://truples.com](https://truples.com)
- 🧪 **Reference Cryptographic Module**: [`src/crypto/truples-crypto.js`](src/crypto/truples-crypto.js)
- 📚 **Technical Whitepapers**:
  - [01. Cryptographic Primitives & Key Agreement](docs/01_cryptographic_specification.md)
  - [02. WebRTC P2P Media Mesh Architecture](docs/02_webrtc_media_mesh.md)
  - [03. Hardware Panic & Anti-Forensics Matrix](docs/03_panic_security_matrix.md)
  - [04. Security Audit & Architecture FAQ](docs/04_security_audit_faq.md)

---

## 2. Live Interactive Evaluation & Verification

Truples is not a theoretical whitepaper project. Evaluators and security researchers can immediately verify cryptographic and network behaviors on live production endpoints:

### A. Live Interactive Client Test (Zero Setup)
1. Navigate to the live web client: **[https://truples.com](https://truples.com)**.
2. Open Browser DevTools (`F12` ➔ **Network** tab ➔ **WS** sub-tab).
3. Authenticate and transmit any message or establish a P2P call.
4. **Inspect WebSocket Frames (`/ws-chat-pure`)**: Verify that all message payloads leave the browser strictly as Base64-encoded `AES-256-GCM` ciphertext with fresh 12-byte IVs, while plaintext is never visible on network boundaries.

### B. Running Local Cryptographic Verification Tests
This repository includes a standalone test suite validating NIST/RFC cryptographic operations:

```bash
# Clone the repository
git clone https://github.com/truplesofficial-sys/truples.git
cd truples

# Run automated cryptographic validation suite
npm test
```

**Validated Test Vectors:**
- ✅ `ECDH P-384` ephemeral keypair generation
- ✅ `HKDF-SHA256` symmetric root & chain key derivation with dynamic CSPRNG salt
- ✅ **Symmetric KDF Chain Ratchet (Strict per-message forward secrecy)**
- ✅ `AES-256-GCM` 256-bit encryption & 128-bit MAC validation
- ✅ Per-message 96-bit CSPRNG IV freshness (No nonce reuse)
- ✅ 128-bit authentication tag tamper resistance
- ✅ Multi-pass memory buffer zeroization

---

## 3. Core Architecture & Threat Model

Truples operates under a **Zero-Knowledge Relay** model. The server infrastructure functions exclusively as an authenticated packet router without possession of cryptographic private keys or plaintext data.

```
┌─────────────────┐             Client-to-Client E2EE Tunnel            ┌─────────────────┐
│ Sender (Client) │ ◄═════════════════════════════════════════════════► │Receiver (Client)│
└────────┬────────┘                                                     └────────┬────────┘
         │               TLS 1.3 / WSS Authenticated Framing                     │
         └──────────────────────────► [ Relay Broker ] ◄─────────────────────────┘
                                 (In-Memory Transient Buffer)
```

### Threat Boundaries & Security Properties:
1. **Client-Side Symmetric KDF Ratchet (Forward Secrecy)**:
   - Each message derives a unique, single-use `MessageKey` from an advancing `ChainKey` via `HKDF-SHA256`. Old chain states are deleted immediately upon key derivation, preventing retrospective decryption of past messages if a future key state is compromised.
2. **Confidentiality Against Relay Seizure (Zero-Knowledge)**:
   - Asymmetric private keys and session keys exist exclusively within client hardware sandboxes (Android Keystore / iOS Secure Enclave / WebCrypto storage). Even under full server infrastructure compromise or legal subpoena, the relay server possesses zero mathematical capability to decrypt payloads.
3. **Atomic Zero-Retention (Defense-in-Depth & Metadata Reduction)**:
   - Transit payloads are held in volatile RAM (Redis) solely during active transmission. Upon delivery acknowledgment (`ACK`), payloads are atomically zeroized and destroyed from memory.
4. **Decentralized Media Channels**:
   - Real-time voice and video streams establish direct P2P mesh connections via WebRTC (`DTLS 1.3` / `SRTP`), bypassing central media processing servers (MCU/SFU).

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

## 5. Security Contact & Disclosures

The technical documentation, specifications, and reference cryptographic implementations contained in this repository are published for evaluation, verification, and transparency purposes under a proprietary specification license.

- ✉️ **Security Contact**: `security@truples.com`

---

Copyright (c) 2025 Truples Systems. All rights reserved.
