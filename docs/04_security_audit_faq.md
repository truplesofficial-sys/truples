# Technical Architecture & Security Evaluation FAQ

This document provides technical clarification on protocol design decisions, cryptographic trade-offs, and independent verification procedures for security researchers and technical auditors.

---

## 1. Protocol Design Decisions

### Q: Why does Truples employ Ephemeral KDF Ratcheting rather than the Signal Protocol Double Ratchet?

1. **Storage Threat Vector Elimination**:
   - The Double Ratchet protocol was designed to mitigate retrospective key compromise in architectures where central servers permanently archive historical ciphertexts.
   - Truples eliminates server-side historical storage entirely: all message payloads exist in volatile memory solely until delivery acknowledgment (`ACK`), at which point they are **atomically purged from memory (Zero-Retention)**.
   - Because historical ciphertexts are not retained on relay infrastructure, retrospective storage breach attacks are mitigated at the architectural layer.
2. **Payload-Level Key Freshness**:
   - Every individual message payload is sealed using a distinct 96-bit CSPRNG initialization vector (IV) and ephemeral `HKDF-SHA256` key derivation, ensuring cryptographic isolation between consecutive transmissions.
3. **Throughput Optimization**:
   - Omitting complex persistent ratchet state trees reduces client computational overhead and state synchronization latency, optimizing throughput for large encrypted file transfers (1GB+) and real-time WebRTC media channels.

---

## 2. Zero-Retention & Zero-Knowledge Trust Model

### Q: How is user confidentiality preserved if remote server internals cannot be directly inspected by clients?

1. **Client-Side Zero-Knowledge Cryptography**:
   - The relay server never possesses private asymmetric keys, shared secrets, or plaintext payloads.
   - In any scenario involving infrastructure seizure or adverse access, **the server possesses zero cryptographic material capable of decrypting in-flight or transient payloads**.
2. **Dual-Layer Assurance**:
   - **Cryptographic Layer**: End-to-end `AES-256-GCM` ensures payloads remain opaque to intermediate transport nodes.
   - **Infrastructure Layer**: Ephemeral Redis buffers execute deterministic zeroization upon delivery acknowledgment.

---

## 3. Independent Client Verification Guide

Security researchers can verify Truples' client-side cryptographic operations using standard developer tools:

| Verification Target | Inspection Method | Expected Artifact |
| :--- | :--- | :--- |
| **1. Symmetric Encryption** | Browser DevTools / APK Decompilation | Execution of WebCrypto `crypto.subtle.encrypt({ name: "AES-GCM", iv: ... })` |
| **2. IV Randomness** | WebSocket Inspection (`/ws-chat-pure`) | Unique 12-byte CSPRNG nonce prefixed to each payload |
| **3. Asymmetric Key Agreement** | Client Key Lifecycle | `ECDH` P-384 keypair generation with `HKDF-SHA256` derivation |
| **4. P2P WebRTC Security** | Chrome: `chrome://webrtc-internals` | Direct `RTCPeerConnection`, `DTLS 1.3`, and `SRTP` cipher suites |
| **5. Hardware Key Storage** | Native Mobile Frameworks | Key material bound to Android `AndroidKeyStore` / iOS `Secure Enclave` |

---

## 4. Asynchronous Offline Message Delivery

### Q: How are messages delivered to offline recipients without permanent database storage?

1. **Transient In-Memory Buffering**:
   - When a recipient is offline, the encrypted payload is buffered in an in-memory Redis queue with a strict Time-To-Live (TTL).
2. **Encrypted Push Wakeup**:
   - A silent high-priority push notification (FCM / APNs) is dispatched to wake the recipient device.
3. **Atomic Delivery & Purge**:
   - Upon WebSocket channel establishment, the client fetches the transit payload and emits an atomic delivery acknowledgment (`ACK`), triggering the immediate zeroization of the buffer.

---

## 5. Anti-Forensics & Physical Coercion Safeguards

1. **Decoy Environment (P1)**: The duress credential renders a functional decoy session with benign synthetic data.
2. **Cryptographic Key Purge (P2)**: The wipe credential triggers immediate deletion of local master keys and SQLite/IndexedDB decryption handles.
3. **Hardware Zeroization (P3)**: Executes low-level memory scrubbing and revokes all active session tokens on relay infrastructure.
4. **Side-Channel Mitigation**: Credential verification employs constant-time comparison primitives (`MessageDigest.isEqual`) to eliminate timing side-channel exploits.
