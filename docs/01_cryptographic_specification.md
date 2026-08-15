# Cryptographic Specification & Key Agreement Protocols

## 1. Scope & Primitives

This document specifies the cryptographic algorithms, key lifecycle management, and payload serialization standards utilized in the Truples communication platform.

### Cryptographic Standards Inventory:
- **Symmetric Cipher**: `AES-256-GCM` (NIST SP 800-38D)
- **Asymmetric Key Exchange**: `ECDH` over NIST P-384 / SECP384R1 (RFC 5903) & `RSA-OAEP-4096` (RFC 8017)
- **Key Derivation Function**: `HKDF` with `HMAC-SHA256` (RFC 5869)
- **Forward Secrecy**: Symmetric KDF Chain Ratchet advancing per-message
- **Random Number Generation**: Cryptographically Secure Pseudorandom Number Generator (CSPRNG) via WebCrypto `crypto.getRandomValues()` and native OS entropy pools.

---

## 2. Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)

To guarantee strict Forward Secrecy at the client layer, Truples utilizes a symmetric KDF Chain Ratchet structure:

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

## 3. Symmetric Payload Encryption (AES-256-GCM)

All conversation text, structured metadata, and media attachments are encrypted on the client device prior to transport.

### Parameters:
- **Key Size**: 256 bits (32 octets) derived via KDF Chain Ratchet.
- **Initialization Vector (IV)**: 96 bits (12 octets), randomly generated per individual message using CSPRNG. Nonces are never reused.
- **Authentication Tag (MAC)**: 128 bits (16 octets), computed over ciphertext and authenticated additional data (AAD).

```
┌──────────────────────────────────────────────────────────┐
│                   Serialized Payload                     │
├───────────────┬──────────────────────────┬───────────────┤
│ IV (12 bytes) │ Ciphertext (N bytes)     │ MAC (16 bytes)│
└───────────────┴──────────────────────────┴───────────────┘
```

Any modification of ciphertext or authentication tags during transit results in immediate MAC verification failure on the recipient device.

---

## 4. Zero-Retention Relay as Defense-in-Depth

In Truples, **Zero-Retention is architected as an infrastructure-level defense-in-depth policy complementing client-side E2EE**:

1. **Metadata & Transport Exposure Minimization**: Purging transient ciphertexts from volatile memory immediately upon delivery acknowledgment (`ACK`) prevents accumulation of network transaction artifacts.
2. **Post-Quantum & Algorithmic Resilience**: Eliminating long-term server-side ciphertext stores mitigates future threats involving retrospective bulk harvesting and offline cryptanalysis.

---

## 5. Client-Side Memory Management & Key Storage

1. **Hardware-Backed Key Isolation**: Mobile clients bind long-term asymmetric identity keys within Android `AndroidKeyStore` and iOS `Keychain / Secure Enclave`.
2. **Deterministic Buffer Zeroization**: Ephemeral cryptographic buffers undergo multi-pass binary overwriting prior to deallocation.
3. **Side-Channel Mitigation**: Credential evaluation endpoints employ constant-time comparison primitives to prevent timing side-channel data leakage.
