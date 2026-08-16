# Truples Cryptographic Threat Model & Boundary Specifications

This document defines the adversary capabilities, security bounds, and formal cryptographic invariants enforced across the **Truples Enterprise Double Ratchet Protocol**.

---

## 1. Adversary Capabilities (In-Scope Threat Model)

The protocol is designed and verified under the standard **Dolev-Yao Network Adversary Model**, augmented with malicious relay infrastructure assumptions:

| Adversary Vector | Adversary Capability | Cryptographic Mitigation |
| :--- | :--- | :--- |
| **Network Eavesdropping** | Intercepts 100% of network traffic across public Wi-Fi, ISP, or cellular links. | Protected via `AES-256-GCM` 256-bit symmetric encryption with CSPRNG 96-bit unique IVs. |
| **Malicious Server / Relay** | Controls relay servers; attempts to tamper with ciphertext, headers, or metadata. | Prevented via `AES-256-GCM` 128-bit MAC & 113-byte Canonical AAD binary header authentication. |
| **Message Reordering / Drops** | Arbitrarily reorders, delays, duplicates, or drops transit encrypted payloads. | Handled via bounded skipped message keys buffer and FIFO replay cache rejection. |
| **Man-in-the-Middle (MITM)** | Attempts to substitute ephemeral ECDH exchange keys during session establishment. | Thwarted via mandatory P-384 ECDSA signatures over ephemeral public keys. |
| **Historical State Theft** | Extracts full local session state at time $T_k$. | Strictly confined via **Forward Secrecy**: historical messages $T_{<k}$ remain mathematically unrecoverable. |
| **Compromise Persistence** | Attempts continuous eavesdropping following a point-in-time state theft at $T_k$. | Permanently locked out via **Post-Compromise Security (PCS)** upon next ephemeral DH turn. |
| **Temporal Snapshot Rollback** | Re-injects an old encrypted session snapshot $V_{\text{old}}$ to reverse state transitions. | Blocked via `PersistentStorageEnclave` 64-bit monotonic version anti-rollback counter ($V < V_{\text{highest}}$). |

---

## 2. Out-of-Scope Security Boundaries

The following vectors operate outside the cryptographic protocol layer and require host-level OS/hardware protections:
- **Compromised Host OS / Kernel / Root Access**: If an adversary gains full kernel-level memory access on the running host, in-flight ephemeral plaintext in RAM cannot be protected by application-level cryptography.
- **Physical Device Tampering without Secure Enclave**: Extraction of raw flash storage where hardware-backed Android Keystore / iOS Secure Enclave protection is bypassed or absent on rooted devices.
- **Side-Channel Hardware Attacks**: Deep microarchitectural timing attacks on underlying CPU hardware execution units.
