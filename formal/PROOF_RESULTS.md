# Tamarin Prover Formal Verification Proof Results

This document records the mathematical verification results of the **Truples Enterprise Double Ratchet Protocol** formal specification (`formal/truples_ratchet.spthy`) modeled for the [Tamarin Prover](https://tamarin-prover.github.io/) cryptographic verification system.

---

## 1. Verified Lemma Proof Summary

All formal lemmas targeting the core ratchet state machine were evaluated under the standard **Dolev-Yao network adversary model**:

| Lemma Name | Mathematical Target | Result | Verification State |
| :--- | :--- | :---: | :---: |
| `Session_Key_Agreement` | Mutual Root Key and Directional Chain Key parity between initiator and responder | **PASSED** | `verified` |
| `Directional_Key_Separation` | Asymmetric isolation of sending and receiving chains ($\text{SendChain} \neq \text{RecvChain}$) | **PASSED** | `verified` |
| `Forward_Secrecy` | Temporal forward secrecy: historical ciphertexts remain secret after future state compromise ($t_{\text{msg}} < t_{\text{compromise}}$) | **PASSED** | `verified` |
| `Post_Compromise_Security` | Self-healing enclave: adversary possessing past state is locked out after fresh Ephemeral DH turn ($t_{\text{compromise}} < t_{\text{turn}}$) | **PASSED** | `verified` |

---

## 2. Command Execution Trace

```bash
$ tamarin-prover formal/truples_ratchet.spthy --prove

==============================================================================
summary of summaries:

analyzed: formal/truples_ratchet.spthy

  Session_Key_Agreement (all-traces): verified (8 steps)
  Directional_Key_Separation (all-traces): verified (4 steps)
  Forward_Secrecy (all-traces): verified (12 steps)
  Post_Compromise_Security (all-traces): verified (14 steps)

==============================================================================
```

---

## 3. Formal Verification Scope Boundary

- **In-Scope (Formally Verified via Tamarin)**:
  - Long-term ECDSA Identity Key Binding
  - Ephemeral P-384 Authenticated Key Exchange
  - Asymmetric Ephemeral DH Ratchet Turn-Taking
  - Directional KDF Chain Separation
  - Temporal Forward Secrecy & Post-Compromise Security
- **Integration Layer (Validated via 28-Vector Automated Suite)**:
  - AES-256-GCM AAD Header Serialization & MAC Validation
  - Skipped/Consumed Message Key Buffering & Out-of-Order Delivery
  - Encrypted Session Snapshots & Monotonic Anti-Rollback Storage
  - Persistent TOFU Identity Store & Truples 60-Digit Safety Number
