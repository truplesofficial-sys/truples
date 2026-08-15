# Formal Verification Specification: Truples Enterprise Double Ratchet

This directory contains the formal mathematical model and automated proof specifications for the **Truples Enterprise Double Ratchet Protocol** formulated for the [Tamarin Prover](https://tamarin-prover.github.io/) cryptographic verification system.

---

## 1. Verified Properties & Security Lemmas

| Security Lemma | Mathematical Property | Threat Model Mitigation |
| :--- | :--- | :--- |
| `Session_Key_Agreement` | $\forall A, B : \text{RootKey}_A = \text{RootKey}_B \land \text{Send}_A = \text{Recv}_B$ | Prevents MITM desynchronization |
| `Forward_Secrecy` | $\forall m, t : \text{AttackerState}_{t+1} \not\implies \text{Plaintext}_t$ | Historical ciphertext confidentiality |
| `Post_Compromise_Security`| $\forall \text{Turn} > t_{\text{compromise}} : \text{Attacker} \not\implies \text{SessionKey}_{\text{new}}$ | Self-healing enclave after state theft |

---

## 2. Verification Execution

To execute automated lemma proofs using Tamarin Prover:

```bash
# Interactive web UI verification
tamarin-prover interactive formal/

# Automated batch proof verification
tamarin-prover formal/truples_ratchet.spthy --prove
```
