# Independent Rust Conformance Implementation

This module contains the standalone, clean-room **Rust reference implementation** for the **Truples Enterprise Double Ratchet Protocol**.

---

## 1. Conformance Verification Target

This independent Rust engine validates byte-level interoperability with [`vectors/deterministic_vectors.json`](../../vectors/deterministic_vectors.json):

1. **RFC 5869 HKDF-SHA256 Directional Key Derivation**:
   - `RootKey`: `1c75d2f8031957618170ba29e5407456a604c1249896bf80f5bb1324a74f19ad`
   - `InitToRespChain`: `62f07800ae176576f818c02e271200cb9884a7e93b9de138e80cb6e80e85abaa`
   - `RespToInitChain`: `1c625c71486b5d4c396595d86bf601d8bf4149192d91077e6161afbfa2a945c7`
2. **Canonical 113-Byte Binary AAD Encoding**:
   - Matches Big-Endian 4-byte version, 4-byte key length, 97-byte raw point, and counter trailers.
3. **Truples 60-Digit Safety Number**:
   - Matches 512-round SHA-512 lexicographically ordered fingerprint (`53385 46115 27790 ...`).

---

## 2. Running Rust Conformance Verification

```bash
cd implementations/rust
cargo run
```
