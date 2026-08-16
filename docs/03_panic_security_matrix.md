# Multi-Tier Panic Defense Matrix & Anti-Forensics

## 1. Threat Model & Overview
The Truples Panic Defense Matrix provides mathematically irreversible hardware and cryptographic safeguards in physical duress, coercion, or device seizure scenarios.

## 2. Panic Security Tiers

### 🚨 Level 1: Duress Decoy State (P1)
- **Trigger**: Entering dedicated Duress PIN (`pw1`) at login prompt.
- **Action**: Renders a convincing decoy environment populated with randomized benign contacts, decoy messages, and synthetic transaction logs.
- **Forensic Status**: The real encrypted partition remains completely hidden and dormant.

### 🚨 Level 2: Ephemeral Cryptographic Wipe (P2)
- **Trigger**: Entering Wipe PIN (`pw2`) or executing remote emergency panic signal.
- **Action**: Instantly wipes local WebCrypto master encryption keys and unlinks conversation stores from SQLite / IndexedDB.
- **Forensic Status**: Local conversation databases become irrecoverable noise without the master key.

### 🚨 Level 3: Complete Hardware Zeroization (P3)
- **Trigger**: Entering Zeroize PIN (`pw3`).
- **Action**: Executes low-level memory zeroization, completely terminates active server sessions via constant-time revocation, and destroys all device configuration tokens.

## 3. Side-Channel Timing Defense
- **Constant-Time Verification**: Server-side PIN evaluation utilizes `MessageDigest.isEqual()` and fixed artificial execution delays to ensure constant response times across valid and invalid PIN challenges, eliminating timing side-channel attacks.
