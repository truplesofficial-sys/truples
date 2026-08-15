/**
 * Truples Cryptographic Core & Enterprise Double Ratchet State Machine
 * 
 * Fully compatible with:
 * - W3C WebCrypto API (Browser & Node.js Universal Runtime, zero external dependencies)
 * - NIST SP 800-38D (AES-GCM-256 with 96-bit CSPRNG IV & 128-bit MAC tag)
 * - FIPS 186-4 (ECDSA over NIST P-384 with SHA-384 for MITM-resistant authenticated key exchange)
 * - RFC 5903 (ECDH over NIST P-384 curve with uncompressed 97-byte 0x04 point validation)
 * - RFC 5869 (HKDF with HMAC-SHA256)
 * - Enterprise Double Ratchet Specification:
 *   - Full 256-bit SHA-256 Key Fingerprinting for Cryptographically Negligible Collision Risk
 *   - Continuous Automated Ephemeral DH Ratchet Turn-Taking (Self-Healing PCS upon Outbound Turn)
 *   - Directional DH KDF Chain Separation (Alice.Send == Bob.Recv && Alice.Send != Alice.Recv)
 *   - AAD-Authenticated Header Binding with Strict Integer Range Validation
 *   - Bounded Replay Protection Cache with Transactional State Rollback on Tamper/Failure
 *   - Encrypted Session Snapshot Storage (Including complete skipped & consumed key states)
 *   - Persistent Monotonic Counter & Encrypted IdentityStore Enclave (Anti-Rollback & TOFU Pinning)
 *   - Truples 60-Digit Verifiable Safety Number Fingerprinting
 */

const cryptoSubtle = typeof window !== 'undefined' && window.crypto?.subtle 
  ? window.crypto.subtle 
  : (globalThis.crypto?.subtle || require('crypto').webcrypto.subtle);

const cryptoRandom = typeof window !== 'undefined' && window.crypto?.getRandomValues
  ? (buf) => window.crypto.getRandomValues(buf)
  : (buf) => (globalThis.crypto?.getRandomValues ? globalThis.crypto.getRandomValues(buf) : require('crypto').randomFillSync(buf));

// Universal zero-dependency Base64 encoding/decoding (Native Browser & Node compatible)
function bytesToBase64(bytes) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Validates and canonically encodes Double Ratchet Headers for AES-GCM AAD Authentication.
 * Binary format: [4-byte version] [4-byte pubKeyLength] [pubKeyBytes] [4-byte prevChainLength] [4-byte messageNum]
 */
export function canonicalEncodeHeader(header) {
  if (!header || typeof header !== 'object') {
    throw new Error('Invalid header format: header must be an object');
  }

  const prevLen = header.previousChainLength;
  const msgNum = header.messageNumber;

  if (!Number.isInteger(prevLen) || prevLen < 0 || prevLen > 0xFFFFFFFF) {
    throw new Error('Invalid header: previousChainLength must be a valid unsigned 32-bit integer');
  }
  if (!Number.isInteger(msgNum) || msgNum < 0 || msgNum > 0xFFFFFFFF) {
    throw new Error('Invalid header: messageNumber must be a valid unsigned 32-bit integer');
  }

  const pubKeyBytes = typeof header.dhPublicKey === 'string' ? base64ToBytes(header.dhPublicKey) : header.dhPublicKey;
  if (!pubKeyBytes || pubKeyBytes.byteLength !== 97 || pubKeyBytes[0] !== 0x04) {
    throw new Error('Invalid header: dhPublicKey must be a 97-byte uncompressed NIST P-384 point (0x04 prefix)');
  }

  const buffer = new ArrayBuffer(4 + 4 + pubKeyBytes.byteLength + 4 + 4);
  const view = new DataView(buffer);

  view.setUint32(0, 1, false); // Version 1
  view.setUint32(4, pubKeyBytes.byteLength, false);
  new Uint8Array(buffer, 8, pubKeyBytes.byteLength).set(pubKeyBytes);

  const offset = 8 + pubKeyBytes.byteLength;
  view.setUint32(offset, prevLen, false);
  view.setUint32(offset + 4, msgNum, false);

  return new Uint8Array(buffer);
}

export class TruplesCryptoCore {
  /**
   * Generates an ephemeral ECDH keypair over the NIST P-384 curve (RFC 5903).
   * @returns {Promise<CryptoKeyPair>}
   */
  static async generateECDHKeypair() {
    return await cryptoSubtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveKey', 'deriveBits']
    );
  }

  /**
   * Generates a long-term ECDSA identity keypair over NIST P-384 with SHA-384 for identity verification.
   * @returns {Promise<CryptoKeyPair>}
   */
  static async generateECDSAKeypair() {
    return await cryptoSubtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify']
    );
  }

  /**
   * Generates a device-specific local storage master encryption key (AES-256-GCM).
   * @returns {Promise<CryptoKey>}
   */
  static async generateDeviceStorageKey() {
    return await cryptoSubtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Signs a payload or ephemeral public key using ECDSA P-384 (MITM Defense).
   */
  static async signPayload(data, privateKey) {
    const rawData = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const signatureBuffer = await cryptoSubtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-384' } },
      privateKey,
      rawData
    );
    return bytesToBase64(new Uint8Array(signatureBuffer));
  }

  /**
   * Verifies an ECDSA P-384 signature against remote public identity key.
   */
  static async verifySignature(data, signatureBase64, publicKey) {
    const rawData = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const signatureBytes = base64ToBytes(signatureBase64);
    return await cryptoSubtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-384' } },
      publicKey,
      signatureBytes,
      rawData
    );
  }

  /**
   * Derives root and role-aligned directional chain keys using HKDF-SHA256.
   */
  static async deriveRootAndChainKeys(localPrivateKey, remotePublicKey, dynamicSalt, role = 'initiator') {
    const salt = dynamicSalt || new Uint8Array(32);
    if (!dynamicSalt) cryptoRandom(salt);

    const sharedBits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: remotePublicKey },
      localPrivateKey,
      384
    );

    const hkdfKey = await cryptoSubtle.importKey(
      'raw',
      sharedBits,
      { name: 'HKDF' },
      false,
      ['deriveKey', 'deriveBits']
    );

    new Uint8Array(sharedBits).fill(0);

    const rootKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('Truples-Root-Key')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    const initToRespChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('Truples-Chain-Initiator-To-Responder')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    const respToInitChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('Truples-Chain-Responder-To-Initiator')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    if (role === 'initiator') {
      return { rootKey, sendingChainKey: initToRespChainKey, receivingChainKey: respToInitChainKey, chainKey: initToRespChainKey };
    } else {
      return { rootKey, sendingChainKey: respToInitChainKey, receivingChainKey: initToRespChainKey, chainKey: respToInitChainKey };
    }
  }

  /**
   * Executes a MITM-resistant Authenticated Key Exchange (ECDH + ECDSA Identity Verification).
   */
  static async deriveAuthenticatedRootAndChainKeys(
    localEcdhPrivateKey,
    remoteEcdhPublicKey,
    remoteEcdsaIdentityPublicKey,
    remoteSignatureBase64,
    dynamicSalt,
    role = 'initiator'
  ) {
    const remoteKeyRaw = await cryptoSubtle.exportKey('raw', remoteEcdhPublicKey);
    const isAuthentic = await this.verifySignature(
      new Uint8Array(remoteKeyRaw),
      remoteSignatureBase64,
      remoteEcdsaIdentityPublicKey
    );

    if (!isAuthentic) {
      throw new Error('Cryptographic Handshake Aborted: MITM identity verification failed.');
    }

    return await this.deriveRootAndChainKeys(localEcdhPrivateKey, remoteEcdhPublicKey, dynamicSalt, role);
  }

  /**
   * Executes an Asymmetric DH Ratchet Step upon conversational turn-taking.
   * Derives a new Root Key and strictly separated directional sending/receiving chains.
   */
  static async executeDhRatchetStep(currentRootKey, localDhPrivateKey, remoteDhPublicKey, role = 'initiator') {
    const newSharedBits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: remoteDhPublicKey },
      localDhPrivateKey,
      384
    );

    const rootKeyBytes = await cryptoSubtle.exportKey('raw', currentRootKey);

    const hkdfKey = await cryptoSubtle.importKey(
      'raw',
      newSharedBits,
      { name: 'HKDF' },
      false,
      ['deriveKey', 'deriveBits']
    );

    new Uint8Array(newSharedBits).fill(0);

    const newRootKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(rootKeyBytes),
        info: new TextEncoder().encode('Truples-DH-Ratchet-Root-Step')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    const initToRespChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(rootKeyBytes),
        info: new TextEncoder().encode('Truples-DH-Ratchet-Init-To-Resp')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    const respToInitChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(rootKeyBytes),
        info: new TextEncoder().encode('Truples-DH-Ratchet-Resp-To-Init')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    new Uint8Array(rootKeyBytes).fill(0);

    if (role === 'initiator') {
      return { 
        newRootKey, 
        newSendingChainKey: initToRespChainKey, 
        newReceivingChainKey: respToInitChainKey,
        newChainKey: initToRespChainKey 
      };
    } else {
      return { 
        newRootKey, 
        newSendingChainKey: respToInitChainKey, 
        newReceivingChainKey: initToRespChainKey,
        newChainKey: respToInitChainKey 
      };
    }
  }

  /**
   * Executes a symmetric KDF Chain Ratchet step (Per-Message Forward Secrecy).
   */
  static async ratchetMessageKey(currentChainKey) {
    const chainKeyData = await cryptoSubtle.exportKey('raw', currentChainKey);
    const hkdfKey = await cryptoSubtle.importKey(
      'raw',
      chainKeyData,
      { name: 'HKDF' },
      false,
      ['deriveKey', 'deriveBits']
    );

    const nextChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('Truples-Chain-Step')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    const messageKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('Truples-Message-Key')
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    new Uint8Array(chainKeyData).fill(0);

    return { nextChainKey, messageKey };
  }

  /**
   * Encrypts plaintext using AES-256-GCM with a fresh 96-bit CSPRNG IV and optional AAD.
   */
  static async encryptPayload(plaintext, messageKey, additionalData) {
    const rawData = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
    const iv = new Uint8Array(12);
    cryptoRandom(iv);

    const gcmParams = { name: 'AES-GCM', iv: iv, tagLength: 128 };
    if (additionalData) {
      gcmParams.additionalData = additionalData;
    }

    const encryptedBuffer = await cryptoSubtle.encrypt(
      gcmParams,
      messageKey,
      rawData
    );

    return {
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer))
    };
  }

  /**
   * Decrypts and authenticates AES-256-GCM ciphertext payload with 128-bit MAC tag and optional AAD validation.
   */
  static async decryptPayload(ivBase64, ciphertextBase64, messageKey, additionalData) {
    const iv = base64ToBytes(ivBase64);
    const ciphertext = base64ToBytes(ciphertextBase64);

    const gcmParams = { name: 'AES-GCM', iv: iv, tagLength: 128 };
    if (additionalData) {
      gcmParams.additionalData = additionalData;
    }

    const decryptedBuffer = await cryptoSubtle.decrypt(
      gcmParams,
      messageKey,
      ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
  }

  /**
   * Best-effort in-memory buffer scrubbing for typed arrays.
   */
  static zeroizeBuffer(buffer) {
    if (!buffer || !buffer.length) return;
    buffer.fill(0x00);
    buffer.fill(0xFF);
    cryptoRandom(buffer);
    buffer.fill(0x00);
  }

  /**
   * Computes a 60-digit verifiable Safety Number from two ECDSA Identity Keys (Truples Safety Number Standard).
   * Formatted into 12 groups of 5 decimal digits: XXXXX XXXXX XXXXX ...
   * @param {CryptoKey} keyA 
   * @param {CryptoKey} keyB 
   * @returns {Promise<string>}
   */
  static async computeSafetyNumber(keyA, keyB) {
    const rawA = new Uint8Array(await cryptoSubtle.exportKey('raw', keyA));
    const rawB = new Uint8Array(await cryptoSubtle.exportKey('raw', keyB));

    const cmp = Buffer.compare ? Buffer.compare(Buffer.from(rawA), Buffer.from(rawB)) : (rawA[0] - rawB[0]);
    const first = cmp <= 0 ? rawA : rawB;
    const second = cmp <= 0 ? rawB : rawA;

    const combined = new Uint8Array(first.length + second.length);
    combined.set(first, 0);
    combined.set(second, first.length);

    let hash = await cryptoSubtle.digest('SHA-512', combined);
    for (let i = 0; i < 512; i++) {
      hash = await cryptoSubtle.digest('SHA-512', hash);
    }

    const hashBytes = new Uint8Array(hash);
    let digits = '';
    for (let i = 0; i < 30; i += 2) {
      const num = ((hashBytes[i] << 8) | hashBytes[i + 1]) % 100000;
      digits += num.toString().padStart(5, '0');
    }

    return digits.substring(0, 60).match(/.{1,5}/g).join(' ');
  }
}

/**
 * Persistent Secure Storage & Monotonic Counter Enclave
 * Simulates OS-level Hardware Security Module / Keychain Monotonic Counter storage.
 */
export class PersistentStorageEnclave {
  constructor() {
    this.counters = new Map();
    this.encryptedBlob = null;
  }

  getHighestVersion(sessionId) {
    return this.counters.get(sessionId) || 0;
  }

  setHighestVersion(sessionId, version) {
    const current = this.getHighestVersion(sessionId);
    if (version < current) {
      throw new Error('Anti-Rollback Violation: Counter cannot be decremented');
    }
    this.counters.set(sessionId, version);
  }
}

/**
 * Persistent Trust-On-First-Use (TOFU) Identity Store Enclave
 * Supports full encrypted export and persistent restoration against app lifecycle resets.
 */
export class IdentityStore {
  constructor() {
    this.trustedIdentities = new Map(); // PeerID -> SHA-256 fingerprint
  }

  async saveIdentity(peerId, identityPublicKey) {
    const fingerprint = await DoubleRatchetSession.getPublicKeyFingerprint(identityPublicKey);
    this.trustedIdentities.set(peerId, fingerprint);
  }

  async verifyOrTrustIdentity(peerId, identityPublicKey) {
    const fingerprint = await DoubleRatchetSession.getPublicKeyFingerprint(identityPublicKey);
    if (!this.trustedIdentities.has(peerId)) {
      this.trustedIdentities.set(peerId, fingerprint);
      return { status: 'TRUSTED_FIRST_USE', fingerprint };
    }

    const trustedFingerprint = this.trustedIdentities.get(peerId);
    if (trustedFingerprint !== fingerprint) {
      throw new Error(`CRITICAL SECURITY ALERT: Remote identity key changed for peer [${peerId}]. Possible MITM attack.`);
    }

    return { status: 'VERIFIED', fingerprint };
  }

  async exportEncrypted(deviceMasterKey) {
    const data = JSON.stringify(Array.from(this.trustedIdentities.entries()));
    return await TruplesCryptoCore.encryptPayload(data, deviceMasterKey);
  }

  static async restoreEncrypted(encryptedBlob, deviceMasterKey) {
    const decryptedJson = await TruplesCryptoCore.decryptPayload(encryptedBlob.iv, encryptedBlob.ciphertext, deviceMasterKey);
    const store = new IdentityStore();
    const entries = JSON.parse(decryptedJson);
    store.trustedIdentities = new Map(entries);
    return store;
  }
}

/**
 * Enterprise Double Ratchet Session State Machine
 * Features Automated Continuous DH Turn-Taking, Directional Chain Separation, 256-bit SHA Fingerprints & Bounded Replay Cache.
 */
export class DoubleRatchetSession {
  constructor({
    rootKey,
    sendingChainKey,
    receivingChainKey,
    localDhKeypair,
    remoteDhPublicKey,
    role = 'initiator'
  }) {
    this.rootKey = rootKey;
    this.sendingChainKey = sendingChainKey;
    this.receivingChainKey = receivingChainKey;
    this.localDhKeypair = localDhKeypair;
    this.remoteDhPublicKey = remoteDhPublicKey;
    this.role = role;
    this.messageNumber = 0;
    this.previousChainLength = 0;
    this.recvMessageNumber = 0;
    this.dhRatchetTurnPending = false; // Trigger for auto local DH rotation upon remote DH receipt
    this.consumedMessageKeys = new Map(); // Bounded Replay Cache: Key -> Timestamp
    this.maxConsumedKeys = 5000;
    this.skippedMessageKeys = new Map();  // Key: `${dhFingerprint}:${messageNumber}`, Value: CryptoKey
    this.maxSkip = 1000;
  }

  /**
   * Computes a full 256-bit SHA-256 cryptographic fingerprint for public keys.
   */
  static async getPublicKeyFingerprint(publicKey) {
    const raw = await cryptoSubtle.exportKey('raw', publicKey);
    const hashBuffer = await cryptoSubtle.digest('SHA-256', raw);
    return bytesToBase64(new Uint8Array(hashBuffer));
  }

  /**
   * Computes fingerprint from raw Base64 public key.
   */
  static async getFingerprintFromBase64(pubKeyBase64) {
    const raw = base64ToBytes(pubKeyBase64);
    const hashBuffer = await cryptoSubtle.digest('SHA-256', raw);
    return bytesToBase64(new Uint8Array(hashBuffer));
  }

  /**
   * Records a consumed message key in the bounded replay cache.
   */
  recordConsumedKey(keyId) {
    if (this.consumedMessageKeys.size >= this.maxConsumedKeys) {
      const oldestKey = this.consumedMessageKeys.keys().next().value;
      this.consumedMessageKeys.delete(oldestKey);
    }
    this.consumedMessageKeys.set(keyId, Date.now());
  }

  /**
   * Exports full raw serializable state snapshot including all skipped and consumed key buffers.
   */
  async exportRawSnapshot() {
    const rootRaw = await cryptoSubtle.exportKey('raw', this.rootKey);
    const sendRaw = await cryptoSubtle.exportKey('raw', this.sendingChainKey);
    const recvRaw = await cryptoSubtle.exportKey('raw', this.receivingChainKey);
    const dhPrivRaw = await cryptoSubtle.exportKey('pkcs8', this.localDhKeypair.privateKey);
    const dhPubRaw = await cryptoSubtle.exportKey('raw', this.localDhKeypair.publicKey);
    const remotePubRaw = await cryptoSubtle.exportKey('raw', this.remoteDhPublicKey);

    // Export all skipped message keys as raw Base64 bytes
    const exportedSkippedKeys = [];
    for (const [keyId, cryptoKey] of this.skippedMessageKeys.entries()) {
      const rawKey = await cryptoSubtle.exportKey('raw', cryptoKey);
      exportedSkippedKeys.push([keyId, bytesToBase64(new Uint8Array(rawKey))]);
    }

    return {
      rootKey: bytesToBase64(new Uint8Array(rootRaw)),
      sendingChainKey: bytesToBase64(new Uint8Array(sendRaw)),
      receivingChainKey: bytesToBase64(new Uint8Array(recvRaw)),
      localDhPrivateKey: bytesToBase64(new Uint8Array(dhPrivRaw)),
      localDhPublicKey: bytesToBase64(new Uint8Array(dhPubRaw)),
      remoteDhPublicKey: bytesToBase64(new Uint8Array(remotePubRaw)),
      role: this.role,
      messageNumber: this.messageNumber,
      previousChainLength: this.previousChainLength,
      recvMessageNumber: this.recvMessageNumber,
      dhRatchetTurnPending: this.dhRatchetTurnPending,
      skippedKeysEntries: exportedSkippedKeys,
      consumedKeysEntries: Array.from(this.consumedMessageKeys.entries())
    };
  }

  /**
   * Exports an encrypted, tamper-proof session snapshot sealed with device master key.
   * Includes Monotonic Versioning and AAD binding to prevent Snapshot Replay / Rollback attacks.
   */
  async exportEncryptedSnapshot(deviceStorageKey, monotonicVersion = 1) {
    const rawState = await this.exportRawSnapshot();
    const jsonPayload = JSON.stringify(rawState);
    
    const aad = new Uint8Array(8);
    new DataView(aad.buffer).setBigUint64(0, BigInt(monotonicVersion), false);

    const encrypted = await TruplesCryptoCore.encryptPayload(jsonPayload, deviceStorageKey, aad);
    return { ...encrypted, version: monotonicVersion };
  }

  /**
   * Restores a session from an encrypted snapshot with master device key validation and anti-rollback verification.
   */
  static async restoreFromEncryptedSnapshot(encryptedSnapshot, deviceStorageKey, persistentEnclave, sessionId) {
    if (persistentEnclave && sessionId) {
      const highestVersion = persistentEnclave.getHighestVersion(sessionId);
      if (encryptedSnapshot.version < highestVersion) {
        throw new Error('Anti-Rollback Replay Attack Detected: Snapshot version is older than highest accepted counter in secure enclave.');
      }
      persistentEnclave.setHighestVersion(sessionId, encryptedSnapshot.version);
    }

    const aad = new Uint8Array(8);
    new DataView(aad.buffer).setBigUint64(0, BigInt(encryptedSnapshot.version), false);

    const decryptedJson = await TruplesCryptoCore.decryptPayload(
      encryptedSnapshot.iv,
      encryptedSnapshot.ciphertext,
      deviceStorageKey,
      aad
    );

    const snapshot = JSON.parse(decryptedJson);
    return await DoubleRatchetSession.restoreFromSnapshot(snapshot);
  }

  /**
   * Restores a session from a raw snapshot object including skipped and consumed key states.
   */
  static async restoreFromSnapshot(snapshot) {
    const rootKey = await cryptoSubtle.importKey(
      'raw', base64ToBytes(snapshot.rootKey),
      { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign']
    );
    const sendingChainKey = await cryptoSubtle.importKey(
      'raw', base64ToBytes(snapshot.sendingChainKey),
      { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign']
    );
    const receivingChainKey = await cryptoSubtle.importKey(
      'raw', base64ToBytes(snapshot.receivingChainKey),
      { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign']
    );
    const privateKey = await cryptoSubtle.importKey(
      'pkcs8', base64ToBytes(snapshot.localDhPrivateKey),
      { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey', 'deriveBits']
    );
    const publicKey = await cryptoSubtle.importKey(
      'raw', base64ToBytes(snapshot.localDhPublicKey),
      { name: 'ECDH', namedCurve: 'P-384' }, true, []
    );
    const remoteDhPublicKey = await cryptoSubtle.importKey(
      'raw', base64ToBytes(snapshot.remoteDhPublicKey),
      { name: 'ECDH', namedCurve: 'P-384' }, true, []
    );

    const session = new DoubleRatchetSession({
      rootKey,
      sendingChainKey,
      receivingChainKey,
      localDhKeypair: { privateKey, publicKey },
      remoteDhPublicKey,
      role: snapshot.role
    });

    session.messageNumber = snapshot.messageNumber;
    session.previousChainLength = snapshot.previousChainLength;
    session.recvMessageNumber = snapshot.recvMessageNumber;
    session.dhRatchetTurnPending = snapshot.dhRatchetTurnPending;

    // Restore skipped keys
    if (snapshot.skippedKeysEntries && Array.isArray(snapshot.skippedKeysEntries)) {
      for (const [keyId, rawBase64] of snapshot.skippedKeysEntries) {
        const msgKey = await cryptoSubtle.importKey(
          'raw', base64ToBytes(rawBase64),
          { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
        session.skippedMessageKeys.set(keyId, msgKey);
      }
    }

    // Restore consumed keys
    if (snapshot.consumedKeysEntries && Array.isArray(snapshot.consumedKeysEntries)) {
      session.consumedMessageKeys = new Map(snapshot.consumedKeysEntries);
    }

    return session;
  }

  /**
   * Performs an asymmetric DH Ratchet turn on send (Turn-Taking).
   */
  async rotateLocalDhKeypair() {
    this.localDhKeypair = await TruplesCryptoCore.generateECDHKeypair();
    const { newRootKey, newSendingChainKey } = await TruplesCryptoCore.executeDhRatchetStep(
      this.rootKey,
      this.localDhKeypair.privateKey,
      this.remoteDhPublicKey,
      this.role
    );
    this.rootKey = newRootKey;
    this.sendingChainKey = newSendingChainKey;
    this.previousChainLength = this.messageNumber;
    this.messageNumber = 0;
    this.dhRatchetTurnPending = false;
  }

  /**
   * Sends an encrypted message. Automatically performs local DH keypair rotation if an inbound DH turn was received.
   */
  async send(plaintext) {
    if (this.dhRatchetTurnPending) {
      await this.rotateLocalDhKeypair();
    }

    const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.sendingChainKey);
    this.sendingChainKey = nextChainKey;

    const rawLocalDhPub = await cryptoSubtle.exportKey('raw', this.localDhKeypair.publicKey);
    const header = {
      dhPublicKey: bytesToBase64(new Uint8Array(rawLocalDhPub)),
      previousChainLength: this.previousChainLength,
      messageNumber: this.messageNumber++
    };

    const aad = canonicalEncodeHeader(header);
    const encrypted = await TruplesCryptoCore.encryptPayload(plaintext, messageKey, aad);
    return { header, ...encrypted, seq: header.messageNumber };
  }

  /**
   * Receives and decrypts a Double Ratchet message with AAD header authentication, replay rejection, and automatic DH ratchets.
   */
  async receive(header, iv, ciphertext) {
    const aad = canonicalEncodeHeader(header);
    const remoteDhFingerprint = await DoubleRatchetSession.getFingerprintFromBase64(header.dhPublicKey);
    const keyId = `${remoteDhFingerprint}:${header.messageNumber}`;

    if (this.consumedMessageKeys.has(keyId)) {
      throw new Error('Replay Attack Detected: Message key already consumed');
    }

    if (this.skippedMessageKeys.has(keyId)) {
      const messageKey = this.skippedMessageKeys.get(keyId);
      const plaintext = await TruplesCryptoCore.decryptPayload(iv, ciphertext, messageKey, aad);
      this.skippedMessageKeys.delete(keyId);
      this.recordConsumedKey(keyId);
      return plaintext;
    }

    const backupState = {
      rootKey: this.rootKey,
      receivingChainKey: this.receivingChainKey,
      remoteDhPublicKey: this.remoteDhPublicKey,
      recvMessageNumber: this.recvMessageNumber,
      dhRatchetTurnPending: this.dhRatchetTurnPending,
      skippedKeysEntries: Array.from(this.skippedMessageKeys.entries())
    };

    try {
      const remoteDhKeyBytes = base64ToBytes(header.dhPublicKey);
      const currentRemoteFingerprint = this.remoteDhPublicKey 
        ? await DoubleRatchetSession.getPublicKeyFingerprint(this.remoteDhPublicKey) 
        : null;

      if (remoteDhFingerprint !== currentRemoteFingerprint) {
        if (this.receivingChainKey) {
          while (this.recvMessageNumber < header.previousChainLength) {
            if (this.skippedMessageKeys.size >= this.maxSkip) throw new Error('Skipped keys limit exceeded');
            const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.receivingChainKey);
            this.receivingChainKey = nextChainKey;
            this.skippedMessageKeys.set(`${currentRemoteFingerprint}:${this.recvMessageNumber++}`, messageKey);
          }
        }

        this.remoteDhPublicKey = await cryptoSubtle.importKey(
          'raw',
          remoteDhKeyBytes,
          { name: 'ECDH', namedCurve: 'P-384' },
          true,
          []
        );

        const { newRootKey, newReceivingChainKey } = await TruplesCryptoCore.executeDhRatchetStep(
          this.rootKey,
          this.localDhKeypair.privateKey,
          this.remoteDhPublicKey,
          this.role
        );
        this.rootKey = newRootKey;
        this.receivingChainKey = newReceivingChainKey;
        this.recvMessageNumber = 0;
        this.dhRatchetTurnPending = true;
      }

      while (this.recvMessageNumber < header.messageNumber) {
        if (this.skippedMessageKeys.size >= this.maxSkip) throw new Error('Skipped keys limit exceeded');
        const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.receivingChainKey);
        this.receivingChainKey = nextChainKey;
        this.skippedMessageKeys.set(`${remoteDhFingerprint}:${this.recvMessageNumber++}`, messageKey);
      }

      const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.receivingChainKey);
      this.receivingChainKey = nextChainKey;
      this.recvMessageNumber++;

      const plaintext = await TruplesCryptoCore.decryptPayload(iv, ciphertext, messageKey, aad);
      this.recordConsumedKey(keyId);
      return plaintext;
    } catch (err) {
      this.rootKey = backupState.rootKey;
      this.receivingChainKey = backupState.receivingChainKey;
      this.remoteDhPublicKey = backupState.remoteDhPublicKey;
      this.recvMessageNumber = backupState.recvMessageNumber;
      this.dhRatchetTurnPending = backupState.dhRatchetTurnPending;
      this.skippedMessageKeys = new Map(backupState.skippedKeysEntries);
      throw err;
    }
  }
}
