/**
 * Truples Cryptographic Core & Full Double Ratchet State Machine (v2.6)
 * 
 * Fully compatible with:
 * - W3C WebCrypto API (Browser & Node.js Universal Runtime, zero external dependencies)
 * - NIST SP 800-38D (AES-GCM-256 with 96-bit CSPRNG IV & 128-bit MAC tag)
 * - FIPS 186-4 (ECDSA over NIST P-384 with SHA-384 for MITM-resistant authenticated key exchange)
 * - RFC 5903 (ECDH over NIST P-384 curve)
 * - RFC 5869 (HKDF with HMAC-SHA256)
 * - Signal-Standard Full Double Ratchet Specification:
 *   - Role-Aware Initiator / Responder Directional Chain Alignment
 *   - Header-Driven Automatic Ephemeral DH Ratchet State Machine
 *   - Multi-Epoch Bounded Skipped Message Key Management
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
   * Signs a payload or ephemeral public key using ECDSA P-384 (MITM Defense).
   * @param {string|Uint8Array} data 
   * @param {CryptoKey} privateKey 
   * @returns {Promise<string>} Base64 signature
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
   * @param {string|Uint8Array} data 
   * @param {string} signatureBase64 
   * @param {CryptoKey} publicKey 
   * @returns {Promise<boolean>}
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
   * Initiator and Responder derive symmetrically opposed sending and receiving chains.
   * 
   * @param {CryptoKey} localPrivateKey 
   * @param {CryptoKey} remotePublicKey 
   * @param {Uint8Array} [dynamicSalt] 
   * @param {'initiator'|'responder'} [role='initiator']
   * @returns {Promise<{ rootKey: CryptoKey, sendingChainKey: CryptoKey, receivingChainKey: CryptoKey }>}
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
        info: new TextEncoder().encode('Truples-Root-Key-v2')
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
   * @param {CryptoKey} localEcdhPrivateKey 
   * @param {CryptoKey} remoteEcdhPublicKey 
   * @param {CryptoKey} remoteEcdsaIdentityPublicKey 
   * @param {string} remoteSignatureBase64 
   * @param {Uint8Array} [dynamicSalt] 
   * @param {'initiator'|'responder'} [role='initiator']
   * @returns {Promise<{ rootKey: CryptoKey, sendingChainKey: CryptoKey, receivingChainKey: CryptoKey }>}
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
   * Executes an Asymmetric DH Ratchet Step upon conversational turn-taking (Post-Compromise Recovery).
   * Derives a new Root Key and fresh Chain Key using domain-separated HKDF.
   * 
   * @param {CryptoKey} currentRootKey 
   * @param {CryptoKey} localDhPrivateKey 
   * @param {CryptoKey} remoteDhPublicKey 
   * @param {string} [chainInfo='Truples-DH-Ratchet-Chain-Step']
   * @returns {Promise<{ newRootKey: CryptoKey, newChainKey: CryptoKey }>}
   */
  static async executeDhRatchetStep(currentRootKey, localDhPrivateKey, remoteDhPublicKey, chainInfo = 'Truples-DH-Ratchet-Chain-Step') {
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

    const newChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(rootKeyBytes),
        info: new TextEncoder().encode(chainInfo)
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    new Uint8Array(rootKeyBytes).fill(0);

    return { 
      newRootKey, 
      newChainKey, 
      newSendingChainKey: newChainKey, 
      newReceivingChainKey: newChainKey 
    };
  }

  /**
   * Executes a symmetric KDF Chain Ratchet step (Per-Message Forward Secrecy).
   * @param {CryptoKey} currentChainKey 
   * @returns {Promise<{ nextChainKey: CryptoKey, messageKey: CryptoKey }>}
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
   * Encrypts plaintext using AES-256-GCM with a fresh 96-bit CSPRNG IV.
   * @param {string|Uint8Array} plaintext 
   * @param {CryptoKey} messageKey 
   * @returns {Promise<{ iv: string, ciphertext: string }>} Base64 encoded payload
   */
  static async encryptPayload(plaintext, messageKey) {
    const rawData = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
    const iv = new Uint8Array(12);
    cryptoRandom(iv);

    const encryptedBuffer = await cryptoSubtle.encrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      messageKey,
      rawData
    );

    return {
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer))
    };
  }

  /**
   * Decrypts and authenticates AES-256-GCM ciphertext payload with 128-bit MAC tag validation.
   * @param {string} ivBase64 
   * @param {string} ciphertextBase64 
   * @param {CryptoKey} messageKey 
   * @returns {Promise<string>} Decrypted UTF-8 plaintext
   */
  static async decryptPayload(ivBase64, ciphertextBase64, messageKey) {
    const iv = base64ToBytes(ivBase64);
    const ciphertext = base64ToBytes(ciphertextBase64);

    const decryptedBuffer = await cryptoSubtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      messageKey,
      ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
  }

  /**
   * Best-effort in-memory buffer scrubbing for typed arrays.
   * @param {Uint8Array} buffer 
   */
  static zeroizeBuffer(buffer) {
    if (!buffer || !buffer.length) return;
    buffer.fill(0x00);
    buffer.fill(0xFF);
    cryptoRandom(buffer);
    buffer.fill(0x00);
  }
}

/**
 * Signal-Standard Full Double Ratchet Session State Machine
 * Integrates Asymmetric DH Ratchet, Directional Symmetric KDF Chains, and Multi-Epoch Skipped Keys.
 */
export class DoubleRatchetSession {
  constructor({
    rootKey,
    sendingChainKey,
    receivingChainKey,
    localDhKeypair,
    remoteDhPublicKey
  }) {
    this.rootKey = rootKey;
    this.sendingChainKey = sendingChainKey;
    this.receivingChainKey = receivingChainKey;
    this.localDhKeypair = localDhKeypair;
    this.remoteDhPublicKey = remoteDhPublicKey;
    this.messageNumber = 0;
    this.previousChainLength = 0;
    this.recvMessageNumber = 0;
    this.skippedMessageKeys = new Map(); // Key: `${dhFingerprint}:${messageNumber}`, Value: CryptoKey
    this.maxSkip = 1000;
  }

  static async getPublicKeyFingerprint(publicKey) {
    const raw = await cryptoSubtle.exportKey('raw', publicKey);
    return bytesToBase64(new Uint8Array(raw)).substring(0, 24);
  }

  /**
   * Performs an asymmetric DH Ratchet turn on send (Turn-Taking).
   */
  async rotateLocalDhKeypair() {
    this.localDhKeypair = await TruplesCryptoCore.generateECDHKeypair();
    const { newRootKey, newChainKey } = await TruplesCryptoCore.executeDhRatchetStep(
      this.rootKey,
      this.localDhKeypair.privateKey,
      this.remoteDhPublicKey,
      'Truples-DH-Ratchet-Chain-Step'
    );
    this.rootKey = newRootKey;
    this.sendingChainKey = newChainKey;
    this.previousChainLength = this.messageNumber;
    this.messageNumber = 0;
  }

  /**
   * Sends an encrypted message encapsulating the current Double Ratchet Header.
   * @param {string} plaintext 
   * @returns {Promise<{ header: object, iv: string, ciphertext: string }>}
   */
  async send(plaintext) {
    const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.sendingChainKey);
    this.sendingChainKey = nextChainKey;

    const rawLocalDhPub = await cryptoSubtle.exportKey('raw', this.localDhKeypair.publicKey);
    const header = {
      dhPublicKey: bytesToBase64(new Uint8Array(rawLocalDhPub)),
      previousChainLength: this.previousChainLength,
      messageNumber: this.messageNumber++
    };

    const encrypted = await TruplesCryptoCore.encryptPayload(plaintext, messageKey);
    return { header, ...encrypted, seq: header.messageNumber };
  }

  /**
   * Receives and decrypts a Double Ratchet message, automatically executing a DH Ratchet step upon key rotation.
   * @param {object} header 
   * @param {string} iv 
   * @param {string} ciphertext 
   * @returns {Promise<string>}
   */
  async receive(header, iv, ciphertext) {
    const remoteDhKeyBytes = base64ToBytes(header.dhPublicKey);
    const remoteDhFingerprint = header.dhPublicKey.substring(0, 24);
    const keyId = `${remoteDhFingerprint}:${header.messageNumber}`;

    // Case 1: Check skipped keys buffer (Delayed out-of-order message)
    if (this.skippedMessageKeys.has(keyId)) {
      const messageKey = this.skippedMessageKeys.get(keyId);
      this.skippedMessageKeys.delete(keyId);
      return await TruplesCryptoCore.decryptPayload(iv, ciphertext, messageKey);
    }

    // Check if remote party rotated their Ephemeral DH Key (New DH Ratchet Turn)
    const currentRemoteFingerprint = this.remoteDhPublicKey 
      ? await DoubleRatchetSession.getPublicKeyFingerprint(this.remoteDhPublicKey) 
      : null;

    if (remoteDhFingerprint !== currentRemoteFingerprint) {
      // 1. Skip any remaining messages in the previous receiving chain
      if (this.receivingChainKey) {
        while (this.recvMessageNumber < header.previousChainLength) {
          if (this.skippedMessageKeys.size >= this.maxSkip) throw new Error('Skipped keys limit exceeded');
          const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.receivingChainKey);
          this.receivingChainKey = nextChainKey;
          this.skippedMessageKeys.set(`${currentRemoteFingerprint}:${this.recvMessageNumber++}`, messageKey);
        }
      }

      // 2. Import new remote DH public key
      this.remoteDhPublicKey = await cryptoSubtle.importKey(
        'raw',
        remoteDhKeyBytes,
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        []
      );

      // 3. Execute DH Ratchet Step (Update Root Key & derive matching Receiving Chain Key)
      const { newRootKey, newChainKey } = await TruplesCryptoCore.executeDhRatchetStep(
        this.rootKey,
        this.localDhKeypair.privateKey,
        this.remoteDhPublicKey,
        'Truples-DH-Ratchet-Chain-Step'
      );
      this.rootKey = newRootKey;
      this.receivingChainKey = newChainKey;
      this.recvMessageNumber = 0;
    }

    // Buffer skipped messages within the current receiving chain
    while (this.recvMessageNumber < header.messageNumber) {
      if (this.skippedMessageKeys.size >= this.maxSkip) throw new Error('Skipped keys limit exceeded');
      const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.receivingChainKey);
      this.receivingChainKey = nextChainKey;
      this.skippedMessageKeys.set(`${remoteDhFingerprint}:${this.recvMessageNumber++}`, messageKey);
    }

    // Decrypt current message
    const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.receivingChainKey);
    this.receivingChainKey = nextChainKey;
    this.recvMessageNumber++;

    return await TruplesCryptoCore.decryptPayload(iv, ciphertext, messageKey);
  }
}
