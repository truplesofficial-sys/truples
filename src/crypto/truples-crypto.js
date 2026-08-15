/**
 * Truples Cryptographic Core Reference Implementation (v2.5)
 * 
 * Fully compatible with:
 * - W3C WebCrypto API (Browser & Node.js Universal Runtime, zero external dependencies)
 * - NIST SP 800-38D (AES-GCM-256 with 96-bit CSPRNG IV & 128-bit MAC tag)
 * - FIPS 186-4 (ECDSA over NIST P-384 with SHA-384 for MITM-resistant authenticated key exchange)
 * - RFC 5903 (ECDH over NIST P-384 curve)
 * - RFC 5869 (HKDF with HMAC-SHA256)
 * - Full Bidirectional Double Ratchet Core with Out-of-Order Skipped Message Key Handling
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
   * Derives root and initial bidirectional chain keys using HKDF-SHA256 with dynamic CSPRNG salt.
   * @param {CryptoKey} localPrivateKey 
   * @param {CryptoKey} remotePublicKey 
   * @param {Uint8Array} [dynamicSalt] 
   * @returns {Promise<{ rootKey: CryptoKey, sendingChainKey: CryptoKey, receivingChainKey: CryptoKey }>}
   */
  static async deriveRootAndChainKeys(localPrivateKey, remotePublicKey, dynamicSalt) {
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

    const sendingChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('Truples-Sending-Chain-Key-v2')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    const receivingChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('Truples-Receiving-Chain-Key-v2')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    return { rootKey, sendingChainKey, receivingChainKey, chainKey: sendingChainKey };
  }

  /**
   * Executes a MITM-resistant Authenticated Key Exchange (ECDH + ECDSA Identity Verification).
   * @param {CryptoKey} localEcdhPrivateKey 
   * @param {CryptoKey} remoteEcdhPublicKey 
   * @param {CryptoKey} remoteEcdsaIdentityPublicKey 
   * @param {string} remoteSignatureBase64 
   * @param {Uint8Array} [dynamicSalt] 
   * @returns {Promise<{ rootKey: CryptoKey, sendingChainKey: CryptoKey, receivingChainKey: CryptoKey }>}
   */
  static async deriveAuthenticatedRootAndChainKeys(
    localEcdhPrivateKey,
    remoteEcdhPublicKey,
    remoteEcdsaIdentityPublicKey,
    remoteSignatureBase64,
    dynamicSalt
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

    return await this.deriveRootAndChainKeys(localEcdhPrivateKey, remoteEcdhPublicKey, dynamicSalt);
  }

  /**
   * Executes an Asymmetric DH Ratchet Step upon conversational turn-taking (Post-Compromise Recovery).
   * Derives a new Root Key and fresh bidirectional Sending/Receiving Chain Keys.
   * 
   * @param {CryptoKey} currentRootKey 
   * @param {CryptoKey} localNewEcdhPrivateKey 
   * @param {CryptoKey} remoteNewEcdhPublicKey 
   * @returns {Promise<{ newRootKey: CryptoKey, newSendingChainKey: CryptoKey, newReceivingChainKey: CryptoKey, newChainKey: CryptoKey }>}
   */
  static async executeDhRatchetStep(currentRootKey, localNewEcdhPrivateKey, remoteNewEcdhPublicKey) {
    // 1. Calculate new ephemeral DH shared secret
    const newSharedBits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: remoteNewEcdhPublicKey },
      localNewEcdhPrivateKey,
      384
    );

    // 2. Export current root key bytes to act as HKDF salt
    const rootKeyBytes = await cryptoSubtle.exportKey('raw', currentRootKey);

    const hkdfKey = await cryptoSubtle.importKey(
      'raw',
      newSharedBits,
      { name: 'HKDF' },
      false,
      ['deriveKey', 'deriveBits']
    );

    new Uint8Array(newSharedBits).fill(0);

    // 3. Derive advanced Root Key
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

    // 4. Derive fresh Sending Chain Key
    const newSendingChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(rootKeyBytes),
        info: new TextEncoder().encode('Truples-DH-Ratchet-Send-Chain')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    // 5. Derive fresh Receiving Chain Key
    const newReceivingChainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(rootKeyBytes),
        info: new TextEncoder().encode('Truples-DH-Ratchet-Recv-Chain')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    new Uint8Array(rootKeyBytes).fill(0);

    return { 
      newRootKey, 
      newSendingChainKey, 
      newReceivingChainKey, 
      newChainKey: newSendingChainKey 
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
   * Note: JS runtimes with garbage collectors cannot guarantee elimination of immutable string copies.
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
 * Double Ratchet Session Manager with Out-of-Order Skipped Message Key Handling.
 */
export class DoubleRatchetSession {
  constructor(rootKey, sendingChainKey, receivingChainKey) {
    this.rootKey = rootKey;
    this.sendingChainKey = sendingChainKey;
    this.receivingChainKey = receivingChainKey;
    this.sendSequence = 0;
    this.recvSequence = 0;
    this.skippedMessageKeys = new Map(); // Key: messageSeq, Value: CryptoKey (MessageKey)
    this.maxSkip = 1000;
  }

  async send(plaintext) {
    const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.sendingChainKey);
    this.sendingChainKey = nextChainKey;
    const seq = this.sendSequence++;
    const encrypted = await TruplesCryptoCore.encryptPayload(plaintext, messageKey);
    return { ...encrypted, seq };
  }

  async receive(iv, ciphertext, seq) {
    // Case 1: Key already in skipped keys buffer (delayed out-of-order message arrival)
    if (this.skippedMessageKeys.has(seq)) {
      const messageKey = this.skippedMessageKeys.get(seq);
      this.skippedMessageKeys.delete(seq);
      return await TruplesCryptoCore.decryptPayload(iv, ciphertext, messageKey);
    }

    // Case 2: In-order or future out-of-order message
    if (seq >= this.recvSequence) {
      // Ratchet forward and buffer intermediate skipped keys
      while (this.recvSequence < seq) {
        if (this.skippedMessageKeys.size >= this.maxSkip) {
          throw new Error('Skipped message keys limit exceeded');
        }
        const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.receivingChainKey);
        this.receivingChainKey = nextChainKey;
        this.skippedMessageKeys.set(this.recvSequence++, messageKey);
      }

      // Ratchet to current message key
      const { nextChainKey, messageKey } = await TruplesCryptoCore.ratchetMessageKey(this.receivingChainKey);
      this.receivingChainKey = nextChainKey;
      this.recvSequence++;
      return await TruplesCryptoCore.decryptPayload(iv, ciphertext, messageKey);
    }

    throw new Error('Duplicate or expired message key');
  }
}
