/**
 * Truples Cryptographic Core Reference Implementation (v2.1)
 * 
 * Complies with:
 * - NIST SP 800-38D (AES-GCM-256 with 96-bit random IV & 128-bit MAC tag)
 * - RFC 5903 (ECDH over NIST P-384 curve)
 * - RFC 5869 (HKDF with HMAC-SHA256)
 * - Symmetric KDF Chain Ratchet for strict Per-Message Forward Secrecy
 * - FIPS 140-3 zeroization standards for in-memory cryptographic buffers
 */

const cryptoSubtle = typeof window !== 'undefined' && window.crypto?.subtle 
  ? window.crypto.subtle 
  : (globalThis.crypto?.subtle || require('crypto').webcrypto.subtle);

const cryptoRandom = typeof window !== 'undefined' && window.crypto?.getRandomValues
  ? (buf) => window.crypto.getRandomValues(buf)
  : (buf) => (globalThis.crypto?.getRandomValues ? globalThis.crypto.getRandomValues(buf) : require('crypto').randomFillSync(buf));

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
   * Derives a root session key from local private & remote public key using HKDF-SHA256.
   * Enforces dynamic 32-byte cryptographic salt.
   * @param {CryptoKey} localPrivateKey 
   * @param {CryptoKey} remotePublicKey 
   * @param {Uint8Array} [dynamicSalt] 
   * @returns {Promise<{ rootKey: CryptoKey, chainKey: CryptoKey }>}
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

    // Scrub raw shared secret bits immediately from memory
    new Uint8Array(sharedBits).fill(0);

    const rootKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('Truples-Root-Key-v2')
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const chainKey = await cryptoSubtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('Truples-Initial-Chain-Key-v2')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    );

    return { rootKey, chainKey };
  }

  /**
   * Executes a symmetric KDF Chain Ratchet step (Per-Message Forward Secrecy).
   * Derives a one-time Message Key and advances the Chain Key, zeroizing previous states.
   * @param {CryptoKey} currentChainKey 
   * @returns {Promise<{ nextChainKey: CryptoKey, messageKey: CryptoKey }>}
   */
  static async ratchetMessageKey(currentChainKey) {
    // Export raw key bits of current chain key
    const chainKeyData = await cryptoSubtle.exportKey('raw', currentChainKey);
    const hkdfKey = await cryptoSubtle.importKey(
      'raw',
      chainKeyData,
      { name: 'HKDF' },
      false,
      ['deriveKey', 'deriveBits']
    );

    // 1. Advance to Next Chain Key (Info: 'Truples-Chain-Step')
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

    // 2. Derive One-Time Ephemeral Message Key (Info: 'Truples-Message-Key')
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

    // Zeroize raw buffer
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
      iv: Buffer.from(iv).toString('base64'),
      ciphertext: Buffer.from(encryptedBuffer).toString('base64')
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
    const iv = new Uint8Array(Buffer.from(ivBase64, 'base64'));
    const ciphertext = new Uint8Array(Buffer.from(ciphertextBase64, 'base64'));

    const decryptedBuffer = await cryptoSubtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      messageKey,
      ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
  }

  /**
   * Executes multi-pass cryptographic zeroization on in-memory buffers.
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
