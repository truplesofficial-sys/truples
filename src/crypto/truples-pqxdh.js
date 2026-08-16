/**
 * Truples Signal PQXDH (Hybrid Post-Quantum Extended Diffie-Hellman) Protocol State Machine
 * 
 * Complies with:
 * - Signal PQXDH Specification (Post-Quantum Extended Diffie-Hellman Initial Key Agreement)
 * - NIST FIPS 203 ML-KEM-768 (Kyber-768) + NIST P-384 ECDH Hybrid Construction
 * - Mutual Identity Authentication via FIPS 186-4 ECDSA P-384 Signatures
 * - Zero-Dependency Universal WebCrypto & Node.js Runtime Interoperability
 * - Seamless Initialization of Truples Enterprise Double Ratchet Sessions
 */

import { TruplesPQKEM } from './truples-pqkem.js';
import { TruplesCryptoCore, DoubleRatchetSession } from './truples-crypto.js';

const cryptoSubtle = typeof window !== 'undefined' && window.crypto?.subtle 
  ? window.crypto.subtle 
  : (globalThis.crypto?.subtle || require('crypto').webcrypto.subtle);

const cryptoRandom = typeof window !== 'undefined' && window.crypto?.getRandomValues
  ? (buf) => window.crypto.getRandomValues(buf)
  : (buf) => (globalThis.crypto?.getRandomValues ? globalThis.crypto.getRandomValues(buf) : require('crypto').randomFillSync(buf));

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
 * Prekey Bundle representing a recipient's published cryptographic prekeys.
 */
class PrekeyBundle {
  constructor({
    identityKey,
    signedPrekey,
    signedPrekeySignature,
    pqSignedPrekey,
    pqSignedPrekeySignature,
    oneTimePrekey = null,
    oneTimePrekeyId = null,
    pqOneTimePrekey = null,
    pqOneTimePrekeyId = null
  }) {
    this.identityKey = identityKey; // Base64 P-384 ECDSA
    this.signedPrekey = signedPrekey; // Base64 P-384 ECDH
    this.signedPrekeySignature = signedPrekeySignature; // Base64 ECDSA Sig
    this.pqSignedPrekey = pqSignedPrekey; // Base64 ML-KEM-768 public key (1184 bytes)
    this.pqSignedPrekeySignature = pqSignedPrekeySignature; // Base64 ECDSA Sig over PQSPK
    this.oneTimePrekey = oneTimePrekey; // Optional Base64 P-384 ECDH
    this.oneTimePrekeyId = oneTimePrekeyId;
    this.pqOneTimePrekey = pqOneTimePrekey; // Optional Base64 ML-KEM-768 public key
    this.pqOneTimePrekeyId = pqOneTimePrekeyId;
  }
}

/**
 * Encapsulated Handshake Message sent by the initiator to establish the PQXDH session.
 */
class PQXDHHandshakeMessage {
  constructor({
    initiatorIdentityKey,
    ephemeralKey,
    pqCiphertext,
    pqOneTimeCiphertext = null,
    oneTimePrekeyId = null,
    pqOneTimePrekeyId = null,
    initialMessage = null
  }) {
    this.initiatorIdentityKey = initiatorIdentityKey; // Base64 P-384 ECDSA
    this.ephemeralKey = ephemeralKey; // Base64 P-384 ECDH
    this.pqCiphertext = pqCiphertext; // Base64 ML-KEM-768 ciphertext (1088 bytes)
    this.pqOneTimeCiphertext = pqOneTimeCiphertext;
    this.oneTimePrekeyId = oneTimePrekeyId;
    this.pqOneTimePrekeyId = pqOneTimePrekeyId;
    this.initialMessage = initialMessage; // Initial encrypted message payload
  }
}

class TruplesPQXDH {
  /**
   * Generates a complete Prekey Bundle for a responder party.
   */
  static async createPrekeyBundle({
    identityKeypair,
    signedPrekeyKeypair,
    pqSignedPrekeyKeypair,
    oneTimePrekeyKeypair = null,
    oneTimePrekeyId = null,
    pqOneTimePrekeyKeypair = null,
    pqOneTimePrekeyId = null
  }) {
    // 1. Export raw keys
    const rawIdentityPub = await cryptoSubtle.exportKey('raw', identityKeypair.publicKey);
    const rawSpkPub = await cryptoSubtle.exportKey('raw', signedPrekeyKeypair.publicKey);

    // 2. Sign classical signed prekey
    const spkSignature = await TruplesCryptoCore.signPayload(new Uint8Array(rawSpkPub), identityKeypair.privateKey);

    // 3. Sign post-quantum signed prekey
    const pqSpkSignature = await TruplesCryptoCore.signPayload(pqSignedPrekeyKeypair.publicKey, identityKeypair.privateKey);

    let rawOpkPub = null;
    if (oneTimePrekeyKeypair) {
      rawOpkPub = await cryptoSubtle.exportKey('raw', oneTimePrekeyKeypair.publicKey);
    }

    return new PrekeyBundle({
      identityKey: bytesToBase64(new Uint8Array(rawIdentityPub)),
      signedPrekey: bytesToBase64(new Uint8Array(rawSpkPub)),
      signedPrekeySignature: spkSignature,
      pqSignedPrekey: bytesToBase64(pqSignedPrekeyKeypair.publicKey),
      pqSignedPrekeySignature: pqSpkSignature,
      oneTimePrekey: rawOpkPub ? bytesToBase64(new Uint8Array(rawOpkPub)) : null,
      oneTimePrekeyId,
      pqOneTimePrekey: pqOneTimePrekeyKeypair ? bytesToBase64(pqOneTimePrekeyKeypair.publicKey) : null,
      pqOneTimePrekeyId
    });
  }

  /**
   * Initiator (Alice) executes PQXDH Handshake to recipient (Bob).
   */
  static async initiateHandshake({
    initiatorIdentityKeypair,
    recipientBundle,
    initialPlaintext = null
  }) {
    // 1. Import recipient identity key (P-384 ECDSA)
    const recipientIdentityKey = await cryptoSubtle.importKey(
      'raw',
      base64ToBytes(recipientBundle.identityKey),
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['verify']
    );

    // 2. Verify classical SPK signature
    const spkBytes = base64ToBytes(recipientBundle.signedPrekey);
    const isSpkValid = await TruplesCryptoCore.verifySignature(
      spkBytes,
      recipientBundle.signedPrekeySignature,
      recipientIdentityKey
    );
    if (!isSpkValid) {
      throw new Error('PQXDH Handshake Aborted: Recipient Signed Prekey signature verification failed.');
    }

    // 3. Verify post-quantum SPK signature
    const pqSpkBytes = base64ToBytes(recipientBundle.pqSignedPrekey);
    const isPqSpkValid = await TruplesCryptoCore.verifySignature(
      pqSpkBytes,
      recipientBundle.pqSignedPrekeySignature,
      recipientIdentityKey
    );
    if (!isPqSpkValid) {
      throw new Error('PQXDH Handshake Aborted: Recipient Post-Quantum Signed Prekey signature verification failed.');
    }

    // 4. Import recipient SPK (P-384 ECDH) and Identity (P-384 ECDH equivalent for DH2)
    const recipientSpk = await cryptoSubtle.importKey(
      'raw',
      spkBytes,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );

    const recipientIdentityEcdh = await cryptoSubtle.importKey(
      'raw',
      base64ToBytes(recipientBundle.identityKey),
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );

    // 5. Generate Alice's ephemeral keypair EK_A (P-384 ECDH)
    const ephemeralKeypair = await TruplesCryptoCore.generateECDHKeypair();

    // 6. Alice identity ECDH key (for DH1)
    const aliceIdentityPkcs8 = await cryptoSubtle.exportKey('pkcs8', initiatorIdentityKeypair.privateKey);
    const aliceIdentityEcdhPriv = await cryptoSubtle.importKey(
      'pkcs8',
      aliceIdentityPkcs8,
      { name: 'ECDH', namedCurve: 'P-384' },
      false,
      ['deriveBits']
    );

    // 7. Compute Classical ECDH Shared Secrets:
    // DH1 = ECDH(IK_A, SPK_B)
    const dh1Bits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: recipientSpk },
      aliceIdentityEcdhPriv,
      384
    );

    // DH2 = ECDH(EK_A, IK_B)
    const dh2Bits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: recipientIdentityEcdh },
      ephemeralKeypair.privateKey,
      384
    );

    // DH3 = ECDH(EK_A, SPK_B)
    const dh3Bits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: recipientSpk },
      ephemeralKeypair.privateKey,
      384
    );

    // DH4 = ECDH(EK_A, OPK_B) if present
    let dh4Bits = null;
    if (recipientBundle.oneTimePrekey) {
      const recipientOpk = await cryptoSubtle.importKey(
        'raw',
        base64ToBytes(recipientBundle.oneTimePrekey),
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        []
      );
      dh4Bits = await cryptoSubtle.deriveBits(
        { name: 'ECDH', public: recipientOpk },
        ephemeralKeypair.privateKey,
        384
      );
    }

    // 8. Execute ML-KEM-768 Post-Quantum Encapsulation
    const { ciphertext: pqCiphertext, sharedSecret: pqSharedSecret } = await TruplesPQKEM.encapsulate(pqSpkBytes);

    let pqOneTimeCiphertext = null;
    let pqOneTimeSharedSecret = null;
    if (recipientBundle.pqOneTimePrekey) {
      const pqOpkBytes = base64ToBytes(recipientBundle.pqOneTimePrekey);
      const res = await TruplesPQKEM.encapsulate(pqOpkBytes);
      pqOneTimeCiphertext = res.ciphertext;
      pqOneTimeSharedSecret = res.sharedSecret;
    }

    // 9. Combine Hybrid Keying Material (IKM):
    // IKM = DH1 (48B) || DH2 (48B) || DH3 (48B) [|| DH4 (48B)] || ss_pq (32B) [|| ss_pq_opk (32B)]
    const dh1Bytes = new Uint8Array(dh1Bits);
    const dh2Bytes = new Uint8Array(dh2Bits);
    const dh3Bytes = new Uint8Array(dh3Bits);
    const dh4Bytes = dh4Bits ? new Uint8Array(dh4Bits) : null;

    const totalLen = dh1Bytes.length + dh2Bytes.length + dh3Bytes.length + 
      (dh4Bytes ? dh4Bytes.length : 0) + 
      pqSharedSecret.length + 
      (pqOneTimeSharedSecret ? pqOneTimeSharedSecret.length : 0);

    const ikm = new Uint8Array(totalLen);
    let ikmOffset = 0;
    ikm.set(dh1Bytes, ikmOffset); ikmOffset += dh1Bytes.length;
    ikm.set(dh2Bytes, ikmOffset); ikmOffset += dh2Bytes.length;
    ikm.set(dh3Bytes, ikmOffset); ikmOffset += dh3Bytes.length;
    if (dh4Bytes) {
      ikm.set(dh4Bytes, ikmOffset); ikmOffset += dh4Bytes.length;
    }
    ikm.set(pqSharedSecret, ikmOffset); ikmOffset += pqSharedSecret.length;
    if (pqOneTimeSharedSecret) {
      ikm.set(pqOneTimeSharedSecret, ikmOffset); ikmOffset += pqOneTimeSharedSecret.length;
    }

    // 10. Derive Hybrid Master Secret via HKDF-SHA256
    const hkdfKey = await cryptoSubtle.importKey(
      'raw',
      ikm,
      { name: 'HKDF' },
      false,
      ['deriveKey', 'deriveBits']
    );

    TruplesCryptoCore.zeroizeBuffer(ikm);

    const salt = new TextEncoder().encode('Truples-PQXDH-v1-Salt');

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

    const sendingChainKey = await cryptoSubtle.deriveKey(
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

    const receivingChainKey = await cryptoSubtle.deriveKey(
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

    // 11. Initialize Double Ratchet Session
    const session = new DoubleRatchetSession({
      rootKey,
      sendingChainKey,
      receivingChainKey,
      localDhKeypair: ephemeralKeypair,
      remoteDhPublicKey: recipientSpk,
      role: 'initiator'
    });

    // 12. Send initial encrypted message if provided
    let initialMessage = null;
    if (initialPlaintext) {
      initialMessage = await session.send(initialPlaintext);
    }

    const rawAliceIdentity = await cryptoSubtle.exportKey('raw', initiatorIdentityKeypair.publicKey);
    const rawAliceEphemeral = await cryptoSubtle.exportKey('raw', ephemeralKeypair.publicKey);

    const handshakeMessage = new PQXDHHandshakeMessage({
      initiatorIdentityKey: bytesToBase64(new Uint8Array(rawAliceIdentity)),
      ephemeralKey: bytesToBase64(new Uint8Array(rawAliceEphemeral)),
      pqCiphertext: bytesToBase64(pqCiphertext),
      pqOneTimeCiphertext: pqOneTimeCiphertext ? bytesToBase64(pqOneTimeCiphertext) : null,
      oneTimePrekeyId: recipientBundle.oneTimePrekeyId,
      pqOneTimePrekeyId: recipientBundle.pqOneTimePrekeyId,
      initialMessage
    });

    return { session, handshakeMessage };
  }

  /**
   * Responder (Bob) processes PQXDH Handshake Message and establishes session.
   */
  static async respondHandshake({
    responderIdentityKeypair,
    signedPrekeyKeypair,
    pqSignedPrekeyKeypair,
    oneTimePrekeyKeypair = null,
    pqOneTimePrekeyKeypair = null,
    handshakeMessage
  }) {
    // 1. Import Initiator Identity (P-384 ECDSA / ECDH) & Ephemeral (P-384 ECDH)
    const initiatorIdentityEcdsa = await cryptoSubtle.importKey(
      'raw',
      base64ToBytes(handshakeMessage.initiatorIdentityKey),
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['verify']
    );

    const initiatorIdentityEcdh = await cryptoSubtle.importKey(
      'raw',
      base64ToBytes(handshakeMessage.initiatorIdentityKey),
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );

    const initiatorEphemeralEcdh = await cryptoSubtle.importKey(
      'raw',
      base64ToBytes(handshakeMessage.ephemeralKey),
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );

    // 2. Responder Identity ECDH Priv (for DH2)
    const responderIdentityPkcs8 = await cryptoSubtle.exportKey('pkcs8', responderIdentityKeypair.privateKey);
    const responderIdentityEcdhPriv = await cryptoSubtle.importKey(
      'pkcs8',
      responderIdentityPkcs8,
      { name: 'ECDH', namedCurve: 'P-384' },
      false,
      ['deriveBits']
    );

    // 3. Compute matching Classical ECDH Shared Secrets:
    // DH1 = ECDH(SPK_B, IK_A)
    const dh1Bits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: initiatorIdentityEcdh },
      signedPrekeyKeypair.privateKey,
      384
    );

    // DH2 = ECDH(IK_B, EK_A)
    const dh2Bits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: initiatorEphemeralEcdh },
      responderIdentityEcdhPriv,
      384
    );

    // DH3 = ECDH(SPK_B, EK_A)
    const dh3Bits = await cryptoSubtle.deriveBits(
      { name: 'ECDH', public: initiatorEphemeralEcdh },
      signedPrekeyKeypair.privateKey,
      384
    );

    // DH4 = ECDH(OPK_B, EK_A) if OPK was used
    let dh4Bits = null;
    if (oneTimePrekeyKeypair && handshakeMessage.oneTimePrekeyId !== null) {
      dh4Bits = await cryptoSubtle.deriveBits(
        { name: 'ECDH', public: initiatorEphemeralEcdh },
        oneTimePrekeyKeypair.privateKey,
        384
      );
    }

    // 4. ML-KEM-768 Post-Quantum Decapsulation
    const pqCiphertextBytes = base64ToBytes(handshakeMessage.pqCiphertext);
    const pqSharedSecret = await TruplesPQKEM.decapsulate(pqCiphertextBytes, pqSignedPrekeyKeypair.privateKey);

    let pqOneTimeSharedSecret = null;
    if (pqOneTimePrekeyKeypair && handshakeMessage.pqOneTimeCiphertext) {
      const pqOpkCtBytes = base64ToBytes(handshakeMessage.pqOneTimeCiphertext);
      pqOneTimeSharedSecret = await TruplesPQKEM.decapsulate(pqOpkCtBytes, pqOneTimePrekeyKeypair.privateKey);
    }

    // 5. Combine Hybrid Keying Material (IKM)
    const dh1Bytes = new Uint8Array(dh1Bits);
    const dh2Bytes = new Uint8Array(dh2Bits);
    const dh3Bytes = new Uint8Array(dh3Bits);
    const dh4Bytes = dh4Bits ? new Uint8Array(dh4Bits) : null;

    const totalLen = dh1Bytes.length + dh2Bytes.length + dh3Bytes.length + 
      (dh4Bytes ? dh4Bytes.length : 0) + 
      pqSharedSecret.length + 
      (pqOneTimeSharedSecret ? pqOneTimeSharedSecret.length : 0);

    const ikm = new Uint8Array(totalLen);
    let ikmOffset = 0;
    ikm.set(dh1Bytes, ikmOffset); ikmOffset += dh1Bytes.length;
    ikm.set(dh2Bytes, ikmOffset); ikmOffset += dh2Bytes.length;
    ikm.set(dh3Bytes, ikmOffset); ikmOffset += dh3Bytes.length;
    if (dh4Bytes) {
      ikm.set(dh4Bytes, ikmOffset); ikmOffset += dh4Bytes.length;
    }
    ikm.set(pqSharedSecret, ikmOffset); ikmOffset += pqSharedSecret.length;
    if (pqOneTimeSharedSecret) {
      ikm.set(pqOneTimeSharedSecret, ikmOffset); ikmOffset += pqOneTimeSharedSecret.length;
    }

    // 6. Derive identical Master Secret via HKDF
    const hkdfKey = await cryptoSubtle.importKey(
      'raw',
      ikm,
      { name: 'HKDF' },
      false,
      ['deriveKey', 'deriveBits']
    );

    TruplesCryptoCore.zeroizeBuffer(ikm);

    const salt = new TextEncoder().encode('Truples-PQXDH-v1-Salt');

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

    const sendingChainKey = await cryptoSubtle.deriveKey(
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

    const receivingChainKey = await cryptoSubtle.deriveKey(
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

    // 7. Initialize Bob's Double Ratchet Session
    const session = new DoubleRatchetSession({
      rootKey,
      sendingChainKey,
      receivingChainKey,
      localDhKeypair: signedPrekeyKeypair,
      remoteDhPublicKey: initiatorEphemeralEcdh,
      role: 'responder'
    });

    // 8. Decrypt initial message if present
    let decryptedPayload = null;
    if (handshakeMessage.initialMessage) {
      const msg = handshakeMessage.initialMessage;
      decryptedPayload = await session.receive(msg.header, msg.iv, msg.ciphertext);
    }

    return { session, decryptedPayload, initiatorIdentityKey: initiatorIdentityEcdsa };
  }
}

export {
  PrekeyBundle,
  PQXDHHandshakeMessage,
  TruplesPQXDH
};
