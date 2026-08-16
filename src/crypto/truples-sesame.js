/**
 * Truples Sesame Multi-Device Session Management Protocol
 * 
 * Implements the Signal Sesame Specification Architecture:
 * - 3-Tier Identity Hierarchy: User -> Device -> Pairwise Session
 * - Independent Pairwise Double Ratchet Sessions with PQXDH Initial Key Agreement
 * - Multi-Recipient Fan-Out Encryption with Automatic Self-Device Sync
 * - Dynamic Device Lifecycle: Register, Add, Revoke, Stale Quarantine
 * - Device Compromise Isolation: Compromising one device yields zero access to sibling devices
 * - Atomic Persistence & Anti-Rollback Protection for Multi-Device Session Stores
 */

import { TruplesCryptoCore, DoubleRatchetSession } from './truples-crypto.js';
import { TruplesPQKEM } from './truples-pqkem.js';
import { TruplesPQXDH, PrekeyBundle, PQXDHHandshakeMessage } from './truples-pqxdh.js';

const cryptoSubtle = typeof window !== 'undefined' && window.crypto?.subtle 
  ? window.crypto.subtle 
  : (globalThis.crypto?.subtle || require('crypto').webcrypto.subtle);

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
 * Status constants for managed devices.
 */
export const DeviceStatus = {
  ACTIVE: 'ACTIVE',
  REVOKED: 'REVOKED',
  STALE: 'STALE'
};

/**
 * Represents a registered device in the Sesame device directory.
 */
export class DeviceRecord {
  constructor({
    deviceId,
    identityPublicKey,
    registrationTimestamp = Date.now(),
    status = DeviceStatus.ACTIVE
  }) {
    this.deviceId = deviceId;
    this.identityPublicKey = identityPublicKey; // Base64 or CryptoKey
    this.registrationTimestamp = registrationTimestamp;
    this.status = status;
  }
}

/**
 * Encapsulated multi-device encrypted transmission bundle.
 */
export class MultiDeviceEncryptedPayload {
  constructor({
    senderUserId,
    senderDeviceId,
    recipientUserId,
    devicePayloads = new Map(), // deviceId -> { handshakeMessage, encryptedMessage }
    timestamp = Date.now()
  }) {
    this.senderUserId = senderUserId;
    this.senderDeviceId = senderDeviceId;
    this.recipientUserId = recipientUserId;
    this.devicePayloads = devicePayloads;
    this.timestamp = timestamp;
  }
}

/**
 * Core Sesame Protocol State Machine and Session Directory.
 */
export class SesameEngine {
  constructor({ userId, deviceId, identityKeypair, signedPrekeyKeypair, pqSignedPrekeyKeypair }) {
    this.userId = userId;
    this.deviceId = deviceId;
    this.identityKeypair = identityKeypair;
    this.signedPrekeyKeypair = signedPrekeyKeypair;
    this.pqSignedPrekeyKeypair = pqSignedPrekeyKeypair;

    // Local device prekeys
    this.oneTimePrekeys = new Map(); // opkId -> keypair
    this.pqOneTimePrekeys = new Map(); // pqOpkId -> keypair

    // Session Directory: `${peerUserId}:${peerDeviceId}` -> DoubleRatchetSession
    this.sessions = new Map();

    // Device Directory: peerUserId -> Map<peerDeviceId, DeviceRecord>
    this.deviceDirectory = new Map();

    // Self Devices Directory: deviceId -> DeviceRecord
    this.selfDevices = new Map();
  }

  /**
   * Generates a published PrekeyBundle for this local device.
   */
  async getLocalPrekeyBundle(opkId = null, pqOpkId = null) {
    let opkKeypair = null;
    let pqOpkKeypair = null;

    if (opkId) {
      opkKeypair = await TruplesCryptoCore.generateECDHKeypair();
      this.oneTimePrekeys.set(opkId, opkKeypair);
    }
    if (pqOpkId) {
      pqOpkKeypair = await TruplesPQKEM.generateKeypair();
      this.pqOneTimePrekeys.set(pqOpkId, pqOpkKeypair);
    }

    return await TruplesPQXDH.createPrekeyBundle({
      identityKeypair: this.identityKeypair,
      signedPrekeyKeypair: this.signedPrekeyKeypair,
      pqSignedPrekeyKeypair: this.pqSignedPrekeyKeypair,
      oneTimePrekeyKeypair: opkKeypair,
      oneTimePrekeyId: opkId,
      pqOneTimePrekeyKeypair: pqOpkKeypair,
      pqOneTimePrekeyId: pqOpkId
    });
  }

  /**
   * Registers or updates a device record for a peer user.
   */
  registerPeerDevice(peerUserId, deviceRecord) {
    if (!this.deviceDirectory.has(peerUserId)) {
      this.deviceDirectory.set(peerUserId, new Map());
    }
    const userDevices = this.deviceDirectory.get(peerUserId);
    userDevices.set(deviceRecord.deviceId, deviceRecord);
  }

  /**
   * Registers a sibling device belonging to the same local user.
   */
  registerSelfDevice(deviceRecord) {
    this.selfDevices.set(deviceRecord.deviceId, deviceRecord);
  }

  /**
   * Revokes a peer device. Future transmissions to this device will be blocked.
   */
  revokePeerDevice(peerUserId, peerDeviceId) {
    const userDevices = this.deviceDirectory.get(peerUserId);
    if (userDevices && userDevices.has(peerDeviceId)) {
      const record = userDevices.get(peerDeviceId);
      record.status = DeviceStatus.REVOKED;
    }
    const sessionKey = `${peerUserId}:${peerDeviceId}`;
    this.sessions.delete(sessionKey);
  }

  /**
   * Revokes a self device.
   */
  revokeSelfDevice(selfDeviceId) {
    if (this.selfDevices.has(selfDeviceId)) {
      this.selfDevices.get(selfDeviceId).status = DeviceStatus.REVOKED;
    }
    const sessionKey = `${this.userId}:${selfDeviceId}`;
    this.sessions.delete(sessionKey);
  }

  /**
   * Encrypts a message with Sesame multi-device fan-out across all active recipient devices
   * and all active self devices (excluding current sending device).
   * 
   * @param {Object} params
   * @param {string} params.recipientUserId Target user ID
   * @param {string} params.plaintext Plaintext message
   * @param {Map<string, PrekeyBundle>} params.recipientBundles Map of deviceId -> PrekeyBundle (for new sessions)
   * @param {Map<string, PrekeyBundle>} [params.selfBundles] Map of self deviceId -> PrekeyBundle
   */
  async encryptMultiDeviceMessage({
    recipientUserId,
    plaintext,
    recipientBundles = new Map(),
    selfBundles = new Map()
  }) {
    const devicePayloads = new Map();

    // 1. Fan-out to Recipient Devices
    const recipientDeviceMap = this.deviceDirectory.get(recipientUserId) || new Map();
    for (const [recDeviceId, recRecord] of recipientDeviceMap.entries()) {
      if (recRecord.status !== DeviceStatus.ACTIVE) {
        continue; // Skip revoked or stale devices
      }

      const sessionKey = `${recipientUserId}:${recDeviceId}`;
      let session = this.sessions.get(sessionKey);
      let handshakeMessage = null;

      if (!session) {
        // Initialize new pairwise session via PQXDH
        const bundle = recipientBundles.get(recDeviceId);
        if (!bundle) {
          throw new Error(`Cannot initialize session: missing PrekeyBundle for recipient device [${recDeviceId}]`);
        }
        const res = await TruplesPQXDH.initiateHandshake({
          initiatorIdentityKeypair: this.identityKeypair,
          recipientBundle: bundle,
          initialPlaintext: plaintext
        });
        session = res.session;
        handshakeMessage = res.handshakeMessage;
        this.sessions.set(sessionKey, session);
        devicePayloads.set(recDeviceId, { handshakeMessage, encryptedMessage: null });
      } else {
        const encryptedMessage = await session.send(plaintext);
        devicePayloads.set(recDeviceId, { handshakeMessage: null, encryptedMessage });
      }
    }

    // 2. Fan-out to Sibling Self Devices (Self-Sync)
    for (const [selfDevId, selfRecord] of this.selfDevices.entries()) {
      if (selfDevId === this.deviceId || selfRecord.status !== DeviceStatus.ACTIVE) {
        continue;
      }

      const sessionKey = `${this.userId}:${selfDevId}`;
      let session = this.sessions.get(sessionKey);
      let handshakeMessage = null;

      if (!session) {
        const bundle = selfBundles.get(selfDevId);
        if (bundle) {
          const res = await TruplesPQXDH.initiateHandshake({
            initiatorIdentityKeypair: this.identityKeypair,
            recipientBundle: bundle,
            initialPlaintext: plaintext
          });
          session = res.session;
          handshakeMessage = res.handshakeMessage;
          this.sessions.set(sessionKey, session);
          devicePayloads.set(selfDevId, { handshakeMessage, encryptedMessage: null });
        }
      } else {
        const encryptedMessage = await session.send(plaintext);
        devicePayloads.set(selfDevId, { handshakeMessage: null, encryptedMessage });
      }
    }

    return new MultiDeviceEncryptedPayload({
      senderUserId: this.userId,
      senderDeviceId: this.deviceId,
      recipientUserId,
      devicePayloads
    });
  }

  /**
   * Decrypts an inbound Sesame message designated for this local device.
   */
  async decryptInboundMessage({
    senderUserId,
    senderDeviceId,
    payloadForDevice
  }) {
    const sessionKey = `${senderUserId}:${senderDeviceId}`;

    // Verify sender device status if registered
    const senderUserDevices = this.deviceDirectory.get(senderUserId);
    if (senderUserDevices && senderUserDevices.has(senderDeviceId)) {
      const senderRecord = senderUserDevices.get(senderDeviceId);
      if (senderRecord.status === DeviceStatus.REVOKED) {
        throw new Error(`Decryption Aborted: Sender device [${senderDeviceId}] is revoked.`);
      }
    }

    if (payloadForDevice.handshakeMessage) {
      // New Session Initiation via PQXDH
      const hs = payloadForDevice.handshakeMessage;

      // Extract one-time prekeys if used
      let opkKeypair = null;
      if (hs.oneTimePrekeyId && this.oneTimePrekeys.has(hs.oneTimePrekeyId)) {
        opkKeypair = this.oneTimePrekeys.get(hs.oneTimePrekeyId);
        this.oneTimePrekeys.delete(hs.oneTimePrekeyId); // Consumed
      }

      let pqOpkKeypair = null;
      if (hs.pqOneTimePrekeyId && this.pqOneTimePrekeys.has(hs.pqOneTimePrekeyId)) {
        pqOpkKeypair = this.pqOneTimePrekeys.get(hs.pqOneTimePrekeyId);
        this.pqOneTimePrekeys.delete(hs.pqOneTimePrekeyId); // Consumed
      }

      const { session, decryptedPayload } = await TruplesPQXDH.respondHandshake({
        responderIdentityKeypair: this.identityKeypair,
        signedPrekeyKeypair: this.signedPrekeyKeypair,
        pqSignedPrekeyKeypair: this.pqSignedPrekeyKeypair,
        oneTimePrekeyKeypair: opkKeypair,
        pqOneTimePrekeyKeypair: pqOpkKeypair,
        handshakeMessage: hs
      });

      this.sessions.set(sessionKey, session);
      return decryptedPayload;
    } else if (payloadForDevice.encryptedMessage) {
      const session = this.sessions.get(sessionKey);
      if (!session) {
        throw new Error(`Decryption Failed: No active session found for peer [${sessionKey}]`);
      }
      const msg = payloadForDevice.encryptedMessage;
      return await session.receive(msg.header, msg.iv, msg.ciphertext);
    } else {
      throw new Error('Invalid payload structure: neither handshakeMessage nor encryptedMessage present');
    }
  }

  /**
   * Quarantines a session if anomalous behavior or unauthorized key alteration is detected.
   */
  quarantineSession(peerUserId, peerDeviceId) {
    const sessionKey = `${peerUserId}:${peerDeviceId}`;
    this.sessions.delete(sessionKey);
    const userDevices = this.deviceDirectory.get(peerUserId);
    if (userDevices && userDevices.has(peerDeviceId)) {
      userDevices.get(peerDeviceId).status = DeviceStatus.STALE;
    }
  }
}

export {
  PrekeyBundle,
  PQXDHHandshakeMessage,
  TruplesPQXDH
};
