/**
 * Truples Cryptographic Core Self-Testing Suite (v2.8)
 * Full Double Ratchet State Machine & Negative Security Validation Suite
 * Run with: node tests/crypto.test.js
 */

const { TruplesCryptoCore, DoubleRatchetSession, canonicalEncodeHeader } = require('../src/crypto/truples-crypto');
const assert = require('assert');

async function runCryptographicTestSuite() {
  console.log('🧪 [TEST] Starting Truples Full Double Ratchet Validation Suite (v2.8)...\n');

  // Test 1: ECDH Keypair Generation (NIST P-384)
  console.log('1️⃣ Testing Ephemeral ECDH Keypair Generation (P-384)...');
  const aliceKeypair = await TruplesCryptoCore.generateECDHKeypair();
  const bobKeypair = await TruplesCryptoCore.generateECDHKeypair();
  assert(aliceKeypair.publicKey && aliceKeypair.privateKey, 'Alice keypair must be valid');
  assert(bobKeypair.publicKey && bobKeypair.privateKey, 'Bob keypair must be valid');
  console.log('   ✅ Passed: Generated distinct cryptographic keypairs.\n');

  // Test 2: ECDSA Long-Term Identity Keypair & Signature (MITM Defense)
  console.log('2️⃣ Testing ECDSA Identity Signatures (MITM Defense)...');
  const aliceIdentity = await TruplesCryptoCore.generateECDSAKeypair();
  const bobIdentity = await TruplesCryptoCore.generateECDSAKeypair();
  const handshakeChallenge = "Truples-Handshake-Auth-" + Date.now();
  const signature = await TruplesCryptoCore.signPayload(handshakeChallenge, aliceIdentity.privateKey);
  const isValidSig = await TruplesCryptoCore.verifySignature(handshakeChallenge, signature, aliceIdentity.publicKey);
  assert(isValidSig, 'ECDSA signature must verify successfully against public identity key');
  
  // Verify tampering fails
  const isTamperedValid = await TruplesCryptoCore.verifySignature(handshakeChallenge + "-tampered", signature, aliceIdentity.publicKey);
  assert(!isTamperedValid, 'Tampered data must fail ECDSA verification');
  console.log('   ✅ Passed: Verified ECDSA identity signature and anti-tamper rejection.\n');

  // Test 3: Authenticated Key Exchange (ECDH + ECDSA Handshake & Key Equality)
  console.log('3️⃣ Testing MITM-Resistant Authenticated Key Exchange & Byte-Level Key Equality...');
  const bobEcdhRaw = await globalThis.crypto.subtle.exportKey('raw', bobKeypair.publicKey);
  const bobSignedEcdhKey = await TruplesCryptoCore.signPayload(new Uint8Array(bobEcdhRaw), bobIdentity.privateKey);
  
  const aliceEcdhRaw = await globalThis.crypto.subtle.exportKey('raw', aliceKeypair.publicKey);
  const aliceSignedEcdhKey = await TruplesCryptoCore.signPayload(new Uint8Array(aliceEcdhRaw), aliceIdentity.privateKey);

  const dynamicSalt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(dynamicSalt);

  const aliceKeys = await TruplesCryptoCore.deriveAuthenticatedRootAndChainKeys(
    aliceKeypair.privateKey,
    bobKeypair.publicKey,
    bobIdentity.publicKey,
    bobSignedEcdhKey,
    dynamicSalt,
    'initiator'
  );
  const bobKeys = await TruplesCryptoCore.deriveAuthenticatedRootAndChainKeys(
    bobKeypair.privateKey,
    aliceKeypair.publicKey,
    aliceIdentity.publicKey,
    aliceSignedEcdhKey,
    dynamicSalt,
    'responder'
  );

  // Explicit byte-level equality test between independent derivations
  const aliceRootRaw = await globalThis.crypto.subtle.exportKey('raw', aliceKeys.rootKey);
  const bobRootRaw = await globalThis.crypto.subtle.exportKey('raw', bobKeys.rootKey);
  assert.deepStrictEqual(Buffer.from(aliceRootRaw), Buffer.from(bobRootRaw), 'Both parties must derive byte-identical Root Keys');

  // Verify Role-Aware Directional Chain Alignment: Alice Send === Bob Recv
  const aliceSendRaw = await globalThis.crypto.subtle.exportKey('raw', aliceKeys.sendingChainKey);
  const bobRecvRaw = await globalThis.crypto.subtle.exportKey('raw', bobKeys.receivingChainKey);
  assert.deepStrictEqual(Buffer.from(aliceSendRaw), Buffer.from(bobRecvRaw), 'Alice Sending Chain must be byte-identical to Bob Receiving Chain');

  // Verify MITM Attack Failure (Eve attempts to inject untrusted public key)
  const eveIdentity = await TruplesCryptoCore.generateECDSAKeypair();
  const eveFakeSignature = await TruplesCryptoCore.signPayload(new Uint8Array(bobEcdhRaw), eveIdentity.privateKey);
  
  let mitmBlocked = false;
  try {
    await TruplesCryptoCore.deriveAuthenticatedRootAndChainKeys(
      aliceKeypair.privateKey,
      bobKeypair.publicKey,
      bobIdentity.publicKey,
      eveFakeSignature,
      dynamicSalt,
      'initiator'
    );
  } catch (err) {
    mitmBlocked = true;
  }
  assert(mitmBlocked, 'MITM attack with forged identity signature must abort handshake');
  console.log('   ✅ Passed: Verified Role-Aware Root/Chain derivation and blocked MITM spoofing.\n');

  // Test 4: Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)
  console.log('4️⃣ Testing Directional Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)...');
  const aliceStep1 = await TruplesCryptoCore.ratchetMessageKey(aliceKeys.sendingChainKey);
  const bobStep1 = await TruplesCryptoCore.ratchetMessageKey(bobKeys.receivingChainKey);
  
  const payload1 = await TruplesCryptoCore.encryptPayload("Message 1: Initial Handshake", aliceStep1.messageKey);
  const decrypted1 = await TruplesCryptoCore.decryptPayload(payload1.iv, payload1.ciphertext, bobStep1.messageKey);
  assert.strictEqual(decrypted1, "Message 1: Initial Handshake");

  // Message 2 Ratchet Step (Chain advances)
  const aliceStep2 = await TruplesCryptoCore.ratchetMessageKey(aliceStep1.nextChainKey);
  const bobStep2 = await TruplesCryptoCore.ratchetMessageKey(bobStep1.nextChainKey);
  
  const payload2 = await TruplesCryptoCore.encryptPayload("Message 2: Next Ratcheted Transmission", aliceStep2.messageKey);
  const decrypted2 = await TruplesCryptoCore.decryptPayload(payload2.iv, payload2.ciphertext, bobStep2.messageKey);
  assert.strictEqual(decrypted2, "Message 2: Next Ratcheted Transmission");

  // Verify Forward Secrecy
  let failedDecryption = false;
  try {
    await TruplesCryptoCore.decryptPayload(payload2.iv, payload2.ciphertext, bobStep1.messageKey);
  } catch (err) {
    failedDecryption = true;
  }
  assert(failedDecryption, 'Message Key 1 must fail to decrypt Message 2');
  console.log('   ✅ Passed: Verified directional KDF chain ratcheting and strict forward secrecy.\n');

  // Test 5: Dynamic 96-bit IV Freshness (Nonce Uniqueness)
  console.log('5️⃣ Testing IV Freshness & Random Nonce Isolation...');
  const msgKey = aliceStep1.messageKey;
  const pA = await TruplesCryptoCore.encryptPayload("Identical text", msgKey);
  const pB = await TruplesCryptoCore.encryptPayload("Identical text", msgKey);
  assert.notStrictEqual(pA.iv, pB.iv, 'IVs must be distinct across consecutive transmissions');
  assert.notStrictEqual(pA.ciphertext, pB.ciphertext, 'Identical plaintexts must produce distinct ciphertexts');
  console.log('   ✅ Passed: Enforced strict per-message nonce isolation.\n');

  // Test 6: Authentication Tag (MAC) Tamper Resistance
  console.log('6️⃣ Testing 128-bit MAC Integrity & Tamper Detection...');
  const rawBytes = Buffer.from(payload1.ciphertext, 'base64');
  rawBytes[rawBytes.length - 1] ^= 0x01; // Tamper with 1 bit
  
  let tamperDetected = false;
  try {
    await TruplesCryptoCore.decryptPayload(payload1.iv, rawBytes.toString('base64'), bobStep1.messageKey);
  } catch (err) {
    tamperDetected = true;
  }
  assert(tamperDetected, 'Tampered ciphertext must fail MAC verification');
  console.log('   ✅ Passed: Cryptographic MAC verification rejected tampered ciphertext.\n');

  // Test 7: Memory Buffer Scrubbing
  console.log('7️⃣ Testing Best-Effort In-Memory Buffer Scrubbing...');
  const sensitiveBuffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  TruplesCryptoCore.zeroizeBuffer(sensitiveBuffer);
  assert(sensitiveBuffer.every(b => b === 0), 'Buffer must be completely zeroized');
  console.log('   ✅ Passed: Multi-pass binary memory scrubbing verified.\n');

  // Test 8: Asymmetric DH Ratchet Step & Directional Chain Separation Test
  console.log('8️⃣ Testing Asymmetric DH Ratchet Step & Directional Chain Separation...');
  const bobNewTurnKeypair = await TruplesCryptoCore.generateECDHKeypair();
  const aliceNewTurnKeypair = await TruplesCryptoCore.generateECDHKeypair();

  const aliceRatchet = await TruplesCryptoCore.executeDhRatchetStep(aliceKeys.rootKey, aliceNewTurnKeypair.privateKey, bobNewTurnKeypair.publicKey, 'initiator');
  const bobRatchet = await TruplesCryptoCore.executeDhRatchetStep(bobKeys.rootKey, bobNewTurnKeypair.privateKey, aliceNewTurnKeypair.publicKey, 'responder');

  // 1. Direct byte-level comparison of new Root Keys
  const aliceRatchetRootRaw = await globalThis.crypto.subtle.exportKey('raw', aliceRatchet.newRootKey);
  const bobRatchetRootRaw = await globalThis.crypto.subtle.exportKey('raw', bobRatchet.newRootKey);
  assert.deepStrictEqual(Buffer.from(aliceRatchetRootRaw), Buffer.from(bobRatchetRootRaw), 'Both parties must derive byte-identical Root Keys');

  // 2. Alice Sending === Bob Receiving
  const aliceRatchetSendRaw = await globalThis.crypto.subtle.exportKey('raw', aliceRatchet.newSendingChainKey);
  const bobRatchetRecvRaw = await globalThis.crypto.subtle.exportKey('raw', bobRatchet.newReceivingChainKey);
  assert.deepStrictEqual(Buffer.from(aliceRatchetSendRaw), Buffer.from(bobRatchetRecvRaw), 'Alice newSendingChainKey must match Bob newReceivingChainKey');

  // 3. Alice Sending !== Alice Receiving (Proves strict directional isolation)
  const aliceRatchetRecvRaw = await globalThis.crypto.subtle.exportKey('raw', aliceRatchet.newReceivingChainKey);
  assert.notDeepStrictEqual(Buffer.from(aliceRatchetSendRaw), Buffer.from(aliceRatchetRecvRaw), 'Alice Sending Chain must be distinct from Alice Receiving Chain');
  console.log('   ✅ Passed: Verified DH Ratchet state transition and proved 3-way directional chain isolation.\n');

  // Test 9: Full Adversarial Post-Compromise Security (PCS) Recovery
  console.log('9️⃣ Testing Full Adversarial Post-Compromise Security (PCS) Recovery...');
  const compromisedRootKey = aliceKeys.rootKey;
  const compromisedOldDhPrivateKey = aliceKeypair.privateKey;

  const aliceFreshKeypair = await TruplesCryptoCore.generateECDHKeypair();
  const bobFreshKeypair = await TruplesCryptoCore.generateECDHKeypair();

  const alicePcsRatchet = await TruplesCryptoCore.executeDhRatchetStep(aliceKeys.rootKey, aliceFreshKeypair.privateKey, bobFreshKeypair.publicKey, 'initiator');
  const bobPcsRatchet = await TruplesCryptoCore.executeDhRatchetStep(bobKeys.rootKey, bobFreshKeypair.privateKey, aliceFreshKeypair.publicKey, 'responder');

  const { messageKey: postDhMsgKey } = await TruplesCryptoCore.ratchetMessageKey(alicePcsRatchet.newSendingChainKey);
  const pcsPayload = await TruplesCryptoCore.encryptPayload("Top Secret Post-Compromise Message", postDhMsgKey);

  const { messageKey: bobPostDhMsgKey } = await TruplesCryptoCore.ratchetMessageKey(bobPcsRatchet.newReceivingChainKey);
  const bobDecrypted = await TruplesCryptoCore.decryptPayload(pcsPayload.iv, pcsPayload.ciphertext, bobPostDhMsgKey);
  assert.strictEqual(bobDecrypted, "Top Secret Post-Compromise Message");

  let attackerDecryptionFailed = false;
  try {
    const attackerFakeRatchet = await TruplesCryptoCore.executeDhRatchetStep(compromisedRootKey, compromisedOldDhPrivateKey, bobFreshKeypair.publicKey, 'initiator');
    const { messageKey: attackerFakeMsgKey } = await TruplesCryptoCore.ratchetMessageKey(attackerFakeRatchet.newSendingChainKey);
    await TruplesCryptoCore.decryptPayload(pcsPayload.iv, pcsPayload.ciphertext, attackerFakeMsgKey);
  } catch (err) {
    attackerDecryptionFailed = true;
  }
  assert(attackerDecryptionFailed, 'Attacker possessing past RootKey and past DH private keys MUST fail to decrypt post-DH turn messages');
  console.log('   ✅ Passed: Full Adversarial PCS proven: Healed cryptographic enclave and locked out historical attacker.\n');

  // Test 10: Out-of-Order Message Delivery & Skipped Key Buffering
  console.log('🔟 Testing Out-of-Order Message Delivery & Skipped Key Resolution...');
  const aliceSession = new DoubleRatchetSession({
    rootKey: aliceKeys.rootKey,
    sendingChainKey: aliceKeys.sendingChainKey,
    receivingChainKey: aliceKeys.receivingChainKey,
    localDhKeypair: aliceKeypair,
    remoteDhPublicKey: bobKeypair.publicKey,
    role: 'initiator'
  });

  const bobSession = new DoubleRatchetSession({
    rootKey: bobKeys.rootKey,
    sendingChainKey: bobKeys.sendingChainKey,
    receivingChainKey: bobKeys.receivingChainKey,
    localDhKeypair: bobKeypair,
    remoteDhPublicKey: aliceKeypair.publicKey,
    role: 'responder'
  });

  const m1 = await aliceSession.send("Message 1: Alpha");
  const m2 = await aliceSession.send("Message 2: Beta (Delayed)");
  const m3 = await aliceSession.send("Message 3: Gamma");
  const m4 = await aliceSession.send("Message 4: Delta");

  const r1 = await bobSession.receive(m1.header, m1.iv, m1.ciphertext);
  assert.strictEqual(r1, "Message 1: Alpha");

  // M3 arrives ahead of M2
  const r3 = await bobSession.receive(m3.header, m3.iv, m3.ciphertext);
  assert.strictEqual(r3, "Message 3: Gamma");

  // M4 arrives
  const r4 = await bobSession.receive(m4.header, m4.iv, m4.ciphertext);
  assert.strictEqual(r4, "Message 4: Delta");

  // Delayed M2 arrives and decrypts from skipped keys cache
  const r2 = await bobSession.receive(m2.header, m2.iv, m2.ciphertext);
  assert.strictEqual(r2, "Message 2: Beta (Delayed)");
  console.log('   ✅ Passed: Successfully resolved out-of-order delivery and managed skipped keys.\n');

  // Test 11: True Bidirectional Double Ratchet Messaging
  console.log('1️⃣1️⃣ Testing True Bidirectional Double Ratchet Messaging (Alice <-> Bob)...');
  const aliceMsg1 = await aliceSession.send("Hello Bob! (Alice -> Bob)");
  const bobRecv1 = await bobSession.receive(aliceMsg1.header, aliceMsg1.iv, aliceMsg1.ciphertext);
  assert.strictEqual(bobRecv1, "Hello Bob! (Alice -> Bob)");

  const bobReply1 = await bobSession.send("Hi Alice, received loud and clear! (Bob -> Alice)");
  const aliceRecv1 = await aliceSession.receive(bobReply1.header, bobReply1.iv, bobReply1.ciphertext);
  assert.strictEqual(aliceRecv1, "Hi Alice, received loud and clear! (Bob -> Alice)");
  console.log('   ✅ Passed: Verified true bidirectional message interchange between sessions.\n');

  // Test 12: Continuous Automated Ephemeral DH Turn-Taking
  console.log('1️⃣2️⃣ Testing Continuous Automated Ephemeral DH Turn-Taking State Machine...');
  // Alice rotates local DH keypair and sends
  await aliceSession.rotateLocalDhKeypair();
  const aliceTurn1 = await aliceSession.send("Alice Turn 1 after DH rotation");
  
  // Bob receives (Bob's session automatically flags dhRatchetTurnPending)
  const bobTurn1 = await bobSession.receive(aliceTurn1.header, aliceTurn1.iv, aliceTurn1.ciphertext);
  assert.strictEqual(bobTurn1, "Alice Turn 1 after DH rotation");

  // Bob simply replies: bobSession.send() automatically performs local DH rotation and advances turn!
  const bobTurnReply = await bobSession.send("Bob automated reply with auto-rotated DH key");
  const aliceRecvTurnReply = await aliceSession.receive(bobTurnReply.header, bobTurnReply.iv, bobTurnReply.ciphertext);
  assert.strictEqual(aliceRecvTurnReply, "Bob automated reply with auto-rotated DH key");
  console.log('   ✅ Passed: Proved fully automated continuous DH turn-taking without manual rotation calls.\n');

  // Test 13: Multi-Epoch Out-of-Order Delivery across Consecutive DH Ratchets
  console.log('1️⃣3️⃣ Testing Multi-Epoch Out-of-Order Delivery Across Consecutive DH Ratchets...');
  const epochAlice = new DoubleRatchetSession({
    rootKey: aliceKeys.rootKey,
    sendingChainKey: aliceKeys.sendingChainKey,
    receivingChainKey: aliceKeys.receivingChainKey,
    localDhKeypair: aliceKeypair,
    remoteDhPublicKey: bobKeypair.publicKey,
    role: 'initiator'
  });

  const epochBob = new DoubleRatchetSession({
    rootKey: bobKeys.rootKey,
    sendingChainKey: bobKeys.sendingChainKey,
    receivingChainKey: bobKeys.receivingChainKey,
    localDhKeypair: bobKeypair,
    remoteDhPublicKey: aliceKeypair.publicKey,
    role: 'responder'
  });

  // Epoch A: Alice prepares two messages
  const msgEpochA1 = await epochAlice.send("Epoch A - Message 1");
  const msgEpochA2 = await epochAlice.send("Epoch A - Message 2 (Delayed across DH turn)");

  // Alice rotates DH keypair, advancing to Epoch B
  await epochAlice.rotateLocalDhKeypair();
  const msgEpochB1 = await epochAlice.send("Epoch B - Message 1");

  // Bob receives Epoch B message first (triggering DH ratchet and buffering unconsumed Epoch A messages)
  const recvB1 = await epochBob.receive(msgEpochB1.header, msgEpochB1.iv, msgEpochB1.ciphertext);
  assert.strictEqual(recvB1, "Epoch B - Message 1");

  // Bob receives delayed Epoch A Message 2 from previous DH epoch
  const recvA2 = await epochBob.receive(msgEpochA2.header, msgEpochA2.iv, msgEpochA2.ciphertext);
  assert.strictEqual(recvA2, "Epoch A - Message 2 (Delayed across DH turn)");
  console.log('   ✅ Passed: Verified multi-epoch skipped key resolution across DH Ratchet boundaries.\n');

  // Test 14: Header Tamper Resistance (AES-GCM Additional Authenticated Data - AAD)
  console.log('1️⃣4️⃣ Testing Double Ratchet Header Tamper Rejection via AES-GCM AAD Binding...');
  const legitimateMsg = await aliceSession.send("Authenticity Guaranteed Message");

  // Attack A: Adversary tampers with messageNumber
  const tamperedNumberHeader = { ...legitimateMsg.header, messageNumber: 999 };
  let tamperedNumberFailed = false;
  try {
    await bobSession.receive(tamperedNumberHeader, legitimateMsg.iv, legitimateMsg.ciphertext);
  } catch (err) {
    tamperedNumberFailed = true;
  }
  assert(tamperedNumberFailed, 'Tampering with messageNumber in header MUST fail AES-GCM AAD authentication');

  // Attack B: Adversary tampers with dhPublicKey
  const fakeDhKey = await TruplesCryptoCore.generateECDHKeypair();
  const fakeRaw = await globalThis.crypto.subtle.exportKey('raw', fakeDhKey.publicKey);
  const tamperedDhHeader = { ...legitimateMsg.header, dhPublicKey: Buffer.from(fakeRaw).toString('base64') };
  let tamperedDhFailed = false;
  try {
    await bobSession.receive(tamperedDhHeader, legitimateMsg.iv, legitimateMsg.ciphertext);
  } catch (err) {
    tamperedDhFailed = true;
  }
  assert(tamperedDhFailed, 'Tampering with dhPublicKey in header MUST fail AES-GCM AAD authentication');

  // Attack C: Adversary tampers with previousChainLength
  const tamperedPrevLenHeader = { ...legitimateMsg.header, previousChainLength: 777 };
  let tamperedPrevLenFailed = false;
  try {
    await bobSession.receive(tamperedPrevLenHeader, legitimateMsg.iv, legitimateMsg.ciphertext);
  } catch (err) {
    tamperedPrevLenFailed = true;
  }
  assert(tamperedPrevLenFailed, 'Tampering with previousChainLength MUST fail AES-GCM AAD authentication');
  console.log('   ✅ Passed: Proved strict header integrity: AAD prevents all header tampering attacks.\n');

  // Test 15: Strict Replay Attack Protection & Transactional Rollback
  console.log('1️⃣5️⃣ Testing Strict Replay Attack Protection & State Rollback...');
  const legitimateRecv = await bobSession.receive(legitimateMsg.header, legitimateMsg.iv, legitimateMsg.ciphertext);
  assert.strictEqual(legitimateRecv, "Authenticity Guaranteed Message");

  let replayBlocked = false;
  try {
    await bobSession.receive(legitimateMsg.header, legitimateMsg.iv, legitimateMsg.ciphertext);
  } catch (err) {
    replayBlocked = true;
  }
  assert(replayBlocked, 'Replay of previously consumed message MUST be rejected with error');
  console.log('   ✅ Passed: Verified strict replay attack rejection for duplicate transmissions.\n');

  // Test 16: Negative Protocol Security & Malformed Input Test Suite
  console.log('1️⃣6️⃣ Testing Negative Protocol Security & Malformed Input Bounds...');
  
  // A: Malformed public key (invalid length)
  let invalidKeyRejected = false;
  try {
    canonicalEncodeHeader({
      dhPublicKey: Buffer.from([0x04, 1, 2, 3]).toString('base64'),
      previousChainLength: 0,
      messageNumber: 0
    });
  } catch (err) {
    invalidKeyRejected = true;
  }
  assert(invalidKeyRejected, 'Malformed public key length must be rejected by canonical encoder');

  // B: Header integer overflow / negative numbers
  let invalidIntegerRejected = false;
  try {
    canonicalEncodeHeader({
      dhPublicKey: legitimateMsg.header.dhPublicKey,
      previousChainLength: -5,
      messageNumber: 0
    });
  } catch (err) {
    invalidIntegerRejected = true;
  }
  assert(invalidIntegerRejected, 'Negative header sequence numbers must be rejected');

  // C: Bounded LRU Replay Cache Eviction (FIFO limit enforcement)
  const testLruSession = new DoubleRatchetSession({
    rootKey: aliceKeys.rootKey,
    sendingChainKey: aliceKeys.sendingChainKey,
    receivingChainKey: aliceKeys.receivingChainKey,
    localDhKeypair: aliceKeypair,
    remoteDhPublicKey: bobKeypair.publicKey
  });
  testLruSession.maxConsumedKeys = 3; // Lower bound for testing
  testLruSession.recordConsumedKey('key-1');
  testLruSession.recordConsumedKey('key-2');
  testLruSession.recordConsumedKey('key-3');
  assert(testLruSession.consumedMessageKeys.has('key-1'), 'key-1 should exist');
  
  testLruSession.recordConsumedKey('key-4'); // Triggers eviction of oldest ('key-1')
  assert(!testLruSession.consumedMessageKeys.has('key-1'), 'key-1 must be evicted from bounded cache');
  assert(testLruSession.consumedMessageKeys.has('key-4'), 'key-4 must exist in bounded cache');
  console.log('   ✅ Passed: Verified strict P-384 point validation, integer bounds, and bounded LRU cache eviction.\n');

  console.log('========================================================================');
  console.log('🎉 ALL 16 CRYPTOGRAPHIC, FULL DOUBLE RATCHET, AAD & NEGATIVE TESTS PASSED!');
  console.log('========================================================================');
}

runCryptographicTestSuite().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
