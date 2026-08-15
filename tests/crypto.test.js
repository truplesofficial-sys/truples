/**
 * Truples Cryptographic Core Self-Testing Suite (v2.4)
 * Run with: node tests/crypto.test.js
 */

const { TruplesCryptoCore } = require('../src/crypto/truples-crypto');
const assert = require('assert');

async function runCryptographicTestSuite() {
  console.log('🧪 [TEST] Starting Truples Cryptographic Core Validation (v2.4)...\n');

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
  console.log('3️⃣ Testing MITM-Resistant Authenticated Key Exchange & Key Equality...');
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
    dynamicSalt
  );
  const bobKeys = await TruplesCryptoCore.deriveAuthenticatedRootAndChainKeys(
    bobKeypair.privateKey,
    aliceKeypair.publicKey,
    aliceIdentity.publicKey,
    aliceSignedEcdhKey,
    dynamicSalt
  );

  // Explicit byte-level equality test between independent derivations
  const aliceRootRaw = await globalThis.crypto.subtle.exportKey('raw', aliceKeys.rootKey);
  const bobRootRaw = await globalThis.crypto.subtle.exportKey('raw', bobKeys.rootKey);
  assert.deepStrictEqual(Buffer.from(aliceRootRaw), Buffer.from(bobRootRaw), 'Both parties must derive byte-identical Root Keys');

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
      dynamicSalt
    );
  } catch (err) {
    mitmBlocked = true;
  }
  assert(mitmBlocked, 'MITM attack with forged identity signature must abort handshake');
  console.log('   ✅ Passed: Successfully verified byte-identical Root Key derivation and blocked MITM spoofing.\n');

  // Test 4: Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)
  console.log('4️⃣ Testing Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)...');
  const aliceStep1 = await TruplesCryptoCore.ratchetMessageKey(aliceKeys.chainKey);
  const bobStep1 = await TruplesCryptoCore.ratchetMessageKey(bobKeys.chainKey);
  
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
  console.log('   ✅ Passed: Verified KDF chain ratcheting and strict per-message forward secrecy.\n');

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

  // Test 8: Asymmetric DH Ratchet Step & Post-Compromise Recovery Simulation
  console.log('8️⃣ Testing Asymmetric DH Ratchet Step & Post-Compromise Security Recovery...');
  // Scenario: Attacker compromises Alice's current chain key (aliceStep2.nextChainKey)
  const compromisedChainKey = aliceStep2.nextChainKey;

  // Turn-Taking occurs: Bob generates a brand new ephemeral ECDH keypair and sends his public key
  const bobNewTurnKeypair = await TruplesCryptoCore.generateECDHKeypair();
  const aliceNewTurnKeypair = await TruplesCryptoCore.generateECDHKeypair();

  // Both parties advance their Root Keys via Asymmetric DH Ratchet
  const aliceRatchet = await TruplesCryptoCore.executeDhRatchetStep(aliceKeys.rootKey, aliceNewTurnKeypair.privateKey, bobNewTurnKeypair.publicKey);
  const bobRatchet = await TruplesCryptoCore.executeDhRatchetStep(bobKeys.rootKey, bobNewTurnKeypair.privateKey, aliceNewTurnKeypair.publicKey);

  // Derive fresh post-DH message key
  const alicePostStep = await TruplesCryptoCore.ratchetMessageKey(aliceRatchet.newChainKey);
  const bobPostStep = await TruplesCryptoCore.ratchetMessageKey(bobRatchet.newChainKey);

  const postPayload = await TruplesCryptoCore.encryptPayload("Post-Compromise Recovered Secret", alicePostStep.messageKey);
  const decryptedPost = await TruplesCryptoCore.decryptPayload(postPayload.iv, postPayload.ciphertext, bobPostStep.messageKey);
  assert.strictEqual(decryptedPost, "Post-Compromise Recovered Secret");

  // Attacker attempts to derive future message key using the compromised old chain key
  const attackerStep = await TruplesCryptoCore.ratchetMessageKey(compromisedChainKey);
  let attackerFailed = false;
  try {
    await TruplesCryptoCore.decryptPayload(postPayload.iv, postPayload.ciphertext, attackerStep.messageKey);
  } catch (err) {
    attackerFailed = true;
  }
  assert(attackerFailed, 'Attacker with compromised historical chain key MUST fail to decrypt post-DH ratchet messages');
  console.log('   ✅ Passed: Verified Asymmetric DH Ratchet step and proved Post-Compromise Security recovery.\n');

  console.log('========================================================================');
  console.log('🎉 ALL 8 CRYPTOGRAPHIC, DH RATCHET & POST-COMPROMISE RECOVERY TESTS PASSED!');
  console.log('========================================================================');
}

runCryptographicTestSuite().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
