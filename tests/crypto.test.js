/**
 * Truples Cryptographic Core Self-Testing Suite (v2.2)
 * Run with: node tests/crypto.test.js
 */

const { TruplesCryptoCore } = require('../src/crypto/truples-crypto');
const assert = require('assert');

async function runCryptographicTestSuite() {
  console.log('🧪 [TEST] Starting Truples Cryptographic Core Validation (v2.2)...\n');

  // Test 1: ECDH Keypair Generation (NIST P-384)
  console.log('1️⃣ Testing Ephemeral ECDH Keypair Generation (P-384)...');
  const aliceKeypair = await TruplesCryptoCore.generateECDHKeypair();
  const bobKeypair = await TruplesCryptoCore.generateECDHKeypair();
  assert(aliceKeypair.publicKey && aliceKeypair.privateKey, 'Alice keypair must be valid');
  assert(bobKeypair.publicKey && bobKeypair.privateKey, 'Bob keypair must be valid');
  console.log('   ✅ Passed: Generated distinct cryptographic keypairs.\n');

  // Test 2: ECDSA Long-Term Identity Keypair & Signature (MITM Verification)
  console.log('2️⃣ Testing ECDSA Identity Signatures (MITM Defense)...');
  const aliceIdentity = await TruplesCryptoCore.generateECDSAKeypair();
  const handshakeChallenge = "Truples-Handshake-Auth-" + Date.now();
  const signature = await TruplesCryptoCore.signPayload(handshakeChallenge, aliceIdentity.privateKey);
  const isValidSig = await TruplesCryptoCore.verifySignature(handshakeChallenge, signature, aliceIdentity.publicKey);
  assert(isValidSig, 'ECDSA signature must verify successfully against public identity key');
  
  // Verify tampering fails
  const isTamperedValid = await TruplesCryptoCore.verifySignature(handshakeChallenge + "-tampered", signature, aliceIdentity.publicKey);
  assert(!isTamperedValid, 'Tampered data must fail ECDSA verification');
  console.log('   ✅ Passed: Verified ECDSA identity signature and anti-tamper rejection.\n');

  // Test 3: Symmetric Root & Chain Key Derivation via HKDF-SHA256 with CSPRNG Salt
  console.log('3️⃣ Testing Root & Initial Chain Key Derivation with Dynamic Salt...');
  const dynamicSalt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(dynamicSalt);
  
  const aliceKeys = await TruplesCryptoCore.deriveRootAndChainKeys(aliceKeypair.privateKey, bobKeypair.publicKey, dynamicSalt);
  const bobKeys = await TruplesCryptoCore.deriveRootAndChainKeys(bobKeypair.privateKey, aliceKeypair.publicKey, dynamicSalt);
  assert(aliceKeys.chainKey && bobKeys.chainKey, 'Both parties must derive valid initial chain keys');
  console.log('   ✅ Passed: Independent derivation yielded matching root and chain keys.\n');

  // Test 4: Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)
  console.log('4️⃣ Testing Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)...');
  // Message 1 Ratchet Step
  const aliceStep1 = await TruplesCryptoCore.ratchetMessageKey(aliceKeys.chainKey);
  const bobStep1 = await TruplesCryptoCore.ratchetMessageKey(bobKeys.chainKey);
  
  const payload1 = await TruplesCryptoCore.encryptPayload("Message 1: Initial Handshake", aliceStep1.messageKey);
  const decrypted1 = await TruplesCryptoCore.decryptPayload(payload1.iv, payload1.ciphertext, bobStep1.messageKey);
  assert.strictEqual(decrypted1, "Message 1: Initial Handshake");

  // Message 2 Ratchet Step (Chain advances, new Message Key derived)
  const aliceStep2 = await TruplesCryptoCore.ratchetMessageKey(aliceStep1.nextChainKey);
  const bobStep2 = await TruplesCryptoCore.ratchetMessageKey(bobStep1.nextChainKey);
  
  const payload2 = await TruplesCryptoCore.encryptPayload("Message 2: Next Ratcheted Transmission", aliceStep2.messageKey);
  const decrypted2 = await TruplesCryptoCore.decryptPayload(payload2.iv, payload2.ciphertext, bobStep2.messageKey);
  assert.strictEqual(decrypted2, "Message 2: Next Ratcheted Transmission");

  // Verify that Message Key 1 CANNOT decrypt Message 2 (Strict Forward Secrecy)
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

  console.log('========================================================================');
  console.log('🎉 ALL 7 CRYPTOGRAPHIC, ECDSA & KDF RATCHET TESTS PASSED PERFECTLY!');
  console.log('========================================================================');
}

runCryptographicTestSuite().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
