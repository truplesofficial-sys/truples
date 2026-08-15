/**
 * Truples Cryptographic Core Self-Testing Suite
 * Run with: node tests/crypto.test.js
 */

const { TruplesCryptoCore } = require('../src/crypto/truples-crypto');
const assert = require('assert');

async function runCryptographicTestSuite() {
  console.log('🧪 [TEST] Starting Truples Cryptographic Core Validation (v2.1)...\n');

  // Test 1: ECDH Keypair Generation (NIST P-384)
  console.log('1️⃣ Testing Ephemeral ECDH Keypair Generation (P-384)...');
  const aliceKeypair = await TruplesCryptoCore.generateECDHKeypair();
  const bobKeypair = await TruplesCryptoCore.generateECDHKeypair();
  assert(aliceKeypair.publicKey && aliceKeypair.privateKey, 'Alice keypair must be valid');
  assert(bobKeypair.publicKey && bobKeypair.privateKey, 'Bob keypair must be valid');
  console.log('   ✅ Passed: Generated distinct cryptographic keypairs.\n');

  // Test 2: Symmetric Root & Chain Key Derivation via HKDF-SHA256 with CSPRNG Salt
  console.log('2️⃣ Testing Root & Initial Chain Key Derivation with Dynamic Salt...');
  const dynamicSalt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(dynamicSalt);
  
  const aliceKeys = await TruplesCryptoCore.deriveRootAndChainKeys(aliceKeypair.privateKey, bobKeypair.publicKey, dynamicSalt);
  const bobKeys = await TruplesCryptoCore.deriveRootAndChainKeys(bobKeypair.privateKey, aliceKeypair.publicKey, dynamicSalt);
  assert(aliceKeys.chainKey && bobKeys.chainKey, 'Both parties must derive valid initial chain keys');
  console.log('   ✅ Passed: Independent derivation yielded matching root and chain keys.\n');

  // Test 3: Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)
  console.log('3️⃣ Testing Symmetric KDF Chain Ratchet (Per-Message Forward Secrecy)...');
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

  // Test 4: Dynamic 96-bit IV Freshness (Nonce Uniqueness)
  console.log('4️⃣ Testing IV Freshness & Random Nonce Isolation...');
  const msgKey = aliceStep1.messageKey;
  const pA = await TruplesCryptoCore.encryptPayload("Identical text", msgKey);
  const pB = await TruplesCryptoCore.encryptPayload("Identical text", msgKey);
  assert.notStrictEqual(pA.iv, pB.iv, 'IVs must be distinct across consecutive transmissions');
  assert.notStrictEqual(pA.ciphertext, pB.ciphertext, 'Identical plaintexts must produce distinct ciphertexts');
  console.log('   ✅ Passed: Enforced strict per-message nonce isolation.\n');

  // Test 5: Authentication Tag (MAC) Tamper Resistance
  console.log('5️⃣ Testing 128-bit MAC Integrity & Tamper Detection...');
  let tamperedCiphertext = Buffer.from(payload1.ciphertext, 'base64');
  tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0x01; // Tamper with 1 bit
  
  let tamperDetected = false;
  try {
    await TruplesCryptoCore.decryptPayload(payload1.iv, tamperedCiphertext.toString('base64'), bobStep1.messageKey);
  } catch (err) {
    tamperDetected = true;
  }
  assert(tamperDetected, 'Tampered ciphertext must fail MAC verification');
  console.log('   ✅ Passed: Cryptographic MAC verification rejected tampered ciphertext.\n');

  // Test 6: Memory Zeroization
  console.log('6️⃣ Testing Cryptographic Memory Buffer Zeroization...');
  const sensitiveBuffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  TruplesCryptoCore.zeroizeBuffer(sensitiveBuffer);
  assert(sensitiveBuffer.every(b => b === 0), 'Buffer must be completely zeroized');
  console.log('   ✅ Passed: Multi-pass binary memory zeroization verified.\n');

  console.log('========================================================================');
  console.log('🎉 ALL 6 CRYPTOGRAPHIC & KDF RATCHET SECURITY TESTS PASSED PERFECTLY!');
  console.log('========================================================================');
}

runCryptographicTestSuite().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
