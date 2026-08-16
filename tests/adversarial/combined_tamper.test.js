/**
 * Truples Adversarial Combined Multi-Vector Tamper & State Invariance Test Suite
 * 
 * Executes simultaneous catastrophic multi-vector attacks:
 * 1. Simulates simultaneous tampering across:
 *    - Ephemeral DH Public Key coordinate mutation
 *    - Previous Chain Length (PN) integer forgery
 *    - Message Sequence Number (N) integer forgery
 *    - Ciphertext Bit-Flip payload mutation
 * 2. Proves that upon decryption failure, ALL 11 internal session state variables:
 *    [RK, CKs, CKr, DHs, DHr, Ns, Nr, PN, MKSKIPPED, MKCONSUMED]
 *    remain 100% byte-for-byte identical to pre-attack baseline state (Zero State Corruption).
 */

const { TruplesCryptoCore, DoubleRatchetSession } = require('../../src/crypto/truples-crypto');
const crypto = require('crypto');
const assert = require('assert');

async function computeStateDigest(session) {
  const raw = await session.exportRawSnapshot();
  const hash = crypto.createHash('sha256');
  hash.update(JSON.stringify(raw));
  return hash.digest('hex');
}

async function runCombinedTamperStateInvarianceSuite() {
  console.log('🧪 [ADVERSARIAL] Starting Combined Multi-Vector Tamper & State Invariance Suite...\n');

  const aliceEcdh = await TruplesCryptoCore.generateECDHKeypair();
  const bobEcdh = await TruplesCryptoCore.generateECDHKeypair();
  const salt = new Uint8Array(32).fill(0x99);

  const aKeys = await TruplesCryptoCore.deriveRootAndChainKeys(aliceEcdh.privateKey, bobEcdh.publicKey, salt, 'initiator');
  const bKeys = await TruplesCryptoCore.deriveRootAndChainKeys(bobEcdh.privateKey, aliceEcdh.publicKey, salt, 'responder');

  const alice = new DoubleRatchetSession({
    rootKey: aKeys.rootKey,
    sendingChainKey: aKeys.sendingChainKey,
    receivingChainKey: aKeys.receivingChainKey,
    localDhKeypair: aliceEcdh,
    remoteDhPublicKey: bobEcdh.publicKey,
    role: 'initiator'
  });

  const bob = new DoubleRatchetSession({
    rootKey: bKeys.rootKey,
    sendingChainKey: bKeys.sendingChainKey,
    receivingChainKey: bKeys.receivingChainKey,
    localDhKeypair: bobEcdh,
    remoteDhPublicKey: aliceEcdh.publicKey,
    role: 'responder'
  });

  // Warmup normal communication to build baseline state
  const m1 = await alice.send("Initial Baseline Packet");
  await bob.receive(m1.header, m1.iv, m1.ciphertext);

  // Capture Bob's Pre-Attack Full State Digest
  const preAttackStateDigest = await computeStateDigest(bob);
  console.log(`🔒 Pre-Attack Bob Session State Digest: [${preAttackStateDigest}]`);

  // Alice generates message #2
  const m2 = await alice.send("Target Payload for Multi-Vector Attack");

  // Adversary crafts a catastrophically forged packet:
  // 1. Forged DH Key (substituting with completely random P-384 key)
  const attackerEcdh = await TruplesCryptoCore.generateECDHKeypair();
  const forgedHeader = {
    ...m2.header,
    dhPublicKey: attackerEcdh.publicKey,
    previousChainLength: 9999, // Forged PN
    messageNumber: 8888        // Forged N
  };

  // 2. Mutated Ciphertext (Bit-flip)
  const tamperedCipherBytes = Buffer.from(m2.ciphertext, 'base64');
  tamperedCipherBytes[0] ^= 0xFF;
  const tamperedCipherBase64 = tamperedCipherBytes.toString('base64');

  console.log('⚡ Injecting Simultaneous Multi-Vector Attack (Forged DH + Forged PN + Forged N + Tampered Ciphertext)...');
  let attackBlocked = false;
  try {
    await bob.receive(forgedHeader, m2.iv, tamperedCipherBase64);
  } catch (err) {
    attackBlocked = true;
  }
  assert(attackBlocked, 'Combined multi-vector attack MUST be rejected');

  // Verify Post-Attack State Digest is 100% IDENTICAL to Pre-Attack Baseline
  const postAttackStateDigest = await computeStateDigest(bob);
  console.log(`🔒 Post-Attack Bob Session State Digest: [${postAttackStateDigest}]`);
  assert.strictEqual(postAttackStateDigest, preAttackStateDigest, 'Session state MUST be 100% uncorrupted after multi-vector rejection');
  console.log('   ✅ Passed: Catastrophic multi-vector attack rejected with ZERO state corruption.\n');

  // Alice sends message #3 normally -> Bob must still receive and decrypt seamlessly
  console.log('🔄 Verifying Session Liveness: Alice sends Message #3 normally...');
  const m3 = await alice.send("Post-Attack Legitimate Message #3");
  const decM3 = await bob.receive(m3.header, m3.iv, m3.ciphertext);
  assert.strictEqual(decM3, "Post-Attack Legitimate Message #3");
  console.log('   ✅ Passed: Session ratcheting continued seamlessly with 0 deadlocks.\n');

  console.log('========================================================================================');
  console.log('🎉 COMBINED MULTI-VECTOR TAMPER & STATE INVARIANCE TESTS PASSED (100% INVARIANT)!');
  console.log('========================================================================================');
}

runCombinedTamperStateInvarianceSuite().catch(err => {
  console.error('❌ Combined tamper test failed:', err);
  process.exit(1);
});
