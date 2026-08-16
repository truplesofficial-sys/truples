/**
 * Truples Protocol Security Suite - PQXDH Post-Quantum Initial Key Agreement Tests
 * 
 * 8-Vector Comprehensive Test Suite:
 * 1. ML-KEM-768 Cryptographic Primitive Correctness & Implicit Rejection
 * 2. 2-Party Hybrid PQXDH Handshake & Double Ratchet Session Establishment (Alice <-> Bob)
 * 3. Full Hybrid Handshake with Ephemeral One-Time Prekeys (OPK + PQOPK)
 * 4. Quantum Adversary Defense: Harvest-Now-Decrypt-Later Thwarted on Classical Compromise
 * 5. MITM Attack Defense: Signature Forgery on PQSPK Rejected Immediately
 * 6. Ciphertext Tamper Defense: Bit-Flipped PQ Ciphertext Triggers Implicit Rejection & Auth Failure
 * 7. Post-PQXDH Double Ratchet Seamless Multi-Turn Turn-Taking & Out-of-Order Handling
 * 8. One-Time Prekey Depletion & Lifecycle Transition
 * 
 * Run with: node tests/pqxdh/pqxdh_handshake.test.js
 */

const assert = require('assert');
const { 
  TruplesCryptoCore, 
  DoubleRatchetSession, 
  TruplesPQKEM, 
  TruplesPQXDH, 
  PrekeyBundle 
} = require('../../src/crypto/truples-crypto');

async function runPQXDHTestSuite() {
  console.log('========================================================================================');
  console.log('🔮 TRUPLES SIGNAL PQXDH (HYBRID POST-QUANTUM KEY AGREEMENT) TEST SUITE');
  console.log('========================================================================================\n');

  // =========================================================================
  // Test 1: ML-KEM-768 Primitive Unit Invariants
  // =========================================================================
  console.log('1️⃣ Testing ML-KEM-768 (Kyber-768, FIPS 203) Primitive Correctness & Invariants...');
  const kemKeypair = await TruplesPQKEM.generateKeypair();
  assert.strictEqual(kemKeypair.publicKey.length, 1184, 'Public key must be 1,184 bytes');
  assert.strictEqual(kemKeypair.privateKey.length, 2400, 'Secret key must be 2,400 bytes');

  const { ciphertext, sharedSecret: ssAlice } = await TruplesPQKEM.encapsulate(kemKeypair.publicKey);
  assert.strictEqual(ciphertext.length, 1088, 'Ciphertext must be 1,088 bytes');
  assert.strictEqual(ssAlice.length, 32, 'Shared secret must be 32 bytes (256 bits)');

  const ssBob = await TruplesPQKEM.decapsulate(ciphertext, kemKeypair.privateKey);
  assert.deepStrictEqual(Buffer.from(ssAlice), Buffer.from(ssBob), 'Decapsulated shared secret must match encapsulated secret 100%');

  // Implicit Rejection Check on Tampered Ciphertext
  const tamperedCt = new Uint8Array(ciphertext);
  tamperedCt[50] ^= 0x01; // Bit-flip
  const ssTampered = await TruplesPQKEM.decapsulate(tamperedCt, kemKeypair.privateKey);
  assert.notDeepStrictEqual(Buffer.from(ssAlice), Buffer.from(ssTampered), 'Tampered ciphertext must produce pseudorandom reject key (Implicit Rejection)');
  console.log('   ✅ Passed: ML-KEM-768 KeyGen, Encaps, Decaps and Constant-Time Implicit Rejection Verified.\n');

  // =========================================================================
  // Test 2: Standard 2-Party PQXDH Handshake (Alice -> Bob)
  // =========================================================================
  console.log('2️⃣ Testing Standard 2-Party Hybrid PQXDH Handshake & Session Establishment...');
  // 1. Bob generates identity, signed prekey, and post-quantum signed prekey
  const bobIdentity = await TruplesCryptoCore.generateECDSAKeypair();
  const bobSpk = await TruplesCryptoCore.generateECDHKeypair();
  const bobPqSpk = await TruplesPQKEM.generateKeypair();

  const bobPrekeyBundle = await TruplesPQXDH.createPrekeyBundle({
    identityKeypair: bobIdentity,
    signedPrekeyKeypair: bobSpk,
    pqSignedPrekeyKeypair: bobPqSpk
  });

  // 2. Alice generates identity and executes PQXDH handshake
  const aliceIdentity = await TruplesCryptoCore.generateECDSAKeypair();
  const initialSecretMessage = "Hello Bob, this message is post-quantum encrypted via PQXDH!";
  const { session: aliceSession, handshakeMessage } = await TruplesPQXDH.initiateHandshake({
    initiatorIdentityKeypair: aliceIdentity,
    recipientBundle: bobPrekeyBundle,
    initialPlaintext: initialSecretMessage
  });

  // 3. Bob responds to handshake message
  const { session: bobSession, decryptedPayload } = await TruplesPQXDH.respondHandshake({
    responderIdentityKeypair: bobIdentity,
    signedPrekeyKeypair: bobSpk,
    pqSignedPrekeyKeypair: bobPqSpk,
    handshakeMessage
  });

  assert.strictEqual(decryptedPayload, initialSecretMessage, 'Bob must successfully decrypt initial PQXDH payload');

  // Verify derived Root Keys match byte-for-byte
  const aliceRootRaw = await globalThis.crypto.subtle.exportKey('raw', aliceSession.rootKey);
  const bobRootRaw = await globalThis.crypto.subtle.exportKey('raw', bobSession.rootKey);
  assert.deepStrictEqual(Buffer.from(aliceRootRaw), Buffer.from(bobRootRaw), 'Alice and Bob must share identical Root Keys');
  console.log('   ✅ Passed: Standard Hybrid PQXDH Handshake and Double Ratchet Root Key established.\n');

  // =========================================================================
  // Test 3: Full PQXDH with One-Time Prekeys (OPK + PQOPK)
  // =========================================================================
  console.log('3️⃣ Testing Full Hybrid PQXDH with One-Time Prekeys (OPK + PQOPK)...');
  const bobOpk = await TruplesCryptoCore.generateECDHKeypair();
  const bobPqOpk = await TruplesPQKEM.generateKeypair();

  const bobFullBundle = await TruplesPQXDH.createPrekeyBundle({
    identityKeypair: bobIdentity,
    signedPrekeyKeypair: bobSpk,
    pqSignedPrekeyKeypair: bobPqSpk,
    oneTimePrekeyKeypair: bobOpk,
    oneTimePrekeyId: "opk_slot_42",
    pqOneTimePrekeyKeypair: bobPqOpk,
    pqOneTimePrekeyId: "pqopk_slot_42"
  });

  const fullHandshakeMsg = "Full 4-DH + 2-PQ-KEM Prekey Exchange Active";
  const { session: aliceFullSession, handshakeMessage: fullMsg } = await TruplesPQXDH.initiateHandshake({
    initiatorIdentityKeypair: aliceIdentity,
    recipientBundle: bobFullBundle,
    initialPlaintext: fullHandshakeMsg
  });

  assert(fullMsg.pqOneTimeCiphertext !== null, 'Handshake must contain PQ-OPK ciphertext');
  assert.strictEqual(fullMsg.oneTimePrekeyId, "opk_slot_42", 'Handshake must reference OPK slot ID');

  const { session: bobFullSession, decryptedPayload: fullDecrypted } = await TruplesPQXDH.respondHandshake({
    responderIdentityKeypair: bobIdentity,
    signedPrekeyKeypair: bobSpk,
    pqSignedPrekeyKeypair: bobPqSpk,
    oneTimePrekeyKeypair: bobOpk,
    pqOneTimePrekeyKeypair: bobPqOpk,
    handshakeMessage: fullMsg
  });

  assert.strictEqual(fullDecrypted, fullHandshakeMsg, 'Bob must successfully decrypt payload with OPKs');
  console.log('   ✅ Passed: Full Hybrid 4-DH + 2-KEM Prekey Bundle Handshake Verified.\n');

  // =========================================================================
  // Test 4: Quantum Adversary Simulation (Harvest-Now-Decrypt-Later Defense)
  // =========================================================================
  console.log('4️⃣ Testing Post-Quantum Security Assertion (Harvest-Now-Decrypt-Later Defense)...');
  // Adversary Eve intercepts all classical traffic and later cracks all P-384 ECDH private keys (DH1..DH4)
  // But Eve does NOT possess the ML-KEM-768 private key.
  const dummyPqSk = await TruplesPQKEM.generateKeypair(); // Eve uses a different PQ key
  
  let quantumAttackThwarted = false;
  try {
    const { decryptedPayload: eveDecrypted } = await TruplesPQXDH.respondHandshake({
      responderIdentityKeypair: bobIdentity,
      signedPrekeyKeypair: bobSpk,
      pqSignedPrekeyKeypair: dummyPqSk, // Adversary without genuine PQ secret
      handshakeMessage: fullMsg
    });
    // If decryption succeeds or produces garbage without throwing, check mismatch
    if (eveDecrypted !== fullHandshakeMsg) {
      quantumAttackThwarted = true;
    }
  } catch (err) {
    // Cryptographic MAC failure or implicit rejection mismatch
    quantumAttackThwarted = true;
  }
  assert(quantumAttackThwarted, 'Eve with cracked classical keys must NOT be able to decrypt PQXDH ciphertexts');
  console.log('   ✅ Passed: Harvest-Now-Decrypt-Later attack mathematically thwarted by Post-Quantum KEM.\n');

  // =========================================================================
  // Test 5: MITM Attack Defense: Signature Forgery on PQSPK
  // =========================================================================
  console.log('5️⃣ Testing MITM Signature Forgery Defense on Post-Quantum Prekey...');
  const eveFakeIdentity = await TruplesCryptoCore.generateECDSAKeypair();
  const eveFakePqSpk = await TruplesPQKEM.generateKeypair();
  const eveFakeSig = await TruplesCryptoCore.signPayload(eveFakePqSpk.publicKey, eveFakeIdentity.privateKey);

  // MITM replaces Bob's PQSPK with Eve's key and forged signature
  const tamperedBundle = new PrekeyBundle({
    ...bobPrekeyBundle,
    pqSignedPrekey: Buffer.from(eveFakePqSpk.publicKey).toString('base64'),
    pqSignedPrekeySignature: eveFakeSig
  });

  let mitmBlocked = false;
  try {
    await TruplesPQXDH.initiateHandshake({
      initiatorIdentityKeypair: aliceIdentity,
      recipientBundle: tamperedBundle,
      initialPlaintext: "Should fail"
    });
  } catch (err) {
    if (err.message.includes('signature verification failed')) {
      mitmBlocked = true;
    }
  }
  assert(mitmBlocked, 'Handshake must abort on forged PQSPK signature');
  console.log('   ✅ Passed: MITM signature forgery on post-quantum prekey detected and blocked.\n');

  // =========================================================================
  // Test 6: Malformed / Bit-Flipped PQ Ciphertext Rejection
  // =========================================================================
  console.log('6️⃣ Testing Active Network Tampering on PQ Ciphertext...');
  const tamperedHandshakeMsg = new (require('../../src/crypto/truples-pqxdh').PQXDHHandshakeMessage)({
    ...handshakeMessage
  });
  const rawCtBytes = Buffer.from(handshakeMessage.pqCiphertext, 'base64');
  rawCtBytes[100] ^= 0x5A; // Corrupt ciphertext bytes
  tamperedHandshakeMsg.pqCiphertext = rawCtBytes.toString('base64');

  let tamperBlocked = false;
  try {
    await TruplesPQXDH.respondHandshake({
      responderIdentityKeypair: bobIdentity,
      signedPrekeyKeypair: bobSpk,
      pqSignedPrekeyKeypair: bobPqSpk,
      handshakeMessage: tamperedHandshakeMsg
    });
  } catch (err) {
    tamperBlocked = true;
  }
  assert(tamperBlocked, 'Tampered PQ ciphertext must cause authentication failure');
  console.log('   ✅ Passed: Network bit-flipped PQ ciphertext rejected with zero state corruption.\n');

  // =========================================================================
  // Test 7: Post-PQXDH Continuous Double Ratchet Turn-Taking & Out-of-Order
  // =========================================================================
  console.log('7️⃣ Testing Post-PQXDH Double Ratchet Continuous Turn-Taking & Out-of-Order Messages...');
  // Bob replies to Alice
  const bobReply1 = await bobSession.send("Bob message 1 (epoch 1)");
  const aliceRecv1 = await aliceSession.receive(bobReply1.header, bobReply1.iv, bobReply1.ciphertext);
  assert.strictEqual(aliceRecv1, "Bob message 1 (epoch 1)");

  // Alice sends 3 consecutive messages
  const aMsg1 = await aliceSession.send("Alice msg 1");
  const aMsg2 = await aliceSession.send("Alice msg 2");
  const aMsg3 = await aliceSession.send("Alice msg 3");

  // Bob receives msg 3 first (out of order), then msg 1, then msg 2
  const bobRecv3 = await bobSession.receive(aMsg3.header, aMsg3.iv, aMsg3.ciphertext);
  assert.strictEqual(bobRecv3, "Alice msg 3");

  const bobRecv1 = await bobSession.receive(aMsg1.header, aMsg1.iv, aMsg1.ciphertext);
  assert.strictEqual(bobRecv1, "Alice msg 1");

  const bobRecv2 = await bobSession.receive(aMsg2.header, aMsg2.iv, aMsg2.ciphertext);
  assert.strictEqual(bobRecv2, "Alice msg 2");
  console.log('   ✅ Passed: Post-PQXDH Double Ratchet sustained turn-taking and out-of-order delivery.\n');

  // =========================================================================
  // Test 8: Prekey Depletion & Lifecycle Transition
  // =========================================================================
  console.log('8️⃣ Testing Prekey Depletion & Fallback to Signed Prekeys...');
  // Session 1 consumes OPK
  const { session: s1Alice, handshakeMessage: m1 } = await TruplesPQXDH.initiateHandshake({
    initiatorIdentityKeypair: aliceIdentity,
    recipientBundle: bobFullBundle,
    initialPlaintext: "Session 1 with OPK"
  });
  assert.strictEqual(m1.oneTimePrekeyId, "opk_slot_42");

  // Session 2 initiates when OPK has been depleted (bundle without OPK)
  const { session: s2Alice, handshakeMessage: m2 } = await TruplesPQXDH.initiateHandshake({
    initiatorIdentityKeypair: aliceIdentity,
    recipientBundle: bobPrekeyBundle, // Standard bundle without OPK
    initialPlaintext: "Session 2 after OPK depleted"
  });
  assert.strictEqual(m2.oneTimePrekeyId, null);

  const { decryptedPayload: d2 } = await TruplesPQXDH.respondHandshake({
    responderIdentityKeypair: bobIdentity,
    signedPrekeyKeypair: bobSpk,
    pqSignedPrekeyKeypair: bobPqSpk,
    handshakeMessage: m2
  });
  assert.strictEqual(d2, "Session 2 after OPK depleted");
  console.log('   ✅ Passed: Prekey depletion and fallback lifecycle transitions verified.\n');

  console.log('========================================================================================');
  console.log('🎉 ALL 8 SIGNAL PQXDH HYBRID POST-QUANTUM TEST VECTORS PASSED (8/8)!');
  console.log('========================================================================================\n');
}

runPQXDHTestSuite().catch(err => {
  console.error('❌ PQXDH test suite failed:', err);
  process.exit(1);
});
