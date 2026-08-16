/**
 * Truples Concurrent Snapshot & Atomic CAS Commit Stress Test Suite
 * 
 * Simulates 100 highly concurrent asynchronous session snapshot restoration requests:
 * 1. Proves that atomic Compare-And-Set (CAS) prevents monotonic counter race conditions.
 * 2. Proves that out-of-order concurrent restorations (e.g. V10, V50, V12, V99, V5) strictly converge
 *    to the maximum verified monotonic version without sequence corruption.
 */

const { InMemorySecureCounter } = require('../../src/crypto/secure-counter');
const assert = require('assert');

async function runConcurrentSnapshotCasSuite() {
  console.log('🧪 [CRASH/CONCURRENT] Starting Atomic CAS Concurrent Snapshot Restoration Test Suite...\n');

  const counter = new InMemorySecureCounter();
  const sessionId = "concurrent_stress_session_001";

  // Simulate 100 concurrent threads attempting randomized snapshot restorations
  const TOTAL_OPERATIONS = 100;
  const versions = Array.from({ length: TOTAL_OPERATIONS }, (_, i) => i + 1);
  
  // Shuffle versions randomly
  for (let i = versions.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [versions[i], versions[j]] = [versions[j], versions[i]];
  }

  console.log(`⚡ Dispatching ${TOTAL_OPERATIONS} Concurrent Snapshot Restoration Requests in Randomized Order...`);

  let successfulCommits = 0;
  let blockedRollbacks = 0;

  const promises = versions.map(async (v) => {
    // Artificial micro-delay to maximize concurrency interleaving
    await new Promise(r => setTimeout(r, Math.random() * 20));

    const currentVersion = counter.getHighestVersion(sessionId);
    if (v > currentVersion) {
      const casResult = counter.compareAndSetVersion(sessionId, currentVersion, v);
      if (casResult) {
        successfulCommits++;
      } else {
        // CAS conflict occurred: another higher version was committed concurrently
        blockedRollbacks++;
      }
    } else {
      // Historical version: strictly blocked
      blockedRollbacks++;
    }
  });

  await Promise.all(promises);

  const finalMonotonicVersion = counter.getHighestVersion(sessionId);
  console.log(`🔒 Final Committed Monotonic Version: ${finalMonotonicVersion} (Expected: ${TOTAL_OPERATIONS})`);
  console.log(`📊 Successful Atomic Commits: ${successfulCommits} | Blocked Rollback/Race Interceptions: ${blockedRollbacks}`);

  assert.strictEqual(finalMonotonicVersion, TOTAL_OPERATIONS, 'Final version must strictly equal highest version (100)');
  assert(successfulCommits > 0, 'Must have recorded successful commits');
  assert.strictEqual(successfulCommits + blockedRollbacks, TOTAL_OPERATIONS, 'All operations accounted for');

  console.log('\n========================================================================================');
  console.log('🎉 ATOMIC CAS CONCURRENT SNAPSHOT RESTORATION TESTS PASSED (100% MONOTONIC)!');
  console.log('========================================================================================');
}

runConcurrentSnapshotCasSuite().catch(err => {
  console.error('❌ Concurrent test failed:', err);
  process.exit(1);
});
