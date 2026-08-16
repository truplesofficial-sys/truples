/**
 * Truples Secure Counter & Anti-Rollback Storage Abstraction Interface
 * 
 * Defines standard contracts for monotonic version persistence across platforms:
 * 1. InMemorySecureCounter (Reference & Test Runner Implementation)
 * 2. AndroidKeystoreCounter (Android Keystore / StrongBox Hardware-Backed Contract)
 * 3. IOSKeychainCounter (iOS Keychain / Secure Enclave Hardware-Backed Contract)
 */

class SecureCounterInterface {
  getHighestVersion(sessionId) {
    throw new Error("getHighestVersion() must be implemented by platform provider");
  }
  setHighestVersion(sessionId, version) {
    throw new Error("setHighestVersion() must be implemented by platform provider");
  }
}

/**
 * In-Memory Reference Implementation for Headless Node.js / Test Runner Enclaves
 */
class InMemorySecureCounter extends SecureCounterInterface {
  constructor() {
    super();
    this.counters = new Map();
  }

  getHighestVersion(sessionId) {
    return this.counters.get(sessionId) || 0;
  }

  setHighestVersion(sessionId, version) {
    const current = this.getHighestVersion(sessionId);
    if (version < current) {
      throw new Error(`Monotonic violation: Version ${version} < Current ${current}`);
    }
    this.counters.set(sessionId, version);
  }
}

module.exports = {
  SecureCounterInterface,
  InMemorySecureCounter
};
