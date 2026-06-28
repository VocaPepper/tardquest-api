const path = require('node:path');
const fs = require('node:fs');

const privatePath = path.join(process.cwd(), 'src', 'private', 'db', 'postgres.repository.js');
let impl;

if (fs.existsSync(privatePath)) {
  impl = require(privatePath);
} else {
  impl = {
    verifyCredentials: async () => ({ ok: false, error: 'Account service unavailable', username: null }),
    createAccount: async () => ({ ok: false, error: 'Account service unavailable' }),
    usernameExists: async () => ({ exists: null, error: 'Account service unavailable' }),
    ensureRecoverySchema: async () => {},
    normalizeRecoveryCode: () => '',
    formatRecoveryCode: () => '',
    hashRecoveryCode: () => '',
    generateRecoveryCodes: () => [],
    rotateRecoveryCodes: async () => ({ codes: null, error: 'Account service unavailable' }),
    resetPasswordWithRecoveryCode: async () => ({ ok: false, error: 'Account service unavailable' }),
    close: async () => {},
  };
}

module.exports = impl;
