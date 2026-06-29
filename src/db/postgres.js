const path = require('node:path');
const fs = require('node:fs');
const config = require('../config');
const logger = require('../utils/logger');

const privatePath = path.join(process.cwd(), 'src', 'private', 'db', 'postgres.repository.js');

if (fs.existsSync(privatePath)) {
  const create = require(privatePath);
  module.exports = create(config, logger);
} else {
  module.exports = {
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
    hashOnlineToken: () => '',
    createOnlineAuthSession: async () => null,
    verifyOnlineAuthToken: async () => ({ valid: false, error: 'Online auth service unavailable' }),
    deleteSessionsByUsername: async () => 0,
    close: async () => {},
  };
}
