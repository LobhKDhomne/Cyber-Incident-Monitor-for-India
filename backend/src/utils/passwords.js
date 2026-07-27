const crypto = require('crypto');

const KEY_LEN = 64;

/**
 * Hash a plaintext password. Returns "salt:hash" (both hex).
 * @param {string} password
 * @returns {Promise<string>}
 */
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, KEY_LEN, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`${salt}:${derivedKey.toString('hex')}`);
    });
  });
}

/**
 * Verify a plaintext password against a stored "salt:hash" string.
 * @param {string} password
 * @param {string} stored
 * @returns {Promise<boolean>}
 */
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const [salt, hash] = String(stored || '').split(':');
    if (!salt || !hash) return resolve(false);
    crypto.scrypt(password, salt, KEY_LEN, (err, derivedKey) => {
      if (err) return reject(err);
      const hashBuf = Buffer.from(hash, 'hex');
      if (hashBuf.length !== derivedKey.length) return resolve(false);
      resolve(crypto.timingSafeEqual(hashBuf, derivedKey));
    });
  });
}

module.exports = { hashPassword, verifyPassword };
