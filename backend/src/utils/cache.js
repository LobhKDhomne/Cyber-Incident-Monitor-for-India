const NodeCache = require('node-cache');
const config = require('../config');

// stdTTL in seconds; checkperiod cleans expired keys periodically
const cache = new NodeCache({
  stdTTL: config.cache.ttlSeconds,
  checkperiod: Math.max(60, Math.floor(config.cache.ttlSeconds / 2)),
});

/**
 * Get a cached value, or compute + cache it via `loader` if missing/expired.
 * @param {string} key
 * @param {() => Promise<any>} loader
 * @param {number} [ttlSeconds]
 */
async function getOrSet(key, loader, ttlSeconds) {
  const hit = cache.get(key);
  if (hit !== undefined) {
    return { data: hit, cached: true };
  }
  const data = await loader();
  cache.set(key, data, ttlSeconds ?? config.cache.ttlSeconds);
  return { data, cached: false };
}

module.exports = { cache, getOrSet };
