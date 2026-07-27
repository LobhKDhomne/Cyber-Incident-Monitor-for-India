require('dotenv').config();

function required(name, fallback = undefined) {
  const value = process.env[name] ?? fallback;
  return value;
}

module.exports = {
  port: Number(process.env.PORT || 4000),
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || '*',

  jwt: {
    secret: required('JWT_SECRET', 'insecure-dev-secret-change-me'),
    expiresIn: process.env.JWT_EXPIRES_IN || '8h',
  },

  apiKeys: {
    virusTotal: process.env.VIRUSTOTAL_API_KEY || '',
    abuseIpDb: process.env.ABUSEIPDB_API_KEY || '',
    otx: process.env.OTX_API_KEY || '',
  },

  cisaKevUrl:
    process.env.CISA_KEV_URL ||
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',

  cache: {
    ttlSeconds: Number(process.env.CACHE_TTL_SECONDS || 900),
  },

  rateLimit: {
    windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 60000),
    max: Number(process.env.RATE_LIMIT_MAX || 120),
  },
};
