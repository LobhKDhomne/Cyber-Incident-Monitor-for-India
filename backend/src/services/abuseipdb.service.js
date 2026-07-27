const axios = require('axios');
const config = require('../config');
const { getOrSet } = require('../utils/cache');

const BASE_URL = 'https://api.abuseipdb.com/api/v2';

function client() {
  return axios.create({
    baseURL: BASE_URL,
    headers: {
      Key: config.apiKeys.abuseIpDb,
      Accept: 'application/json',
    },
    timeout: 10000,
  });
}

/**
 * AbuseIPDB only supports IP addresses (v4/v6).
 */
async function lookup(type, value) {
  if (!['ipv4', 'ipv6'].includes(type)) {
    return { source: 'AbuseIPDB', available: false, error: 'AbuseIPDB only supports IP address lookups' };
  }
  if (!config.apiKeys.abuseIpDb) {
    return { source: 'AbuseIPDB', available: false, error: 'ABUSEIPDB_API_KEY not configured' };
  }

  const cacheKey = `abuseipdb:${value}`;

  const { data } = await getOrSet(cacheKey, async () => {
    const res = await client().get('/check', {
      params: { ipAddress: value, maxAgeInDays: 90, verbose: true },
    });
    const d = res.data?.data || {};

    return {
      source: 'AbuseIPDB',
      available: true,
      score: d.abuseConfidenceScore ?? 0,
      verdict: (d.abuseConfidenceScore ?? 0) >= 75 ? 'malicious' : (d.abuseConfidenceScore ?? 0) >= 25 ? 'suspicious' : 'clean',
      isPublic: d.isPublic,
      isTor: d.isTor,
      isWhitelisted: d.isWhitelisted,
      totalReports: d.totalReports,
      numDistinctUsers: d.numDistinctUsers,
      countryCode: d.countryCode,
      usageType: d.usageType,
      isp: d.isp,
      domain: d.domain,
      lastReportedAt: d.lastReportedAt,
      reports: (d.reports || []).slice(0, 5).map((r) => ({
        reportedAt: r.reportedAt,
        comment: r.comment,
        categories: r.categories,
      })),
    };
  });

  return data;
}

module.exports = { lookup };
