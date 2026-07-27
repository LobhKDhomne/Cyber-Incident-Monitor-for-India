const axios = require('axios');
const config = require('../config');
const { getOrSet } = require('../utils/cache');

const BASE_URL = 'https://www.virustotal.com/api/v3';

function client() {
  return axios.create({
    baseURL: BASE_URL,
    headers: { 'x-apikey': config.apiKeys.virusTotal },
    timeout: 10000,
  });
}

function urlToVtId(url) {
  // VirusTotal identifies URLs by the base64url of the raw URL, no padding.
  return Buffer.from(url, 'utf-8').toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Normalize a VT "last_analysis_stats" object into a simple risk summary.
 */
function summarizeStats(stats = {}) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;
  const score = total > 0 ? Math.round(((malicious + suspicious * 0.5) / total) * 100) : 0;

  return { malicious, suspicious, harmless, undetected, total, score };
}

async function lookup(type, value) {
  if (!config.apiKeys.virusTotal) {
    return { source: 'VirusTotal', available: false, error: 'VIRUSTOTAL_API_KEY not configured' };
  }

  const cacheKey = `vt:${type}:${value}`;

  const { data } = await getOrSet(cacheKey, async () => {
    let path;
    if (type === 'ipv4' || type === 'ipv6') path = `/ip_addresses/${value}`;
    else if (type === 'domain') path = `/domains/${value}`;
    else if (type === 'url') path = `/urls/${urlToVtId(value)}`;
    else if (['md5', 'sha1', 'sha256'].includes(type)) path = `/files/${value}`;
    else throw Object.assign(new Error(`Unsupported IoC type for VirusTotal: ${type}`), { status: 400 });

    const res = await client().get(path);
    const attrs = res.data?.data?.attributes || {};
    const stats = summarizeStats(attrs.last_analysis_stats);

    return {
      source: 'VirusTotal',
      available: true,
      score: stats.score,
      verdict: stats.malicious > 0 ? 'malicious' : stats.suspicious > 0 ? 'suspicious' : 'clean',
      stats,
      reputation: attrs.reputation ?? null,
      categories: attrs.categories || {},
      tags: attrs.tags || [],
      lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      raw: { id: res.data?.data?.id, type: res.data?.data?.type },
    };
  });

  return data;
}

module.exports = { lookup };
