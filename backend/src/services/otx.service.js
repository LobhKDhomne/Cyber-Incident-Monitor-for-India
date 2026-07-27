const axios = require('axios');
const config = require('../config');
const { getOrSet } = require('../utils/cache');

const BASE_URL = 'https://otx.alienvault.com/api/v1';

// Map our internal IoC types to OTX's "indicator" path segments
const OTX_TYPE_MAP = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  domain: 'domain',
  url: 'url',
  md5: 'file',
  sha1: 'file',
  sha256: 'file',
};

function client() {
  return axios.create({
    baseURL: BASE_URL,
    headers: { 'X-OTX-API-KEY': config.apiKeys.otx },
    timeout: 10000,
  });
}

async function lookup(type, value) {
  const otxType = OTX_TYPE_MAP[type];
  if (!otxType) {
    return { source: 'AlienVault OTX', available: false, error: `Unsupported IoC type for OTX: ${type}` };
  }
  if (!config.apiKeys.otx) {
    return { source: 'AlienVault OTX', available: false, error: 'OTX_API_KEY not configured' };
  }

  const cacheKey = `otx:${type}:${value}`;

  const { data } = await getOrSet(cacheKey, async () => {
    const encoded = encodeURIComponent(value);
    const [generalRes, reputationRes] = await Promise.allSettled([
      client().get(`/indicators/${otxType}/${encoded}/general`),
      otxType === 'IPv4' || otxType === 'IPv6'
        ? client().get(`/indicators/${otxType}/${encoded}/reputation`)
        : Promise.resolve(null),
    ]);

    if (generalRes.status !== 'fulfilled') {
      throw generalRes.reason;
    }

    const general = generalRes.value.data || {};
    const pulseCount = general.pulse_info?.count ?? 0;
    const pulses = (general.pulse_info?.pulses || []).slice(0, 5).map((p) => ({
      name: p.name,
      tags: p.tags,
      malwareFamilies: p.malware_families,
      adversary: p.adversary,
      created: p.created,
    }));

    const reputation =
      reputationRes.status === 'fulfilled' && reputationRes.value ? reputationRes.value.data?.reputation : null;

    return {
      source: 'AlienVault OTX',
      available: true,
      score: Math.min(100, pulseCount * 10),
      verdict: pulseCount > 5 ? 'malicious' : pulseCount > 0 ? 'suspicious' : 'clean',
      pulseCount,
      pulses,
      reputation,
      tags: general.pulse_info?.tags || [],
      countryName: general.country_name || null,
      asn: general.asn || null,
    };
  });

  return data;
}

async function getSubscribedPulsesImpl({ limit = 20 } = {}) {
  if (!config.apiKeys.otx) {
    return { source: 'AlienVault OTX', available: false, error: 'OTX_API_KEY not configured', pulses: [] };
  }

  const cacheKey = `otx:pulses:subscribed:${limit}`;

  const { data } = await getOrSet(
    cacheKey,
    async () => {
      const res = await client().get('/pulses/subscribed', { params: { limit } });
      const results = res.data?.results || [];
      return {
        source: 'AlienVault OTX',
        available: true,
        pulses: results.map((p) => ({
          id: p.id,
          name: p.name,
          description: p.description,
          author: p.author_name,
          created: p.created,
          modified: p.modified,
          tags: p.tags,
          malwareFamilies: p.malware_families,
          indicatorCount: p.indicator_count ?? (p.indicators || []).length,
          targetedCountries: p.targeted_countries,
          references: p.references,
        })),
      };
    },
    600 // 10 min
  );

  return data;
}

module.exports = { lookup, getSubscribedPulses: getSubscribedPulsesImpl };
