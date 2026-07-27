const axios = require('axios');
const config = require('../config');
const { getOrSet } = require('../utils/cache');

const CACHE_KEY = 'cisa:kev:catalog';
// KEV updates a handful of times a week at most - cache for 6 hours regardless of the
// global TTL to avoid hammering CISA's feed.
const KEV_TTL_SECONDS = 6 * 60 * 60;

async function fetchCatalog() {
  const { data } = await getOrSet(
    CACHE_KEY,
    async () => {
      const res = await axios.get(config.cisaKevUrl, { timeout: 15000 });
      return res.data;
    },
    KEV_TTL_SECONDS
  );
  return data;
}

/**
 * Full KEV catalog metadata + vulnerabilities list.
 */
async function getCatalog({ limit = 50, offset = 0 } = {}) {
  const catalog = await fetchCatalog();
  const vulns = catalog.vulnerabilities || [];
  return {
    source: 'CISA KEV',
    catalogVersion: catalog.catalogVersion,
    dateReleased: catalog.dateReleased,
    count: catalog.count,
    total: vulns.length,
    vulnerabilities: vulns.slice(offset, offset + limit),
  };
}

/**
 * Search the KEV catalog by CVE ID, vendor, or product substring.
 */
async function search(query) {
  const catalog = await fetchCatalog();
  const q = String(query || '').toLowerCase().trim();
  const vulns = catalog.vulnerabilities || [];
  if (!q) return vulns.slice(0, 50);

  return vulns
    .filter(
      (v) =>
        v.cveID?.toLowerCase().includes(q) ||
        v.vendorProject?.toLowerCase().includes(q) ||
        v.product?.toLowerCase().includes(q) ||
        v.vulnerabilityName?.toLowerCase().includes(q)
    )
    .slice(0, 100);
}

/**
 * Check whether a specific CVE ID is present in the KEV catalog.
 */
async function isKnownExploited(cveId) {
  const catalog = await fetchCatalog();
  const vulns = catalog.vulnerabilities || [];
  const match = vulns.find((v) => v.cveID?.toLowerCase() === String(cveId).toLowerCase());
  return match || null;
}

module.exports = { getCatalog, search, isKnownExploited };
