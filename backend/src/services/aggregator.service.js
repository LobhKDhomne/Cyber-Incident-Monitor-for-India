const virusTotal = require('./virustotal.service');
const abuseIpDb = require('./abuseipdb.service');
const otx = require('./otx.service');
const { detectIocType } = require('../utils/iocDetector');
const logger = require('../utils/logger');

const VERDICT_WEIGHT = { malicious: 2, suspicious: 1, clean: 0 };

/**
 * Query every source that supports this IoC type, in parallel, and never
 * let one source's failure take down the whole lookup.
 */
async function queryAllSources(type, value) {
  const jobs = [
    { name: 'virustotal', fn: () => virusTotal.lookup(type, value) },
    { name: 'abuseipdb', fn: () => abuseIpDb.lookup(type, value) },
    { name: 'otx', fn: () => otx.lookup(type, value) },
  ];

  const settled = await Promise.allSettled(jobs.map((j) => j.fn()));

  return settled.map((result, i) => {
    if (result.status === 'fulfilled') return result.value;
    logger.warn(`${jobs[i].name} lookup failed:`, result.reason?.message || result.reason);
    return {
      source: jobs[i].name,
      available: false,
      error: result.reason?.response?.data?.error?.message || result.reason?.message || 'Lookup failed',
    };
  });
}

function buildConsensus(sourceResults) {
  const usable = sourceResults.filter((r) => r.available && typeof r.score === 'number');

  if (usable.length === 0) {
    return { threatScore: 0, verdict: 'unknown', confidence: 0, sourcesQueried: sourceResults.length, sourcesAvailable: 0 };
  }

  const avgScore = Math.round(usable.reduce((sum, r) => sum + r.score, 0) / usable.length);
  const verdictSum = usable.reduce((sum, r) => sum + (VERDICT_WEIGHT[r.verdict] ?? 0), 0);
  const verdictAvg = verdictSum / usable.length;

  let verdict = 'clean';
  if (verdictAvg >= 1.25) verdict = 'malicious';
  else if (verdictAvg >= 0.4) verdict = 'suspicious';

  // Confidence rises with source agreement and how many sources responded
  const confidence = Math.min(100, Math.round((usable.length / sourceResults.length) * 70 + Math.min(usable.length, 3) * 10));

  return {
    threatScore: avgScore,
    verdict,
    confidence,
    sourcesQueried: sourceResults.length,
    sourcesAvailable: usable.length,
  };
}

/**
 * Full pipeline: detect type -> fan out to sources -> build consensus.
 * @param {string} rawIndicator
 */
async function lookupIndicator(rawIndicator) {
  const { type, value } = detectIocType(rawIndicator);

  if (type === 'unknown') {
    const err = new Error('Could not determine indicator type (expected IP, domain, URL, or file hash)');
    err.status = 400;
    throw err;
  }

  const sources = await queryAllSources(type, value);
  const consensus = buildConsensus(sources);

  return {
    indicator: value,
    type,
    ...consensus,
    firstSeen: sources.find((s) => s.available)?.lastAnalysisDate || null,
    sources,
    checkedAt: new Date().toISOString(),
  };
}

async function lookupBulk(indicators) {
  const unique = [...new Set(indicators.map((i) => String(i).trim()).filter(Boolean))].slice(0, 25);
  const results = await Promise.allSettled(unique.map((ind) => lookupIndicator(ind)));

  return results.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    return { indicator: unique[i], error: r.reason?.message || 'Lookup failed' };
  });
}

module.exports = { lookupIndicator, lookupBulk, queryAllSources, buildConsensus };
