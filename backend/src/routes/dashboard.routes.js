const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { readCollection } = require('../utils/jsonStore');
const cisa = require('../services/cisa.service');

const router = express.Router();

router.get('/summary', requireAuth, async (req, res, next) => {
  try {
    const history = readCollection('ioc_history', []);
    const activeThreats = history.filter((h) => h.verdict === 'malicious').length;
    const suspicious = history.filter((h) => h.verdict === 'suspicious').length;
    const totalAnalyzed = history.length;

    let kevCount = null;
    try {
      const catalog = await cisa.getCatalog({ limit: 1 });
      kevCount = catalog.count ?? catalog.total ?? null;
    } catch (_) {
      kevCount = null; // CISA feed unreachable - don't fail the whole dashboard
    }

    const avgConfidence = totalAnalyzed
      ? Math.round(history.reduce((sum, h) => sum + (h.confidence || 0), 0) / totalAnalyzed)
      : 0;

    res.json({
      activeThreats,
      suspiciousIndicators: suspicious,
      totalIndicatorsAnalyzed: totalAnalyzed,
      knownExploitedVulnerabilities: kevCount,
      averageConfidence: avgConfidence,
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

router.get('/trends', requireAuth, (req, res) => {
  const days = Math.min(Number(req.query.days) || 7, 90);
  const history = readCollection('ioc_history', []);

  const buckets = {};
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    buckets[key] = { date: key, malicious: 0, suspicious: 0, clean: 0 };
  }

  history.forEach((h) => {
    const key = String(h.checkedAt || '').slice(0, 10);
    if (buckets[key] && ['malicious', 'suspicious', 'clean'].includes(h.verdict)) {
      buckets[key][h.verdict] += 1;
    }
  });

  res.json({ series: Object.values(buckets) });
});

router.get('/geo-distribution', requireAuth, (req, res) => {
  const history = readCollection('ioc_history', []);
  const counts = {};

  history.forEach((h) => {
    const country = (h.sources || []).find((s) => s.source === 'AbuseIPDB' && s.countryCode)?.countryCode;
    if (country) counts[country] = (counts[country] || 0) + 1;
  });

  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([country, count]) => ({ country, count }));

  res.json({ distribution: sorted });
});

module.exports = router;
