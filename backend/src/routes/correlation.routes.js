const express = require('express');
const { requireAuth } = require('../middleware/auth');
const aggregator = require('../services/aggregator.service');

const router = express.Router();

/**
 * Given a set of indicators, look each up and group them by shared
 * OTX pulse names / tags to surface likely-related infrastructure.
 */
router.post('/analyze', requireAuth, async (req, res, next) => {
  try {
    const { indicators } = req.body || {};
    if (!Array.isArray(indicators) || indicators.length < 2) {
      return res.status(400).json({ error: 'Provide at least 2 indicators to correlate' });
    }

    const results = await aggregator.lookupBulk(indicators);
    const valid = results.filter((r) => !r.error);

    // Build tag/pulse -> [indicators] map
    const groups = new Map();
    for (const r of valid) {
      const otx = (r.sources || []).find((s) => s.source === 'AlienVault OTX' && s.available);
      const labels = new Set();
      (otx?.pulses || []).forEach((p) => labels.add(`pulse:${p.name}`));
      (otx?.tags || []).forEach((t) => labels.add(`tag:${t}`));

      for (const label of labels) {
        if (!groups.has(label)) groups.set(label, []);
        groups.get(label).push(r.indicator);
      }
    }

    const correlations = [...groups.entries()]
      .filter(([, members]) => members.length > 1)
      .map(([label, members]) => ({ label, members }))
      .sort((a, b) => b.members.length - a.members.length);

    res.json({
      indicatorsAnalyzed: valid.length,
      correlations,
      results: valid,
      failed: results.filter((r) => r.error),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
