const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { appendRecord, readCollection } = require('../utils/jsonStore');
const aggregator = require('../services/aggregator.service');

const router = express.Router();

router.post('/lookup', requireAuth, async (req, res, next) => {
  try {
    const { indicator } = req.body || {};
    if (!indicator || !String(indicator).trim()) {
      return res.status(400).json({ error: 'indicator is required' });
    }

    const result = await aggregator.lookupIndicator(indicator);

    appendRecord('ioc_history', {
      ...result,
      userId: req.user.sub,
      userEmail: req.user.email,
    });

    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/bulk', requireAuth, async (req, res, next) => {
  try {
    const { indicators } = req.body || {};
    if (!Array.isArray(indicators) || indicators.length === 0) {
      return res.status(400).json({ error: 'indicators must be a non-empty array (max 25)' });
    }

    const results = await aggregator.lookupBulk(indicators);

    results
      .filter((r) => !r.error)
      .forEach((r) => appendRecord('ioc_history', { ...r, userId: req.user.sub, userEmail: req.user.email }));

    res.json({ count: results.length, results });
  } catch (err) {
    next(err);
  }
});

router.get('/history', requireAuth, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const history = readCollection('ioc_history', []);
  res.json({ total: history.length, results: history.slice(-limit).reverse() });
});

module.exports = router;
