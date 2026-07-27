const express = require('express');
const { requireAuth } = require('../middleware/auth');
const cisa = require('../services/cisa.service');
const otx = require('../services/otx.service');

const router = express.Router();

router.get('/cisa-kev', requireAuth, async (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const offset = Number(req.query.offset) || 0;
    const q = req.query.q;

    if (q) {
      const results = await cisa.search(q);
      return res.json({ source: 'CISA KEV', total: results.length, vulnerabilities: results });
    }

    const catalog = await cisa.getCatalog({ limit, offset });
    res.json(catalog);
  } catch (err) {
    next(err);
  }
});

router.get('/otx-pulses', requireAuth, async (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 20, 50);
    const data = await otx.getSubscribedPulses({ limit });
    res.json(data);
  } catch (err) {
    next(err);
  }
});

// Combined feed for the "Threat Intelligence Feeds" landing page
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const [kev, pulses] = await Promise.allSettled([cisa.getCatalog({ limit: 10 }), otx.getSubscribedPulses({ limit: 10 })]);

    res.json({
      cisaKev: kev.status === 'fulfilled' ? kev.value : { source: 'CISA KEV', available: false, error: kev.reason?.message },
      otxPulses: pulses.status === 'fulfilled' ? pulses.value : { source: 'AlienVault OTX', available: false, error: pulses.reason?.message },
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
