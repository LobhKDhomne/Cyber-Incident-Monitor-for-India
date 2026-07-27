const express = require('express');
const multer = require('multer');
const { v4: uuid } = require('uuid');
const { requireAuth } = require('../middleware/auth');
const { extractIndicatorsFromText } = require('../utils/iocDetector');
const { appendRecord, readCollection } = require('../utils/jsonStore');
const aggregator = require('../services/aggregator.service');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

const MAX_AUTO_SCREEN = 15; // cap how many extracted IoCs get auto-checked against live sources

router.post('/analyze', requireAuth, upload.single('logFile'), async (req, res, next) => {
  try {
    const text = req.file ? req.file.buffer.toString('utf-8') : req.body?.logText;
    if (!text || !text.trim()) {
      return res.status(400).json({ error: 'Provide a logFile upload or logText field' });
    }

    const extracted = extractIndicatorsFromText(text);
    const totalExtracted = Object.values(extracted).reduce((sum, arr) => sum + arr.length, 0);

    const toScreen = [...extracted.ipv4, ...extracted.domain, ...extracted.sha256, ...extracted.sha1, ...extracted.md5].slice(
      0,
      MAX_AUTO_SCREEN
    );

    const screened = toScreen.length ? await aggregator.lookupBulk(toScreen) : [];
    const flagged = screened.filter((r) => !r.error && (r.verdict === 'malicious' || r.verdict === 'suspicious'));

    const report = {
      id: uuid(),
      fileName: req.file?.originalname || 'pasted-log',
      sizeBytes: req.file?.size || Buffer.byteLength(text),
      extracted: {
        ipv4: extracted.ipv4.length,
        domain: extracted.domain.length,
        url: extracted.url.length,
        sha256: extracted.sha256.length,
        sha1: extracted.sha1.length,
        md5: extracted.md5.length,
      },
      totalExtracted,
      screenedCount: screened.length,
      flagged,
      userId: req.user.sub,
      createdAt: new Date().toISOString(),
    };

    appendRecord('log_reports', report, { maxLength: 500 });

    res.json({ ...report, indicators: extracted });
  } catch (err) {
    next(err);
  }
});

router.get('/reports', requireAuth, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 20, 100);
  const reports = readCollection('log_reports', []);
  res.json({ total: reports.length, results: reports.slice(-limit).reverse() });
});

module.exports = router;
