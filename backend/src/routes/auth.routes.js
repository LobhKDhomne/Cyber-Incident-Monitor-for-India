const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { readCollection } = require('../utils/jsonStore');
const { verifyPassword } = require('../utils/passwords');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

router.post('/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const users = readCollection('users', []);
    const user = users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ sub: user.id, email: user.email, name: user.name, role: user.role }, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
    });

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Stateless JWT - logout is a client-side token discard. Endpoint kept for
// symmetry with the frontend's "Sign Out" action.
router.post('/logout', requireAuth, (req, res) => {
  res.json({ ok: true });
});

module.exports = router;
