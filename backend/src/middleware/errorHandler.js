const logger = require('../utils/logger');

function notFound(req, res, _next) {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, _next) {
  const status = err.status || err.statusCode || 500;
  logger.error(err.message, status >= 500 ? err.stack : '');
  res.status(status).json({
    error: err.publicMessage || err.message || 'Internal server error',
  });
}

module.exports = { notFound, errorHandler };
