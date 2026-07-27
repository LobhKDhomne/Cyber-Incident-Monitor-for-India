const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const config = require('./config');
const { apiLimiter } = require('./middleware/rateLimiter');
const { notFound, errorHandler } = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth.routes');
const iocRoutes = require('./routes/ioc.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const feedsRoutes = require('./routes/feeds.routes');
const correlationRoutes = require('./routes/correlation.routes');
const logsRoutes = require('./routes/logs.routes');

const app = express();

app.use(helmet());
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan(config.nodeEnv === 'production' ? 'combined' : 'dev'));
app.use('/api', apiLimiter);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'CIMI Backend', time: new Date().toISOString() });
});

app.use('/api/auth', authRoutes);
app.use('/api/ioc', iocRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/feeds', feedsRoutes);
app.use('/api/correlation', correlationRoutes);
app.use('/api/logs', logsRoutes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
