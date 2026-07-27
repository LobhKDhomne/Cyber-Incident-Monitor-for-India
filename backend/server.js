const app = require('./src/app');
const config = require('./src/config');
const logger = require('./src/utils/logger');

app.listen(config.port, () => {
  logger.info(`CIMI backend listening on http://localhost:${config.port}`);
  logger.info(`Environment: ${config.nodeEnv}`);
});
