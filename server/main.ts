import { buildApp } from './app.js';
import { ConfigError, loadConfig, type Config } from './config.js';
import { migrate, openDb } from './db/db.js';
import { createLogger } from './logging.js';

let config: Config;
try {
  config = loadConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    process.stderr.write(`dawr: refusing to start: ${err.message}\n`);
    process.exit(1);
  }
  throw err;
}

const logger = createLogger({ level: config.logLevel });
const db = openDb(config.dbFile);
const migrations = migrate(db);
logger.info({ applied: migrations.applied, total: migrations.total }, 'migrations');

const app = buildApp({ logger, db, config });

async function shutdown(signal: string): Promise<void> {
  app.log.info({ signal }, 'shutting down');
  await app.close();
  db.close();
  process.exit(0);
}
process.once('SIGTERM', () => void shutdown('SIGTERM'));
process.once('SIGINT', () => void shutdown('SIGINT'));

try {
  await app.listen({ port: config.port, host: config.host });
} catch (err) {
  app.log.fatal({ err }, 'failed to start');
  process.exit(1);
}
