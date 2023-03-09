
/**
 * Module dependencies.
 */

import { format } from 'node:util';
import ora from 'ora';

// Map Playwright log levels to custom logger levels.
const PLAYWRIGHT_LOG_LEVELS = {
  error: 'error',
  info: 'info',
  verbose: 'debug',
  warning: 'warn'
};

const ORA_LOG_LEVELS = {
  info: 'info',
  warn: 'warn',
  debug: 'info',
  error: 'fail',
  succeed: 'succeed'
}

export { PLAYWRIGHT_LOG_LEVELS };

/**
 * Logger with support for TTY detection.
 */

export class Logger {
    constructor(verbosity, isTTY, stream) {
      this.verbosity = verbosity;
      this.isTTY = isTTY;
      this.ora = ora({ isEnabled: this.isTTY });
      this.stream = stream;
    }

    log(level, ...args) {
      if (!this.isTTY) {
        this.stream.write(`${new Date().toISOString()} ${level.toUpperCase()} gsts: ${format(...args)}`);
        return;
      }

      return this.ora[ORA_LOG_LEVELS[level]](format(...args));

    }

    start(...args) {
      if (!this.isTTY) {
        return;
      }

      return this.ora.start(...args);
    }

    stop(...args) {
      if (!this.isTTY) {
        return;
      }

      return this.ora.stop(...args);
    }

    debug(...args) {
      // For security reasons, do not log debug messages which can contain credentials secrets
      // when in non-interactive mode, since other third-party tools could capture this content
      // as part of their error processing logic.
      if (!this.isTTY) {
        return;
      }

      if (this.verbosity < 2) {
        return;
      }

      return this.log('debug', ...args);
    }

    info(...args) {
      if (this.verbosity < 1) {
        return;
      }

      return this.log('info', ...args);
    }

    warn(...args) {
      return this.log('warn', ...args);
    }

    error(...args) {
      return this.log('error', ...args);
    }

    succeed(...args) {
      if (!this.isTTY) {
        return;
      }

      return this.log('succeed', ...args);
    }
}
