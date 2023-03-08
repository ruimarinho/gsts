
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

export { PLAYWRIGHT_LOG_LEVELS };

/**
 * Logger with support for TTY detection.
 */

export class Logger {
    constructor(verbose, isTTY) {
      this.isTTY = isTTY;
      this.verbose = verbose;
      this.ora = ora({ isEnabled: this.isTTY });
    }

    format(...args) {
      if (!this.isTTY) {
        args.unshift(new Date().toISOString())
      }

      return format(...args);
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
      if (this.verbose < 2) {
        return;
      }

      return this.ora.info(this.format(...args));
    }

    info(...args) {
      if (this.verbose < 1) {
        return;
      }

      return this.ora.info(this.format(...args));
    }

    warn(...args) {
      return this.ora.warn(this.format(...args));
    }

    error(...args) {
      return this.ora.fail(this.format(...args));
    }

    succeed(...args) {
      return this.ora.succeed(this.format(...args));
    }
}
