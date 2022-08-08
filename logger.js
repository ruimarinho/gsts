
/**
 * Module dependencies.
 */

const ora = require('ora');
const util = require('util');

// Map Playwright log levels to custom logger levels.
const PLAYWRIGHT_LOG_LEVELS = {
  error: 'error',
  info: 'info',
  verbose: 'debug',
  warning: 'warn'
};

/**
 * Logger with support for TTY detection.
 */

class Logger {
    constructor(verbose, isTTY) {
      this.isTTY = isTTY;
      this.verbose = verbose;
      this.ora = ora({ isEnabled: this.isTTY });
    }

    format(...args) {
      if (!this.isTTY) {
        args.unshift(new Date().toISOString())
      }

      return util.format(...args);
    }

    start(...args) {
      if (!this.isTTY) {
        return;
      }

      return this.ora.start(...args);
    }

    stop(...args) {
      return this.ora.stop(...args);
    }

    debug(...args) {
      if (!this.verbose) {
        return;
      }

      return this.ora.info(this.format(...args));
    }

    info(...args) {
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

module.exports.Logger = Logger;
module.exports.PLAYWRIGHT_LOG_LEVELS = PLAYWRIGHT_LOG_LEVELS;
