
/**
 * Module dependencies.
 */

const Console = require('console').Console;
const util = require('util')

/**
 * Logger with support for TTY detection and log levels.
 */

class Logger extends Console {
    constructor(stdout, stderr, level, ...args) {
      super(stdout, stderr, level, ...args);

      this.isTTY = stdout.isTTY;
      this.level = level;
    }

    log(...args) {
      if (this.isTTY) {
        super.log(util.format(...args));

        return;
      }

      super.log((new Date().toISOString()), util.format(...args));
    }

    debug(...args) {
      if (this.level < 1) {
        return;
      }

      this.log(...args);
    }

    info(...args) {
      this.log(...args);
    }

    error(...args) {
      this.log(...args);
    }
}

module.exports = Logger;
