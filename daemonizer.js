
/**
 * Module dependencies.
 */

const childProcess = require('child_process');
const fs = require('fs').promises;
const homedir = require('os').homedir();
const path = require('path');
const plist = require('plist');

// Project namespace to be used for plist generation.
const PROJECT_NAMESPACE = 'io.github.ruimarinho.gsts';

/**
 * Create daemon to periodically refresh credentials.
 */

class Daemonizer {
  constructor(logger, args) {
    this.args = args;
    this.logger = logger;
  }

  /**
   * Generate a launch agent plist based on dynamic values.
   */

  generateLaunchAgentPlist() {
    const programArguments = ['/usr/local/bin/gsts']

    for (let [key, value] of Object.entries(this.args)) {
      if (key.includes('daemon') || value === undefined) {
        continue;
      }

      programArguments.push(`--${key}${typeof value === 'boolean' ? '' : `=${value}`}`);
    }

    const payload = {
      Label: PROJECT_NAMESPACE,
      EnvironmentVariables: {
        PATH: '/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin'
      },
      RunAtLoad: true,
      StartInterval: 600,
      StandardErrorPath: this.args['daemon-out-log-path'],
      StandardOutPath: this.args['daemon-error-log-path'],
      ProgramArguments: programArguments
    };

    return plist.build(payload);
  }

  /**
   * Only available for macOS: generates dynamic plist and attempts to install and load a launch agent
   * from the user's home directory.
   */

  async install(platform) {
    if (platform !== 'darwin') {
      this.logger.error('Sorry, this feature is only available on macOS at this time');
      return;
    }

    return await this.installMacOS();
  }

  async installMacOS() {
    // LaunchAgents plist path.
    const plistPath = path.join(homedir, 'Library', 'LaunchAgents', `${PROJECT_NAMESPACE}.plist`);

    this.logger.debug('Unloading potentially existing launch agent at %s', plistPath);

    await childProcess.execFile('launchctl', ['unload', plistPath], (error, stdout, stderr) => {
      if (!error) {
        return;
      }

      if (stderr) {
        this.logger.error('Result from stderr while attempting to unload agent was "%s"', stderr);
      }

      if (stdout) {
        this.logger.info('Result from stdout while attempting to unload agent was "%s"', stdout);
      }

      this.logger.error(error);
    });

    const plist = this.generateLaunchAgentPlist().toString();

    this.logger.debug('Generated launch agent plist file %s', plist);

    await fs.writeFile(plistPath, plist);

    this.logger.debug('Successfully wrote the launch agent plist to %s', plistPath);

    await childProcess.execFile('launchctl', ['load', plistPath], (error, stdout, stderr) => {
      if (error) {
        this.logger.error(error);
        return;
      }

      if (stderr) {
        this.logger.error('Result from stderr while attempting to load agent was "%s"', stderr);
      }

      if (stdout) {
        this.logger.info('Result from stdout while attempting to load agent was "%s"', stdout);
      } else {
        this.logger.info('Daemon installed successfully at %s', plistPath)
      }
    });
  }
}

/**
 * Exports.
 */

module.exports = Daemonizer;
