
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
  constructor(logger) {
    this.logger = logger;
  }

  /**
   * Generate a launch agent plist based on dynamic values.
   */

  generateLaunchAgentPlist(idpId, spId, username, outLogPath, errorLogPath) {
    const programArguments = ['/usr/local/bin/gsts', `--idp-id=${idpId}`, `--sp-id=${spId}`]

    if (username) {
      programArguments.push(`--username=${username}`);
    }

    const payload = {
      Label: PROJECT_NAMESPACE,
      EnvironmentVariables: {
        PATH: '/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin'
      },
      RunAtLoad: true,
      StartInterval: 600,
      StandardErrorPath: errorLogPath,
      StandardOutPath: outLogPath,
      ProgramArguments: programArguments
    };

    return plist.build(payload);
  }

  /**
   * Only available for macOS: generates dynamic plist and attempts to install and load a launch agent
   * from the user's home directory.
   */

  async install(platform, googleIdpId, googleSpId, username, daemonOutLogPath, daemonErrorLogPath) {
    if (platform !== 'darwin') {
      return this.logger.error('Sorry, this feature is only available on macOS at this time');
    }

    return await this.installMacOS(googleIdpId, googleSpId, username, daemonOutLogPath, daemonErrorLogPath);
  }

  async installMacOS(googleIdpId, googleSpId, username, daemonOutLogPath, daemonErrorLogPath) {
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

    const plist = this.generateLaunchAgentPlist(googleIdpId, googleSpId, username, daemonOutLogPath, daemonErrorLogPath).toString();

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
