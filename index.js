#!/usr/bin/env node

/**
 * Module dependencies.
 */

const CredentialsManager = require('./credentials-manager');
const Daemonizer = require('./daemonizer');
const DeviceViewportPlugin = require('./puppeteer-device-viewport-plugin');
const IframePlugin = require('./puppeteer-iframe-plugin');
const Logger = require('./logger')
const Stealth = require('puppeteer-extra-plugin-stealth');
const UserAgentOverride = require('puppeteer-extra-plugin-stealth/evasions/user-agent-override')
const childProcess = require('child_process');
const errors = require('./errors');
const homedir = require('os').homedir();
const open = require('open');
const path = require('path');
const paths = require('env-paths')('gsts', { suffix: '' });
const puppeteer = require('puppeteer-extra');
const prompts = require('prompts');
const trash = require('trash');

// Define all available cli options.
const cliOptions = {
  'aws-profile': {
    description: 'AWS profile name for storing credentials',
    default: 'sts'
  },
  'aws-role-arn': {
    description: 'AWS role ARN to authenticate with'
  },
  'aws-session-duration': {
    description: `AWS session duration in seconds (defaults to the value provided by the IDP, if set)`,
    type: 'number'
  },
  'aws-shared-credentials-file': {
    description: 'AWS shared credentials file',
    default: path.join(homedir, '.aws', 'credentials')
  },
  'clean': {
    boolean: false,
    config: false,
    description: 'Start authorization from a clean session state'
  },
  'daemon': {
    boolean: false,
    config: false,
    description: 'Install daemon service (only on macOS for now)'
  },
  'daemon-out-log-path': {
    description: `Path for storing the output log of the daemon`,
    default: '/usr/local/var/log/gsts.stdout.log'
  },
  'daemon-error-log-path': {
    description: `Path for storing the error log of the daemon`,
    default: '/usr/local/var/log/gsts.stderr.log'
  },
  'enable-experimental-u2f-support': {
    boolean: false,
    description: `Enable experimental U2F support`
  },
  'json': {
    boolean: false,
    description: `JSON output (compatible with AWS config's credential_process)`
  },
  'force': {
    boolean: false,
    description: 'Force re-authorization even with valid session'
  },
  'headful': {
    boolean: false,
    config: false,
    description: 'headful',
    hidden: true
  },
  'idp-id': {
    alias: 'google-idp-id',
    description: 'Google Identity Provider ID (IDP ID)',
    required: true
  },
  'puppeteer-executable-path': {
    description: 'Set custom executable path for puppeteer',
    default: null,
    required: false
  },
  'sp-id': {
    alias: 'google-sp-id',
    description: 'Google Service Provider ID (SP ID)',
    required: true
  },
  'username': {
    alias: 'google-username',
    description: 'Google username to auto pre-fill during login'
  },
  'verbose': {
    config: false,
    description: 'Log verbose output'
  }
}

// Parse command line arguments.
const argv = require('yargs')
  .usage('gsts')
  .env()
  .command('console')
  .count('verbose')
  .alias('v', 'verbose')
  .options(cliOptions)
  .strictCommands()
  .argv;

/**
 * The SAML URL to be used for authentication.
 */

const SAML_URL = `https://accounts.google.com/o/saml2/initsso?idpid=${argv.googleIdpId}&spid=${argv.googleSpId}&forceauthn=false`;

/**
 * Custom logger instance to support `-v` or `--verbose` output and non-TTY
 * detailed logging with timestamps.
 */

const logger = new Logger(argv.verbose, process.stderr.isTTY);

/**
 * Always return control to the terminal in case an unhandled rejection occurs.
 */

process.on('unhandledRejection', e => {
	logger.stop();
	console.error(e);
	process.exit(1);
});

/**
 * Create instance of Daemonizer with logger.
 */

const configArgs = {};

for (const key in cliOptions) {
  if (cliOptions[key].config === false) {
    continue;
  }

  configArgs[key] = argv[key];
}

const daemonizer = new Daemonizer(logger, configArgs);

/**
 * Create instance of CredentialsManager with logger.
 */

const credentialsManager = new CredentialsManager(logger);

/**
 * Format output according to the request format.
 */

async function formatOutput(awsSharedCredentialsFile, awsProfile, format = null) {
  if (format !== 'json') {
    return;
  }

  console.log(await credentialsManager.exportAsJSON(awsSharedCredentialsFile, awsProfile));
}

/**
 * Main execution routine which handles command-line flags.
 */

(async () => {
  if (argv._[0] === 'console') {
    logger.debug('Opening url %s', SAML_URL);

    return await open(SAML_URL);
  }

  if (argv.daemon) {
    return await daemonizer.install(process.platform);
  }

  if (argv.clean) {
    logger.debug('Cleaning directory %s', paths.data)

    await trash(paths.data);
  }

  if (!argv.headful) {
   logger.start('Logging in');
  }

  let isAuthenticated = false;

  if (!argv.headful) {
    let session = await credentialsManager.getSessionExpirationFromCredentials(argv.awsSharedCredentialsFile, argv.awsProfile, argv.awsRoleArn);

    if (!argv.force && session.isValid) {
      isAuthenticated = true;

      if (argv.verbose) {
        logger.debug('Skipping re-authorization as session is valid until %s. Use --force to ignore.', new Date(session.expiresAt));
      } else {
        logger.info('Login is still valid, no need to re-authorize!');
      }

      formatOutput(argv.awsSharedCredentialsFile, argv.awsProfile, argv.json ? 'json' : null);

      return;
    }
  }

  const device = {
    platform: process.platform === 'darwin' ? 'MacIntel' : process.platform === 'linux' ? 'Linux x86_64' : 'Win32',
    viewport: { width: 1200, height: 800 },
    deviceScaleFactor: 1
  };
  const stealth = Stealth();
  const options = {
    args: ['--disable-features=site-per-process', `--window-size=${device.viewport.width},${device.viewport.height}`],
    defaultViewport: device.viewport,
    executablePath: argv.puppeteerExecutablePath,
    headless: !argv.headful,
    ignoreDefaultArgs: ['--enable-automation'],
    userDataDir: paths.data
  };

  if (argv.headful && argv.enableExperimentalU2FSupport) {
    stealth.enabledEvasions.delete('chrome.runtime');
    options.ignoreDefaultArgs.push('--disable-component-extensions-with-background-pages');

    logger.debug('Enabled experimental U2F support');
  }


  // Use an appropriate user agent instead that takes the platform into consideration.
  stealth.enabledEvasions.delete('user-agent-override')

  puppeteer.use(stealth)
  puppeteer.use(DeviceViewportPlugin(device))
  puppeteer.use(IframePlugin())
  puppeteer.use(UserAgentOverride({ platform: device.platform }))

  const browser = await puppeteer.launch(options);
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  await page.setDefaultTimeout(0);

  page.on('request', async request => {
    if (request.url() === 'https://signin.aws.amazon.com/saml') {
      isAuthenticated = true;

      try {
        const { samlAssertion, roles } = await credentialsManager.prepareRoleWithSAML(request._postData, argv.awsRoleArn);

        let role = roles[0];

        if (roles.length > 1) {
          logger.stop();

          if (process.stdout.isTTY) {
            const choices = roles.reduce((accumulator, role) => {
              accumulator.push({ title: role.roleArn })
              return accumulator;
            }, []);

            const response = await prompts({
              type: 'select',
              name: 'arn',
              message: 'Select a role to authenticate with:',
              choices
            });

            if (!response.hasOwnProperty('arn')) {
              request.abort();
              logger.error('You must choose one of the available role ARNs to authenticate or, alternatively, set one directly using the --aws-role-arn option');
              return;
            }

            role = roles[response.arn];

            logger.info(`You may skip this step by invoking gsts with --aws-role-arn=${role.roleArn}`);
          } else {
            logger.debug(`Assuming role "${role.roleArn}" from the list of available roles %o due to non-interactive mode`, roles);
          }
        }

        await credentialsManager.assumeRoleWithSAML(samlAssertion, argv.awsSharedCredentialsFile, argv.awsProfile, role, argv.awsSessionDuration);

        if (argv.verbose) {
          logger.debug(`Login successful${ argv.verbose ? ` and credentials stored in "${argv.awsSharedCredentialsFile}" under AWS profile "${argv.awsProfile}" with role ARN "${role.roleArn}"` : '!' }`);
        } else {
          logger.succeed('Login successful!');
        }

        formatOutput(argv.awsSharedCredentialsFile, argv.awsProfile, argv.json ? 'json' : null);
      } catch (e) {
        logger.debug('An error has ocurred while authenticating', e);

        if (e instanceof errors.RoleNotFoundError) {
          request.abort();
          logger.error(`Role ARN "${argv.awsRoleArn}" not found in the list of available roles ${JSON.stringify(e.roles)}`);
          return;
        }

        if (['ValidationError', 'InvalidIdentityToken'].includes(e.code)) {
          request.abort();
          logger.error(`A remote error ocurred while assuming role: ${e.message}`);
          return;
        }

        request.abort();
        logger.error(`An unknown error has ocurred with message "${e.message}". Please try again with --verbose`)
        return;
      }

      request.continue();
      return;
    }

    if (/google|gstatic|youtube|googleusercontent|googleapis|gvt1/.test(request.url())) {
      request.continue();
      return;
    }

    request.abort();
  });

  page.on('requestfailed', async request => {
    // The request to the AWS console is aborted on successful login for performance reasons,
    // so in this particular case it's actually an expected outcome.
    if (request.url().startsWith('https://console.aws.amazon.com/console/home?state')) {
      return;
    }

    logger.debug(`Request to "${request.url()}" has been aborted`);
    await browser.close();
  });

  try {
    await page.goto(`https://accounts.google.com/o/saml2/initsso?idpid=${argv.googleIdpId}&spid=${argv.googleSpId}&forceauthn=false`)
  } catch (e) {
    // The request to the AWS console is aborted on successful login for performance reasons,
    // so in this particular case closing the browser instance is actually an expected outcome.
    if (/browser has disconnected/.test(e.message)) {
      return;
    }

    logger.debug('An error ocurred while browsing to the initsso page', e);
    return;
  }

  if (argv.headful) {
    try {
      await page.waitFor('input[type=email]');

      if (argv.username) {
        logger.debug(`Pre-filling email with ${argv.username}`);

        await page.evaluate((data) => document.querySelector('input[type=email]').value = data.username, { username: argv.username })
      }

      await page.waitForResponse('https://signin.aws.amazon.com/saml');
    } catch (e) {
      if (/Target closed/.test(e.message)) {
        logger.debug('Browser closed outside running context, exiting');
        return;
      }

      if (argv.verbose) {
        logger.debug('An unknown error has ocurred while authenticating in headful mode', e);
      } else {
        logger.error(`An unknown error has ocurred with message "${e.message}". Please try again with --verbose`)
      }
    }
  }

  if (!isAuthenticated && !argv.headful) {
    logger.warn('User is not authenticated, spawning headful instance');

    const args = [__filename, '--headful', ...process.argv.slice(2)];
    const ui = childProcess.spawn(process.execPath, args, { stdio: 'inherit' });

    ui.on('close', code => logger.debug(`Headful instance has exited with code ${code}`))
  }

  await browser.close();
})();
