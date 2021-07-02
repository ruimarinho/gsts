#!/usr/bin/env node

/**
 * Module dependencies.
 */

const playwright = require('playwright');
const CredentialsManager = require('./credentials-manager');
const Daemonizer = require('./daemonizer');
const Logger = require('./logger')
const childProcess = require('child_process');
const errors = require('./errors');
const homedir = require('os').homedir();
const open = require('open');
const path = require('path');
const paths = require('env-paths')('gsts', { suffix: '' });
const prompts = require('prompts');
const trash = require('trash');
const url = require('url');
const endpointVerification = require('./endpointVerification')

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
  'endpoint-verification': {
    boolean: false,
    description: `Enable endpoint verification`
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
  'engine': {
    description: 'Set custom browser engine',
    choices: ['chromium', 'firefox', 'webkit'],
    default: 'chromium',
    required: false
  },
  'engine-executable-path': {
    description: 'Set custom executable path for browser engine',
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
  .command('console', 'Authenticate via SAML and open Amazon AWS console in the default browser')
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

  const options = {
    headless: !argv.headful,
    userDataDir: paths.data
  };

  if (argv.engineExecutablePath) {
    options.executablePath = argv.engineExecutablePath;
  }

  if (argv.endpointVerification) {
    const pathToExtension = await endpointVerification.huntForExtension()

    if (pathToExtension != null) {
      options.args = [
        `--disable-extensions-except=${pathToExtension}`,
        `--load-extension=${pathToExtension}`]
    }
  }

  const context = await playwright[argv.engine].launchPersistentContext(path.join(paths.data, argv.engine), options);
  const page = await context.newPage();
  page.setDefaultTimeout(0);

  await page.route('**/*', async (route) => {
    if (route.request().url() === 'https://signin.aws.amazon.com/saml') {
      isAuthenticated = true;

      try {
        let { availableRoles, roleToAssume, samlAssertion } = await credentialsManager.prepareRoleWithSAML(route.request().postDataJSON(), argv.awsRoleArn);

        if (!roleToAssume && availableRoles.length > 1) {
          logger.stop();

          if (process.stdout.isTTY) {
            const choices = availableRoles.reduce((accumulator, role) => {
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
              logger.error('You must choose one of the available role ARNs to authenticate or, alternatively, set one directly using the --aws-role-arn option');
              route.abort();
              return;
            }

            console.log(require('util').inspect(availableRoles, { depth: null }));
            roleToAssume = availableRoles[response.arn];

            logger.info(`You may skip this step by invoking gsts with --aws-role-arn=${roleToAssume.roleArn}`);
          } else {
            logger.debug(`Assuming role "${roleToAssume.roleArn}" from the list of available roles %o due to non-interactive mode`, availableRoles);
          }
        }

        await credentialsManager.assumeRoleWithSAML(samlAssertion, argv.awsSharedCredentialsFile, argv.awsProfile, roleToAssume, argv.awsSessionDuration);

        logger.debug(`Initiating request to "${route.request().url()}"`);
        route.continue();

        // AWS presents an account selection form when multiple roles are available
        // before redirecting to the console. If we see this form, then we know we
        // are logged in.
        if (availableRoles.length > 1) {
          await page.waitForSelector('#saml_form');
          await context.close();
        }

        if (argv.verbose) {
          logger.debug(`Login successful${ argv.verbose ? ` and credentials stored in "${argv.awsSharedCredentialsFile}" under AWS profile "${argv.awsProfile}" with role ARN "${roleToAssume.roleArn}"` : '!' }`);
        } else {
          logger.succeed('Login successful!');
        }

        formatOutput(argv.awsSharedCredentialsFile, argv.awsProfile, argv.json ? 'json' : null);
      } catch (e) {
        logger.debug('An error has ocurred while authenticating', e);

        if (e instanceof errors.RoleNotFoundError) {
          logger.error(`Role ARN "${argv.awsRoleArn}" not found in the list of available roles ${JSON.stringify(e.roles)}`);
          route.abort();
          return;
        }

        if (['ValidationError', 'InvalidIdentityToken'].includes(e.code)) {
          logger.error(`A remote error ocurred while assuming role: ${e.message}`);
          route.abort();
          return;
        }

        logger.error(`An unknown error has ocurred with message "${e.message}". Please try again with --verbose`)
        route.abort();
        return;
      }

      return;
    }

    if (/google|gstatic|youtube|googleusercontent|googleapis|gvt1/.test(route.request().url())) {
      logger.debug(`Allowing request to "${route.request().url()}"`);
      route.continue();
      return;
    }

    logger.debug(`Aborting request to "${route.request().url()}"`);
    route.abort();
  });

  page.on('requestfailed', async request => {
    logger.debug(`Request to "${request.url()}" has failed`);

    // The request to the AWS console is aborted on successful login for performance reasons,
    // so in this particular case it's actually an expected outcome.
    const parsedURL = url.parse(request.url());
    if (parsedURL.host.endsWith('console.aws.amazon.com') && parsedURL.pathname === '/console/home') {
      logger.debug(`Request to "${request.url()}" matches AWS console which means authentication was successful`);

      await context.close();
      return;
    }
  });

  try {
    const ssoPage = await page.goto(`https://accounts.google.com/o/saml2/initsso?idpid=${argv.googleIdpId}&spid=${argv.googleSpId}&forceauthn=false`)

    if (/ServiceLogin/.test(ssoPage.url())) {
      if (!isAuthenticated && !argv.headful) {
        logger.warn('User is not authenticated, spawning headful instance');

        const args = [__filename, '--headful', ...process.argv.slice(2)];
        const ui = childProcess.spawn(process.execPath, args, { stdio: 'inherit' });

        ui.on('close', code => {
          logger.debug(`Headful instance has exited with code ${code}`);
        });

        await context.close();
      }
    }
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
      await page.waitForSelector('input[type=email]');

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
        process.exit(1);
      } else {
        logger.error(`An unknown error has ocurred with message "${e.message}". Please try again with --verbose`)
        process.exit(1);
      }
    }
  }
})();
