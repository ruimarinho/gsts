#!/usr/bin/env node

/**
 * Module dependencies.
 */

import { Logger, PLAYWRIGHT_LOG_LEVELS } from './logger.js';
import { CredentialsManager } from './credentials-manager.js';
import { RoleNotFoundError } from './errors.js';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath, parse as urlparse } from 'node:url';
import { hideBin } from 'yargs/helpers';
import yargs from 'yargs';
import open from 'open';
import envpaths from 'env-paths';
import playwright from 'playwright';
import prompts from 'prompts';
import trash from 'trash';

const paths = envpaths('gsts', { suffix: '' });

// Define all available cli options.
const cliOptions = {
  'aws-profile': {
    description: 'Profile name used to read AWS config for (e.g. region)',
    default: 'default'
  },
  'aws-role-arn': {
    description: 'AWS role ARN to authenticate with'
  },
  'aws-session-duration': {
    description: `AWS session duration in seconds (defaults to the value provided by the IDP, if set)`,
    type: 'number'
  },
  'aws-region': {
    description: 'AWS region to send requests to',
    required: true
  },
  'clean': {
    boolean: false,
    config: false,
    description: 'Start authorization from a clean session state'
  },
  'cache-dir': {
    description: 'Where to store gsts cache',
    default: paths.cache
  },
  'output': {
    alias: 'o',
    description: `Output format`,
    choices: ['json']
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
    description: 'Identity Provider ID (IdP ID)',
    required: true
  },
  'playwright-engine': {
    description: 'Set custom browser engine',
    choices: ['chromium', 'firefox', 'webkit'],
    default: 'chromium',
    required: false
  },
  'playwright-engine-executable-path': {
    description: 'Set custom executable path for browser engine',
    required: false
  },
  'playwright-engine-channel': {
    choices: ['chrome', 'chrome-beta', 'msedge-beta', 'msedge-dev']
  },
  'sp-id': {
    description: 'Service Provider ID (SP ID)',
    required: true
  },
  'username': {
    description: 'Username to auto pre-fill during login'
  },
  'verbose': {
    config: false,
    description: 'Log verbose output'
  }
}

// Parse command line arguments.
const argv = yargs(hideBin(process.argv))
  .usage('gsts')
  .middleware((argv) => {
    if (!argv.awsRegion && process.env.AWS_DEFAULT_REGION) {
      argv.awsRegion = argv['aws-region'] = process.env.AWS_DEFAULT_REGION;
    }

    // Automatically enable json output format if process is not inside an
    // interactive shell to enable compatibility with third-party tools
    // like the aws cli.
    if (argv.output == undefined && !process.stdout.isTTY) {
      argv.output = 'json';
    }

    return argv;
  }, true)
  .env('GSTS')
  .command('console', 'Authenticate via SAML and open Amazon AWS console in the default browser')
  .count('verbose')
  .alias('v', 'verbose')
  .options(cliOptions)
  .strictCommands()
  .argv;

/**
 * The SAML URL to be used for authentication.
 */

const SAML_URL = `https://accounts.google.com/o/saml2/initsso?idpid=${argv.idpId}&spid=${argv.spId}&forceauthn=false`;

/**
 * Custom logger instance to support `-v` or `--verbose` output and non-TTY
 * detailed logging with timestamps.
 */

const logger = new Logger(argv.verbose, process.stdout.isTTY);

/**
 * Always return control to the terminal in case an unhandled rejection occurs.
 */

process.on('unhandledRejection', e => {
  logger.stop();
  console.error(e);
  process.exit(1);
});

/**
 * Create instance of CredentialsManager with logger.
 */

const credentialsManager = new CredentialsManager(logger, argv.awsRegion, argv.cacheDir);

/**
 * Format output according to the requested output format.
 */

async function formatOutput(content, format) {
  if (format === undefined) {
    return;
  }

  if (format !== 'json') {
    throw new Error(`Unsupported output format ${format}`);
  }

  process.stdout.write(content.toJSON());
}

/**
 * Main execution routine which handles command-line flags.
 */

(async () => {
  if (argv._[0] === 'console') {
    logger.debug('Opening url %s', SAML_URL);

    return await open(SAML_URL);
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
    try {
      let session = await credentialsManager.loadCredentials(argv.awsProfile, argv.awsRoleArn);

      if (!argv.force) {
        if (session.isValid()) {
          logger.info('Session is expected to be valid until %s. Use --force to ignore.', session.expiresAt);

          isAuthenticated = true;

          logger.stop();

          formatOutput(session, argv.output);

          return;
        } else {
          logger.info('Session has expired on %s', session.expiresAt);
        }
      }
    } catch (e) {
      if (e.code !== 'ENOENT') {
        throw e;
      }
    }
  }

  const playwrightOptions = {
    headless: !argv.headful,
    userDataDir: paths.data,
    logger: {
      isEnabled: () => argv.verbose >= 3,
      log: (name, severity, message, args) => logger[PLAYWRIGHT_LOG_LEVELS[severity]](`Playwright: ${name} ${message}`, args)
    },
    channel: argv.playwrightEngineChannel,
    executablePath: argv.playwrightEngineExecutablePath,
  };

  const context = await playwright[argv.playwrightEngine].launchPersistentContext(join(paths.data, argv.playwrightEngine), playwrightOptions);
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

            roleToAssume = availableRoles[response.arn];

            logger.info(`You may skip this step by invoking gsts with --aws-role-arn=${roleToAssume.roleArn}`);
          } else {
            logger.debug(`Assuming role "${roleToAssume.roleArn}" from the list of available roles %o due to non-interactive mode`, availableRoles);
          }
        }

        const session = await credentialsManager.assumeRoleWithSAML(samlAssertion, roleToAssume, argv.awsProfile, argv.awsSessionDuration);

        logger.debug(`Initiating request to "${route.request().url()}"`);
        route.continue();

        // AWS presents an account selection form when multiple roles are available
        // before redirecting to the console. If we see this form, then we know we
        // are logged in.
        if (availableRoles.length > 1) {
          await page.waitForSelector('#saml_form');
          await context.close();
        }

        logger.succeed('Login successful!');

        formatOutput(session, argv.output);
      } catch (e) {
        logger.debug('An error has ocurred while authenticating', e);

        if (e instanceof RoleNotFoundError) {
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

    if (/google|gstatic|youtube|googleusercontent|googleapis|gvt1|okta/.test(route.request().url())) {
      logger.debug(`Allowing request to "${route.request().url()}"`);
      route.continue();
      return;
    }

    logger.debug(`Aborting request to "${route.request().url()}"`);

    // Abort with a specific error so we can tag these requests as being blocked by gsts
    // instead of a configuration issue (like a custom ARN not being available).
    route.abort('blockedbyclient');
  });

  page.on('requestfailed', async request => {
    logger.debug(`Request to "${request.url()}" has failed`);

    // Requests tagged with this specific error were made by gsts and should result
    // in a program termination.
    if (request.failure().errorText === 'net::ERR_BLOCKED_BY_CLIENT') {
      logger.debug(`Request to ${request.url()} has failed due to client request block`);
      await context.close();
      logger.debug(`Closed context of ${request.url()}`);
      return;
    }

    // The request to the AWS console is aborted on successful login for performance reasons,
    // so in this particular case it's actually an expected outcome.
    const parsedURL = urlparse(request.url());
    if (parsedURL.host.endsWith('console.aws.amazon.com') && parsedURL.pathname === '/console/home') {
      logger.debug(`Request to "${request.url()}" matches AWS console which means authentication was successful`);

      await context.close();
      return;
    }
  });

  try {
    const ssoPage = await page.goto(SAML_URL)

    if (/ServiceLogin/.test(ssoPage.url())) {
      if (!isAuthenticated && !argv.headful) {
        logger.warn('User is not authenticated, spawning headful instance');

        const args = [fileURLToPath(import.meta.url), '--headful', ...process.argv.slice(2)];
        const ui = spawn(process.execPath, args, { stdio: 'inherit' });

        ui.on('close', code => {
          logger.debug(`Headful instance has exited with code ${code}`);
        });

        await context.close();
      }
    }
  } catch (e) {
    // The request to the AWS console is aborted on successful login for performance reasons,
    // so in this particular case closing the browser instance is actually an expected outcome.
    if (/browser has disconnected/.test(e.message) || /Navigation failed because page was closed/.test(e.message)) {
      return;
    }

    logger.debug('Error caught while browsing to the initsso page', e);
    return;
  }

  if (argv.headful) {
    try {
      if (argv.username) {
        logger.debug(`Pre-filling email with ${argv.username}`);

        await page.fill('input[type=email]', argv.username)
      }

      await page.waitForResponse('https://signin.aws.amazon.com/saml');
    } catch (e) {
      if (/Target closed/.test(e.message)) {
        logger.debug('Browser closed outside running context, exiting');
        return;
      }

      logger.debug('Error while authenticating in headful mode', e);
      logger.error(`An unknown error has ocurred with message "${e.message}". Please try again with --verbose`)
      process.exit(1);
    }
  }
})();
