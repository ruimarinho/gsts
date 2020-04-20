#!/usr/bin/env node

/**
 * Module dependencies.
 */

const CredentialsManager = require('./credentials-manager');
const Daemonizer = require('./daemonizer');
const Logger = require('./logger')
const Stealth = require('puppeteer-extra-plugin-stealth');
const childProcess = require('child_process');
const errors = require('./errors');
const homedir = require('os').homedir();
const open = require('open');
const ora = require('ora');
const path = require('path');
const paths = require('env-paths')('gsts', { suffix: '' });
const puppeteer = require('puppeteer-extra');
const prompts = require('prompts');
const trash = require('trash');

// Default session duration, as states on AWS documentation.
// See https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/.
const SESSION_DEFAULT_DURATION = 3600 // 1 hour

// Delta (in ms) between exact expiration date and current date to avoid requests
// on the same second to fail.
const SESSION_EXPIRATION_DELTA = 30e3; // 30 seconds

// Parse command line arguments.
const argv = require('yargs')
  .usage('gsts')
  .env()
  .command('console')
  .count('verbose')
  .alias('v', 'verbose')
  .options({
    'aws-profile': {
      description: 'AWS profile name for storing credentials',
      default: 'sts'
    },
    'aws-role-arn': {
      description: 'AWS role ARN to authenticate with'
    },
    'aws-session-duration': {
      description: `AWS session duration in seconds (defaults to the value provided by Google, and if that is not provided then ${SESSION_DEFAULT_DURATION})`,
      type: 'number'
    },
    'aws-shared-credentials-file': {
      description: 'AWS shared credentials file',
      default: path.join(homedir, '.aws', 'credentials')
    },
    'clean': {
      boolean: false,
      description: 'Start authorization from a clean session state'
    },
    'daemon': {
      boolean: false,
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
    'force': {
      boolean: false,
      description: 'Force re-authorization even with valid session'
    },
    'headful': {
      boolean: false,
      description: 'headful',
      hidden: true
    },
    'idp-id': {
      alias: 'google-idp-id',
      description: 'Google Identity Provider ID (IDP ID)',
      required: true
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
      description: 'Log verbose output'
    }
  })
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

const logger = new Logger(process.stdout, process.stderr, argv.verbose);

/**
 * Create instance of Daemonizer with logger.
 */

const daemonizer = new Daemonizer(logger);

/**
 * Create instance of CredentialsManager with logger.
 */

const credentialsManager = new CredentialsManager(logger);

/**
 * Main execution routine which handles command-line flags.
 */

(async () => {
  if (argv._[0] === 'console') {
    logger.debug('Opening url %s', url);

    return await open(SAML_URL);
  }

  if (argv.daemon) {
    return await daemonizer.install(process.platform, argv.googleIdpId, argv.googleSpId, argv.username, argv.daemonOutLogPath, argv.daemonErrorLogPath);
  }

  if (argv.clean) {
    logger.debug('Cleaning directory %s', paths.data)

    await trash(paths.data);
  }

  const spinner = ora({ isEnabled: !argv.verbose });

  if (!argv.headful) {
   spinner.start('Logging in');
  }

  let isAuthenticated = false;

  if (!argv.headful) {
    let session = await credentialsManager.getSessionExpirationFromCredentials(argv.awsSharedCredentialsFile, argv.awsProfile);

    if (!argv.force && session.isValid) {
      logger.debug('Skipping re-authorization as session is valid until %s. Use --force to ignore.', new Date(session.expiresAt));

      isAuthenticated = true;

      spinner.info('Login is still valid, no need to re-authorize!');
      return;
    }
  }

  const stealth = Stealth();
  const options = {
    headless: !argv.headful,
    userDataDir: paths.data,
  };

  if (argv.headful && argv.enableExperimentalU2FSupport) {
    stealth.enabledEvasions.delete('chrome.runtime');
    options.ignoreDefaultArgs = ['--disable-component-extensions-with-background-pages'];

    logger.debug('Enabled experimental U2F support');
  }

  puppeteer.use(stealth)

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
          spinner.stop();

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
              spinner.fail('You must choose one of the available role ARNs to authenticate or, alternatively, set one directly using the --aws-role-arn option');
              return;
            }


            role = roles[response.arn];

            spinner.info(`You may skip this step by invoking gsts with --aws-role-arn=${role.roleArn}`);
          } else {
            logger.debug(`Assuming role "${role.roleArn}" from the list of available roles %o due to non-interactive mode`, roles);
          }
        }

        await credentialsManager.assumeRoleWithSAML(samlAssertion, argv.awsSharedCredentialsFile, argv.awsProfile, role, sessionDuration);

        logger.debug(`Login successful${ argv.verbose ? ` and credentials stored in "${argv.awsSharedCredentialsFile}" under AWS profile "${argv.awsProfile}" with role ARN "${role.roleArn}"` : '!' }`);

        spinner.succeed('Login successful!');
      } catch (e) {
        logger.debug('An error has ocurred while authenticating', e);

        if (e instanceof errors.RoleNotFoundError) {
          request.abort();
          spinner.fail(`Role ARN "${argv.awsRoleArn}" not found in the list of available roles ${JSON.stringify(e.roles)}`);
          return;
        }

        if (['ValidationError', 'InvalidIdentityToken'].includes(e.code)) {
          request.abort();
          spinner.fail(`A remote error ocurred while assuming role: ${e.message}`);
          return;
        }

        request.abort();
        spinner.fail(`An unknown error has ocurred with message "${e.message}". Please try again with --verbose`)
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
    logger.debug(`Request to "${request.url()}" has been aborted`);
    await browser.close();
  });

  try {
    await page.goto(`https://accounts.google.com/o/saml2/initsso?idpid=${argv.googleIdpId}&spid=${argv.googleSpId}&forceauthn=false`)
  } catch (e) {
    logger.debug('An error ocurred while browsing to initsso page', e);
    return;
  }

  if (argv.headful) {
    try {
      await page.waitFor('input[type=email]');

      const selector = await page.$('input[type=email]');

      if (argv.username) {
        logger.debug(`Pre-filling email with ${argv.username}`);

        await selector.type(argv.username);
      }

      await page.waitForResponse('https://signin.aws.amazon.com/saml');
    } catch (e) {
      if (/Target closed/.test(e.message)) {
        logger.debug('Browser closed outside running context, exiting');
        return;
      }

      logger.debug('An error has ocurred while authenticating in headful mode', e);

      spinner.fail(`An unknown error has ocurred with message "${e.message}". Please try again with --verbose`)
    }
  }

  if (!isAuthenticated && !argv.headful) {
    spinner.warn('User is not authenticated, spawning headful instance');

    const args = [__filename, '--headful', ...process.argv.slice(2)];
    const ui = childProcess.spawn(process.execPath, args, { stdio: 'inherit' });

    ui.on('close', code => logger.debug(`Headful instance has exited with code ${code}`))
  }

  await browser.close();
})();
