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
const path = require('path');
const paths = require('env-paths')('gsts', { suffix: '' });
const puppeteer = require('puppeteer-extra');
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

const credentialsManager = new CredentialsManager(logger, {
  sessionDefaultDuration: SESSION_DEFAULT_DURATION,
  sessionExpirationDelta: SESSION_EXPIRATION_DELTA
});

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

  let isAuthenticated = false;

  if (!argv.headful) {
    let session = await credentialsManager.getSessionExpirationFromCredentials(argv.awsSharedCredentialsFile, argv.awsProfile);

    if (!argv.force && session.isValid) {
      logger.info('Skipping re-authorization as session is valid until %s. Use --force to ignore.', new Date(session.expiresAt));

      isAuthenticated = true;
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
        await credentialsManager.assumeRoleWithSAML(request._postData, argv.awsSharedCredentialsFile, argv.awsProfile, argv.awsRoleArn);

        logger.info(`Login successful${ argv.verbose ? ` stored in ${argv.awsSharedCredentialsFile} with AWS profile "${argv.awsProfile}" and ARN role ${argv.awsRoleArn}` : '!' }`);
      } catch (e) {
        if (e.message === errors.ROLE_NOT_FOUND_ERROR) {
          logger.error('Custom role ARN %s not found', argv.awsRoleArn);
          request.abort();
          return;
        }

        if (e.code === 'ValidationError') {
          logger.error(e.message);
          request.abort();
          return;
        }

        request.abort();
        throw e;
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

  await page.goto(`https://accounts.google.com/o/saml2/initsso?idpid=${argv.googleIdpId}&spid=${argv.googleSpId}&forceauthn=false`);

  if (argv.headful) {
    try {
      await page.waitFor('input[type=email]');

      const selector = await page.$('input[type=email]');

      if (argv.username) {
        logger.debug('Pre-filling email with %s', argv.username);

        await selector.type(argv.username);
      }

      await page.waitForResponse('https://signin.aws.amazon.com/saml');
    } catch (e) {
      if (/Target closed/.test(e.message)) {
        logger.error('Browser closed outside running context, exiting');
        return;
      }

      logger.error(e);
    }
  }

  if (!isAuthenticated && !argv.headful) {
    logger.info('User is not authenticated, spawning headful instance');

    const args = [__filename, '--headful', ...process.argv.slice(2)];
    const ui = childProcess.spawn(process.execPath, args, { stdio: 'inherit' });

    ui.on('close', code => logger.debug(`Headful instance has exited with code ${code}`))
  }

  await browser.close();
})();
