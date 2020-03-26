#!/usr/bin/env node

/**
 * Module dependencies.
 */

const AWS = require('aws-sdk');
const Logger = require('./logger')
const Parser = require('./parser');
const childProcess = require('child_process');
const fs = require('fs').promises;
const homedir = require('os').homedir();
const ini = require('ini');
const open = require('open');
const path = require('path')
const paths = require('env-paths')('gsts', { suffix: '' });
const plist = require('plist');
const puppeteer = require('puppeteer-extra');
const stealth = require('puppeteer-extra-plugin-stealth');
const trash = require('trash');

// Delta (in ms) between exact expiration date and current date to avoid requests
// on the same second to fail.
const EXPIRATION_DELTA = 30e3; // 30 seconds

// Project namespace to be used for plist generation.
const PROJECT_NAMESPACE = 'io.github.ruimarinho.gsts';

// LaunchAgents plist path.
const MACOS_LAUNCH_AGENT_HELPER_PATH = path.join(process.env.HOME, 'Library', 'LaunchAgents', `${PROJECT_NAMESPACE}.plist`)

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
      description: 'Google Identity Provider ID (IDP IP)',
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
 * Create instance of Parser with logger.
 */

const parser = new Parser(logger);

/**
 * Load AWS credentials from the user home preferences.
 * Optionally accepts a AWS profile (usually a name representing
 * a section on the .ini-like file).
 */

async function loadCredentials(path, profile) {
  let credentials;

  try {
    credentials = await fs.readFile(path, 'utf-8')
  } catch (e) {
    if (e.code === 'ENOENT') {
      logger.debug('Credentials file does not exist at %s', path)
      return;
    }

    throw e;
  }

  const config = ini.parse(credentials);

  if (profile) {
    return config[profile];
  }

  return config;
}

/**
 * Save AWS credentials to a profile section.
 */

async function saveCredentials(path, profile, { accessKeyId, secretAccessKey, expiration, sessionToken }) {
  // The config file may have other profiles configured, so parse existing data instead of writing a new file instead.
  let credentials = await loadCredentials(path);

  if (!credentials) {
    credentials = {};
  }

  credentials[profile] = {};
  credentials[profile].aws_access_key_id = accessKeyId;
  credentials[profile].aws_secret_access_key = secretAccessKey;
  credentials[profile].aws_session_expiration = expiration.toISOString();
  credentials[profile].aws_session_token = sessionToken;

  await fs.writeFile(path, ini.encode(credentials))

  logger.debug('Config file %O', credentials);
}

/**
 * Extract session expiration from AWS credentials file for a given profile.
 * The constant EXPIRATION_DELTA represents a safety buffer to avoid requests
 * failing at the exact time of expiration.
 */

async function getSessionExpirationForProfileCredentials(credentialsPath, profile) {
  logger.debug('Attempting to retrieve session expiration credentials');

  const credentials = await loadCredentials(credentialsPath, profile);

  if (!credentials) {
    return { isValid: false, expiresAt: null };
  }

  if (!credentials.aws_session_expiration) {
    logger.debug('Session expiration date not found');

    return { isValid: false, expiresAt: null };
  }

  if (new Date(credentials.aws_session_expiration).getTime() - EXPIRATION_DELTA > Date.now()) {
    logger.debug('Session is expected to be valid until %s minus expiration delta of %d seconds', credentials.aws_session_expiration, EXPIRATION_DELTA / 1e3);

    return { isValid: true, expiresAt: new Date(credentials.aws_session_expiration).getTime() - EXPIRATION_DELTA };
  }

  logger.debug('Session has expired on %s', credentials.aws_session_expiration);

  return { isValid: false, expiresAt: new Date(credentials.aws_session_expiration).getTime() - EXPIRATION_DELTA };
}

/**
 * Remove a directory by trashing it (as opposed to permanently deleting it).
 */

async function cleanDirectory(path) {
  logger.debug('Cleaning session data directory %s', path)

  return await trash(path);
}

/**
 * Generate a launch agent plist based on dynamic values.
 */

function generateLaunchAgentPlist(idpId, spId, username, outLogPath, errorLogPath) {
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

async function installDaemon(platform, googleIdpId, googleSpId, username, daemonOutLogPath, daemonErrorLogPath) {
  if (platform !== 'darwin') {
    return logger.error('Sorry, this feature is only available on macOS at this time');
  }

  logger.debug('Unloading potentially existing launch agent at %s', MACOS_LAUNCH_AGENT_HELPER_PATH);

  await childProcess.execFile('launchctl', ['unload', MACOS_LAUNCH_AGENT_HELPER_PATH], (error, stdout, stderr) => {
    if (!error) {
      return;
    }

    if (stderr) {
      logger.error('Result from stderr while attempting to unload agent was "%s"', stderr);
    }

    if (stdout) {
      logger.info('Result from stdout while attempting to unload agent was "%s"', stdout);
    }

    logger.error(error);
  });

  const plist = generateLaunchAgentPlist(googleIdpId, googleSpId, username, daemonOutLogPath, daemonErrorLogPath).toString();

  logger.debug('Generated launch agent plist file %s', plist);

  await fs.writeFile(MACOS_LAUNCH_AGENT_HELPER_PATH, plist);

  logger.debug('Successfully wrote the launch agent plist to %s', MACOS_LAUNCH_AGENT_HELPER_PATH);

  await childProcess.execFile('launchctl', ['load', MACOS_LAUNCH_AGENT_HELPER_PATH], (error, stdout, stderr) => {
    if (error) {
      logger.error(error);
      return;
    }

    if (stderr) {
      logger.error('Result from stderr while attempting to load agent was "%s"', stderr);
    }

    if (stdout) {
      logger.info('Result from stdout while attempting to load agent was "%s"', stdout);
    } else {
      logger.info('Daemon installed successfully at %s', MACOS_LAUNCH_AGENT_HELPER_PATH)
    }
  });
}

/**
 * Open the given url on the user's default browser window.
 */

async function openConsole(url) {
  logger.debug('Opening url %s', url);

  return await open(url);
}

/**
 * Main execution routine which handles command-line flags.
 */

(async () => {
  if (argv._[0] === 'console') {
    return await openConsole(SAML_URL);
  }

  if (argv.daemon) {
    return await installDaemon(process.platform, argv.googleIdpId, argv.googleSpId, argv.username, argv.daemonOutLogPath, argv.daemonErrorLogPath);
  }

  if (argv.clean) {
    logger.debug('Cleaning directory %s', paths.data);

    await cleanDirectory(paths.data);
  }

  let isAuthenticated = false;
  let { isValid: isSessionValid, expiresAt: sessionExpiresAt } = await getSessionExpirationForProfileCredentials(argv.awsSharedCredentialsFile, argv.awsProfile);

  if (!argv.clean && !argv.force && isSessionValid) {
    logger.info('Skipping re-authorization as session is valid until %s. Use --force to ignore.', new Date(sessionExpiresAt));

    isAuthenticated = true;
    return;
  }

  puppeteer.use(stealth());

  const browser = await puppeteer.launch({
    headless: !argv.headful,
    userDataDir: paths.data
  });

  const page = await browser.newPage();
  await page.setRequestInterception(true);
  await page.setDefaultTimeout(0);

  page.on('request', async request => {
    if (request.url() === 'https://signin.aws.amazon.com/saml') {
      isAuthenticated = true;

      try {
        const { sessionDuration, principalArn, roleArn, samlAssertion } = await parser.parseSamlResponse(request._postData, argv.awsRoleArn);
        const response = await (new AWS.STS).assumeRoleWithSAML({
          DurationSeconds: sessionDuration,
          PrincipalArn: principalArn,
          RoleArn: roleArn,
          SAMLAssertion: samlAssertion
        }).promise();

        logger.debug('Role has been assumed %O', response);

        await saveCredentials(argv.awsSharedCredentialsFile, argv.awsProfile, {
          accessKeyId: response.Credentials.AccessKeyId,
          secretAccessKey: response.Credentials.SecretAccessKey,
          expiration: response.Credentials.Expiration,
          sessionToken: response.Credentials.SessionToken
        });

        logger.info(`Login successful${ argv.verbose ? ` stored in ${argv.awsSharedCredentialsFile} with AWS profile "${argv.awsProfile}" and ARN role ${argv.awsRoleArn}` : '!' }`);
      } catch (e) {
        if (e.message === Parser.errors.ROLE_NOT_FOUND_ERROR) {
          log.error('Custom role ARN %s not found', argv.awsRoleArn);
          return;
        }
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

    const args = ['--headful'];

    if (argv.force) {
      args.push('--force');
    }

    if (argv.clean) {
      args.push('--clean');
    }

    const ui = childProcess.spawn('gsts', args, { stdio: 'inherit' });

    ui.on('close', code => logger.debug(`Headful instance has exited with code ${code}`))
  }

  await browser.close();
})();

module.exports = {
  loadCredentials,
  saveCredentials,
  getSessionExpirationForProfileCredentials,
  cleanDirectory,
  installDaemon,
  openConsole
}
