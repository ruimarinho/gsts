#!/usr/bin/env node

/**
 * Module dependencies.
 */

const { parse } = require('querystring');
const AWS = require('aws-sdk');
const Logger = require('./logger')
const Saml = require('libsaml');
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

// AWS Credentials file path (multi-platform support).
const AWS_CREDENTIALS_FILE = path.join(homedir, '.aws', 'credentials');

// Default session duration, as states on AWS documentation.
// See https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/.
const DEFAULT_SESSION_DURATION = 3600 // 1 hour

// Delta (in ms) between exact expiration date and current date to avoid requests
// on the same second to fail.
const EXPIRATION_DELTA = 30e3; // 30 seconds

// Regex pattern for Role.
const REGEX_PATTERN_ROLE = /arn:aws:iam:[^:]*:[0-9]+:role\/[^,]+/i;

// Regex pattern for Principal (SAML Provider).
const REGEX_PATTERN_PRINCIPAL = /arn:aws:iam:[^:]*:[0-9]+:saml-provider\/[^,]+/i;

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
    'clean': {
      boolean: false,
      description: 'Start authorization from a clean session state'
    },
    'daemon': {
      boolean: false,
      description: 'Install daemon service (only on macOS for now)'
    },
    'daemon-out-log-path': {
      description: `Path for storing the daemon's output log`,
      default: '/usr/local/var/log/gsts.stdout.log'
    },
    'daemon-error-log-path': {
      description: `Path for storing the daemon's error log`,
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
 * Process a SAML response and extract all relevant data to be exchanged for an
 * STS token.
 */

async function processSamlResponse(details, { profile, role }) {
  const samlAssertion = unescape(parse(details._postData).SAMLResponse);
  const saml = new Saml(samlAssertion);

  logger.debug('Parsed SAML assertion %O', saml.parsedSaml);

  const attribute = saml.getAttribute('https://aws.amazon.com/SAML/Attributes/Role')[0];
  const roleArn = role || attribute.match(REGEX_PATTERN_ROLE)[0];
  const principalArn = attribute.match(REGEX_PATTERN_PRINCIPAL)[0];

  let sessionDuration = DEFAULT_SESSION_DURATION;

  if (saml.parsedSaml.attributes) {
    for (const attribute of saml.parsedSaml.attributes) {
      if (attribute.name === 'https://aws.amazon.com/SAML/Attributes/SessionDuration') {
        sessionDuration = attribute.value[0];
        logger.debug('Found SessionDuration attribute %s', sessionDuration);
      }
    }
  }

  logger.debug('Found Role ARN %s', roleArn);
  logger.debug('Found Principal ARN %s', principalArn);

  const response = await (new AWS.STS).assumeRoleWithSAML({
    DurationSeconds: sessionDuration,
    PrincipalArn: principalArn,
    RoleArn: roleArn,
    SAMLAssertion: samlAssertion
  }).promise();

  logger.debug('Role has been assumed %O', response);

  await saveCredentials(profile, {
    accessKeyId: response.Credentials.AccessKeyId,
    secretAccessKey: response.Credentials.SecretAccessKey,
    expiration: response.Credentials.Expiration,
    sessionToken: response.Credentials.SessionToken
  });
}

/**
 * Load AWS credentials from the user home preferences.
 * Optionally accepts a AWS profile (usually a name representing
 * a section on the .ini-like file).
 */

async function loadCredentials(path, profile) {
  let credentials;

  try {
    credentials = await fs.readFile('foobar', 'utf-8')
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

async function saveCredentials(profile, { accessKeyId, secretAccessKey, expiration, sessionToken }) {
  // The config file may have other profiles configured, so parse existing data instead of writing a new file instead.
  let credentials = await loadCredentials(AWS_CREDENTIALS_FILE);

  if (!credentials) {
    credentials = {};
  }

  credentials[profile] = {};
  credentials[profile].aws_access_key_id = accessKeyId;
  credentials[profile].aws_secret_access_key = secretAccessKey;
  credentials[profile].aws_session_expiration = expiration.toISOString();
  credentials[profile].aws_session_token = sessionToken;

  await fs.writeFile(AWS_CREDENTIALS_FILE, ini.encode(credentials))

  logger.debug('Config file %O', credentials);
}

/**
 * Extract session expiration from AWS credentials file for a given profile.
 * The constant EXPIRATION_DELTA represents a safety buffer to avoid requests
 * failing at the exact time of expiration.
 */

async function getSessionExpirationForProfileCredentials(path, profile) {
  const credentials = await loadCredentials(path, profile);

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
  let { isValid: isSessionValid, expiresAt: sessionExpiresAt } = await getSessionExpirationForProfileCredentials(AWS_CREDENTIALS_FILE, argv.awsProfile);

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

      await processSamlResponse(request, { profile: argv.awsProfile, role: argv.awsRoleArn,  });

      logger.info('Login successful!');

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

    const args = ['gsts', '--headful'];

    if (argv.force) {
      args.push('--force');
    }

    if (argv.clean) {
      args.push('--clean');
    }

    const ui = childProcess.spawn('node', args, { stdio: 'inherit' });

    ui.on('close', code => logger.debug(`Headful instance has exited with code ${code}`))
  }

  await browser.close();
})();
