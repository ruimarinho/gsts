#!/usr/bin/env node

const { parse } = require('querystring');
const AWS = require('aws-sdk');
const Saml = require('libsaml');
const log = require('debug')('gsts');
const fs = require('fs').promises;
const homedir = require('os').homedir();
const ini = require('ini');
const path = require('path')
const paths = require('env-paths')('gsts', { suffix: '' });
const puppeteer = require('puppeteer-extra');
const stealth = require('puppeteer-extra-plugin-stealth');

// AWS Credentials file path (multi-platform support).
const AWS_CREDENTIALS_FILE = path.join(homedir, '.aws', 'credentials');

// Regex pattern for Role.
const REGEX_PATTERN_ROLE = /arn:aws:iam:[^:]*:[0-9]+:role\/[^,]+/i;

// Regex pattern for Principal (SAML Provider).
const REGEX_PATTERN_PRINCIPAL = /arn:aws:iam:[^:]*:[0-9]+:saml-provider\/[^,]+/i;

// Parse command line arguments.
const argv = require('yargs')
  .usage('gsts')
  .env()
  .options({
    'aws-profile': {
      description: 'AWS Profile',
      default: 'sts'
    },
    'aws-role-arn': {
      description: 'AWS Role ARN'
    },
    'headful': {
      boolean: false,
      description: 'headful',
      hidden: true
    },
    'idp-id': {
      alias: 'google-idp-id',
      description: 'Google IDP ID',
      required: true
    },
    'sp-id': {
      alias: 'google-sp-id',
      description: 'Google SP ID',
      required: true
    },
    'username': {
      alias: 'google-username',
      description: 'Google username'
    },
  })
  .argv;

async function parseSamlRequest(details, { profile, role }) {
  log('Parsing SAML authentication data')

  const samlAssertion = unescape(parse(details._postData).SAMLResponse);
  const saml = new Saml(samlAssertion);

  log('Parsed SAML assertion %O', saml.parsedSaml);

  const attribute = saml.getAttribute('https://aws.amazon.com/SAML/Attributes/Role')[0];
	const roleArn = role || attribute.match(REGEX_PATTERN_ROLE)[0];
	const principalArn = attribute.match(REGEX_PATTERN_PRINCIPAL)[0];

  log('Found Role ARN %s', roleArn);
  log('Found Principal ARN %s', principalArn);

  const response = await (new AWS.STS).assumeRoleWithSAML({
		PrincipalArn: principalArn,
		RoleArn: roleArn,
		SAMLAssertion: samlAssertion
	}).promise();

  writeCredentials(profile, {
    accessKeyId: response.Credentials.AccessKeyId,
    secretAccessKey: response.Credentials.SecretAccessKey,
    expiration: response.Credentials.Expiration,
    sessionToken: response.Credentials.SessionToken
  });
}

async function writeCredentials(profile, { accessKeyId, secretAccessKey, expiration, sessionToken }) {
  const config = ini.parse(await fs.readFile(AWS_CREDENTIALS_FILE, 'utf-8'));

  config[profile] = {};
  config[profile].aws_access_key_id = accessKeyId;
  config[profile].aws_secret_access_key = secretAccessKey;
  config[profile].aws_session_expiration = expiration;
  config[profile].aws_session_token = sessionToken;

  await fs.writeFile(AWS_CREDENTIALS_FILE, ini.encode(config))

  log('Config file %O', config);
}

(async () => {
  let isAuthenticated = false;

  puppeteer.use(stealth());

  const browser = await puppeteer.launch({
    headless: !argv.headful,
    userDataDir: paths.data
  });

  const page = await browser.newPage();
  await page.setRequestInterception(true);
  await page.setDefaultTimeout(0);

  page.on('request', request => {
    if (request.url() === 'https://signin.aws.amazon.com/saml') {
      isAuthenticated = true;
      parseSamlRequest(request, { profile: argv.awsProfile, role: argv.awsRoleArn,  });
      request.continue();
      return;
    }

    if (!isAuthenticated && argv.headful) {
      request.continue();
      return;
    }

    if (/google|gstatic|youtube/.test(request.url())) {
      request.continue();
      return;
    }

    request.abort();
  });

  await page.goto(`https://accounts.google.com/o/saml2/initsso?idpid=${argv.googleIdpId}&spid=${argv.googleSpId}&forceauthn=false`);

  if (argv.headful) {
    await page.waitFor('input[type=email]');
    const selector = await page.$('input[type=email]');

    if (argv.username) {
      log('Pre-filling email with %s', argv.username);

      await selector.type(argv.username);
    }

    try {
      await page.waitForResponse('https://signin.aws.amazon.com/saml');
    } catch (e) {
      if (e.message === 'Target closed') {
        log('Browser closed outside running context, exiting');
        return;
      }

      log(e);
    }
  }

  if (!isAuthenticated && !argv.headful) {
    log('User is not authenticated, spawning headful instance');

    const spawn = require('child_process').spawn;
    const ui = spawn('node', ['index.js', '--headful'], { stdio: 'inherit' });
    ui.on('close', code => log(`Headful instance has exited with code ${code}`))
  }

  await browser.close();
})();
