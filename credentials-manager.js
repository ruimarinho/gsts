
/**
 * Module dependencies.
 */

const { dirname, join, normalize, sep } = require('path');
const Parser = require('./parser');
const STS = require('aws-sdk/clients/sts');
const errors = require('./errors');
const ffs = require('fs');
const ini = require('ini');
const util = require('util');
const fs = {
  exists: util.promisify(ffs.exists),
  mkdir: util.promisify(ffs.mkdir),
  readFile: util.promisify(ffs.readFile),
  writeFile: util.promisify(ffs.writeFile),
}

// Delta (in seconds) between exact expiration date and current date to avoid requests
// on the same second to fail.
const SESSION_EXPIRATION_DELTA = 30e3; // 30 seconds

// Regex pattern for duration seconds validation error.
const REGEX_PATTERN_DURATION_SECONDS = /value less than or equal to ([0-9]+)/

/**
 * Create directory if it doesn't exist. Create parent directories as needed
 */
async function mkdirP(path, mode) {
  let dirs = normalize(path).split(sep).filter(d => d);
  for (let i = 0; i < dirs.length; i++) {
    let dir = join('/', ...dirs.slice(0, i+1));
    let exists = await fs.exists(dir);
    if (!exists) {
      await fs.mkdir(dir, mode);
    }
  }
}

/**
 * Process a SAML response and extract all relevant data to be exchanged for an
 * STS token.
 */

class CredentialsManager {
  constructor(logger) {
    this.logger = logger;
    this.sessionExpirationDelta = SESSION_EXPIRATION_DELTA;
    this.parser = new Parser(logger);
  }

  async prepareRoleWithSAML(response, customRoleArn) {
    const { roles, samlAssertion } = await this.parser.parseSamlResponse(response, customRoleArn);

    if (!customRoleArn) {
      this.logger.debug('A custom role ARN not been set so returning all parsed roles');

      return {
        roles,
        samlAssertion
      }
    }

    const customRole = roles.find(role => role.roleArn === customRoleArn);

    if (!customRole) {
      throw new errors.RoleNotFoundError(roles);
    }

    this.logger.debug('Found custom role ARN "%s" with principal ARN "%s"', customRole.roleArn, customRole.principalArn);

    return {
      roles: [customRole],
      samlAssertion
    }
  }

  /**
   * Parse SAML response and assume role-.
   */

  async assumeRoleWithSAML(samlAssertion, awsSharedCredentialsFile, awsProfile, role, customSessionDuration) {
    let sessionDuration = role.sessionDuration;

    if (customSessionDuration) {
      sessionDuration = customSessionDuration;

      try {
        await (new STS()).assumeRoleWithSAML({
          DurationSeconds: sessionDuration,
          PrincipalArn: role.principalArn,
          RoleArn: role.roleArn,
          SAMLAssertion: samlAssertion
        }).promise();
      } catch (e) {
        if (e.code !== 'ValidationError' ||  !/durationSeconds/.test(e.message)) {
          throw e;
        }

        let matches = e.message.match(REGEX_PATTERN_DURATION_SECONDS);
        if (!matches) {
          return;
        }

        let duration = matches[1];
        if (duration) {
          sessionDuration = Number(duration);

          this.logger.warn('Custom session duration %d exceeds maximum session duration of %d allowed for role. Please set --aws-session-duration=%d or $AWS_SESSION_DURATION=%d to surpress this warning', customSessionDuration, sessionDuration, sessionDuration, sessionDuration);
        }
      }
    }

    const stsResponse = await (new STS()).assumeRoleWithSAML({
      DurationSeconds: sessionDuration,
      PrincipalArn: role.principalArn,
      RoleArn: role.roleArn,
      SAMLAssertion: samlAssertion
    }).promise();

    this.logger.debug('Role ARN "%s" has been assumed %O', role.roleArn, stsResponse);

    await this.saveCredentials(awsSharedCredentialsFile, awsProfile, {
      accessKeyId: stsResponse.Credentials.AccessKeyId,
      roleArn: role.roleArn,
      secretAccessKey: stsResponse.Credentials.SecretAccessKey,
      sessionExpiration: stsResponse.Credentials.Expiration,
      sessionToken: stsResponse.Credentials.SessionToken
    });
  }

  /**
   * Load AWS credentials from the user home preferences.
   * Optionally accepts a AWS profile (usually a name representing
   * a section on the .ini-like file).
   */

  async loadCredentials(path, profile) {
    let credentials;

    try {
      credentials = await fs.readFile(path, 'utf-8')
    } catch (e) {
      if (e.code === 'ENOENT') {
        this.logger.debug('Credentials file does not exist at %s', path)
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

  async saveCredentials(path, profile, { accessKeyId, roleArn, secretAccessKey, sessionExpiration, sessionToken }) {
    // The config file may have other profiles configured, so parse existing data instead of writing a new file instead.
    let credentials = await this.loadCredentials(path);

    if (!credentials) {
      credentials = {};
    }

    credentials[profile] = {};
    credentials[profile].aws_access_key_id = accessKeyId;
    credentials[profile].aws_role_arn = roleArn;
    credentials[profile].aws_secret_access_key = secretAccessKey;
    credentials[profile].aws_session_expiration = sessionExpiration.toISOString();
    credentials[profile].aws_session_token = sessionToken;

    await mkdirP(dirname(path));
    await fs.writeFile(path, ini.encode(credentials));

    this.logger.debug('The credentials have been stored in "%s" under AWS profile "%s" with contents %o', path, profile, credentials);
  }

  /**
   * Extract session expiration from AWS credentials file for a given profile.
   * The property `sessionExpirationDelta` represents a safety buffer to avoid requests
   * failing at the exact time of expiration.
   */

  async getSessionExpirationFromCredentials(path, profile, roleArn) {
    this.logger.debug('Attempting to retrieve session expiration credentials');

    const credentials = await this.loadCredentials(path, profile);

    if (!credentials) {
      return { isValid: false, expiresAt: null };
    }

    if (roleArn && credentials.aws_role_arn !== roleArn)  {
      this.logger.warn('Found credentials for a different role ARN');

      return { isValid: false, expiresAt: null };
    }

    if (!credentials.aws_session_expiration) {
      this.logger.debug('Session expiration date not found');

      return { isValid: false, expiresAt: null };
    }

    if (new Date(credentials.aws_session_expiration).getTime() - this.sessionExpirationDelta > Date.now()) {
      this.logger.debug('Session is expected to be valid until %s minus expiration delta of %d seconds', credentials.aws_session_expiration, this.sessionExpirationDelta / 1e3);

      return { isValid: true, expiresAt: new Date(new Date(credentials.aws_session_expiration).getTime() - this.sessionExpirationDelta).toISOString() };
    }

    this.logger.debug('Session has expired on %s', credentials.aws_session_expiration);

    return { isValid: false, expiresAt: new Date(credentials.aws_session_expiration).toISOString() };
  }
}

/**
 * Exports.
 */

module.exports = CredentialsManager;
