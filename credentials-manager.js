
/**
 * Module dependencies.
 */

const Parser = require('./parser');
const STS = require('aws-sdk/clients/sts');
const fs = require('fs').promises;
const ini = require('ini');

/**
 * Process a SAML response and extract all relevant data to be exchanged for an
 * STS token.
 */

class CredentialsManager {
  constructor(logger, { sessionDefaultDuration, sessionExpirationDelta }) {
    this.logger = logger;
    this.sessionDefaultDuration = sessionDefaultDuration;
    this.sessionExpirationDelta = sessionExpirationDelta;
    this.parser = new Parser(logger);
  }

  /**
   * Parse SAML response and assume role-.
   */

  async assumeRoleWithSAML(samlResponse, awsSharedCredentialsFile, awsProfile, awsRole) {
    const { sessionDuration, principalArn, roleArn, samlAssertion } = await this.parser.parseSamlResponse(samlResponse, awsRole);
    const awsResponse = await (new STS()).assumeRoleWithSAML({
      DurationSeconds: sessionDuration || this.sessionDefaultDuration,
      PrincipalArn: principalArn,
      RoleArn: roleArn,
      SAMLAssertion: samlAssertion
    }).promise();

    this.logger.debug('Role has been assumed %O', awsResponse);

    await this.saveCredentials(awsSharedCredentialsFile, awsProfile, {
      accessKeyId: awsResponse.Credentials.AccessKeyId,
      secretAccessKey: awsResponse.Credentials.SecretAccessKey,
      expiration: awsResponse.Credentials.Expiration,
      sessionToken: awsResponse.Credentials.SessionToken
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

  async saveCredentials(path, profile, { accessKeyId, secretAccessKey, expiration, sessionToken }) {
    // The config file may have other profiles configured, so parse existing data instead of writing a new file instead.
    let credentials = await this.loadCredentials(path);

    if (!credentials) {
      credentials = {};
    }

    credentials[profile] = {};
    credentials[profile].aws_access_key_id = accessKeyId;
    credentials[profile].aws_secret_access_key = secretAccessKey;
    credentials[profile].aws_session_expiration = expiration.toISOString();
    credentials[profile].aws_session_token = sessionToken;

    await fs.writeFile(path, ini.encode(credentials))

    this.logger.debug('Config file %O', credentials);
  }

  /**
   * Extract session expiration from AWS credentials file for a given profile.
   * The property `sessionExpirationDelta` represents a safety buffer to avoid requests
   * failing at the exact time of expiration.
   */

  async getSessionExpirationFromCredentials(credentialsPath, profile) {
    this.logger.debug('Attempting to retrieve session expiration credentials');

    const credentials = await this.loadCredentials(credentialsPath, profile);

    if (!credentials) {
      return { isValid: false, expiresAt: null };
    }

    if (!credentials.aws_session_expiration) {
      this.logger.debug('Session expiration date not found');

      return { isValid: false, expiresAt: null };
    }

    if (new Date(credentials.aws_session_expiration).getTime() - this.sessionExpirationDelta > Date.now()) {
      this.logger.debug('Session is expected to be valid until %s minus expiration delta of %d seconds', credentials.aws_session_expiration, this.sessionExpirationDelta / 1e3);

      return { isValid: true, expiresAt: new Date(credentials.aws_session_expiration).getTime() - this.sessionExpirationDelta };
    }

    this.logger.debug('Session has expired on %s', credentials.aws_session_expiration);

    return { isValid: false, expiresAt: new Date(credentials.aws_session_expiration).getTime() - this.sessionExpirationDelta };
  }
}

/**
 * Exports.
 */

module.exports = CredentialsManager;
