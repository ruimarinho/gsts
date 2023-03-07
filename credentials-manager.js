
/**
 * Module dependencies.
 */

import { Parser } from './parser.js';
import { STSClient, AssumeRoleWithSAMLCommand } from '@aws-sdk/client-sts';
import { RoleNotFoundError } from './errors.js';
import { dirname } from 'node:path';
import { mkdir, stat, readFile, writeFile } from 'node:fs/promises';
import ini from 'ini';

// Delta (in seconds) between exact expiration date and current date to avoid requests
// on the same second to fail.
const SESSION_EXPIRATION_DELTA = 30e3; // 30 seconds

// Regex pattern for duration seconds validation error.
const REGEX_PATTERN_DURATION_SECONDS = /value less than or equal to ([0-9]+)/

/**
 * Recursively create a directory based on the implementation
 * from https://github.com/jprichardson/node-fs-extra.
 */

async function mkdirP(path, mode) {
  try {
    await mkdir(path, mode);
  } catch (e) {
    if (e.code === 'EPERM') {
      throw e;
    }

    if (e.code === 'ENOENT') {
      if (dirname(path) === path) {
        // This replicates the exception of `mkdir` with the native
        // `recusive` option when ran on an invalid drive under Windows.
        // From https://github.com/jprichardson/node-fs-extra.
        const error = new Error(`operation not permitted, mkdir '${path}'`);
        error.code = 'EPERM';
        error.errno = -4048;
        error.path = path;
        error.syscall = 'mkdir';
        throw error;
      }

      if (e.message.includes('null bytes')) {
        throw e;
      }

      await mkdirP(dirname(path));
    }

    try {
      const stats = await stat(path);
      if (!stats.isDirectory()) {
        // This error is never exposed to the user
        // it is caught below, and the original error is thrown
        throw new Error('The path is not a directory');
      }
    } catch (e) {
      if (e.code !== 'EEXIST') {
        throw e;
      }
    }
  }
}

/**
 * Process a SAML response and extract all relevant data to be exchanged for an
 * STS token.
 */

export class CredentialsManager {
  constructor(logger) {
    this.logger = logger;
    this.sessionExpirationDelta = SESSION_EXPIRATION_DELTA;
    this.parser = new Parser(logger);
  }

  async prepareRoleWithSAML(samlResponse, customRoleArn) {
    const { roles, samlAssertion } = await this.parser.parseSamlResponse(samlResponse, customRoleArn);

    if (roles && roles.length) {
      roles.sort((a, b) => {
        if (a.roleArn < b.roleArn) {
          return -1;
        } else if (a.roleArn > b.roleArn) {
          return 1;
        }
        return 0;
      });
    }

    if (!customRoleArn) {
      this.logger.debug('A custom role ARN not been set so returning all parsed roles');

      return {
        roleToAssume: roles.length === 1 ? roles[0] : null,
        availableRoles: roles,
        samlAssertion
      }
    }

    const customRole = roles.find(role => role.roleArn === customRoleArn);

    if (!customRole) {
      throw new RoleNotFoundError(roles);
    }

    this.logger.debug('Found custom role ARN "%s" with principal ARN "%s"', customRole.roleArn, customRole.principalArn);

    return {
      roleToAssume: customRole,
      availableRoles: roles,
      samlAssertion
    }
  }

  /**
   * Parse SAML response and assume role-.
   */

  async assumeRoleWithSAML(samlAssertion, awsSharedCredentialsFile, awsProfile, awsRegion, role, customSessionDuration) {
    let sessionDuration = role.sessionDuration;

    if (customSessionDuration) {
      sessionDuration = customSessionDuration;

      try {
        await (new STSClient({ region: awsRegion })).send(new AssumeRoleWithSAMLCommand({
          DurationSeconds: sessionDuration,
          PrincipalArn: role.principalArn,
          RoleArn: role.roleArn,
          SAMLAssertion: samlAssertion
        }));

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

    const stsResponse = await (new STSClient({ region: awsRegion })).send(new AssumeRoleWithSAMLCommand({
      DurationSeconds: sessionDuration,
      PrincipalArn: role.principalArn,
      RoleArn: role.roleArn,
      SAMLAssertion: samlAssertion
    }));

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
      credentials = await readFile(path, 'utf-8')
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
    await writeFile(path, ini.encode(credentials));

    this.logger.info('The credentials have been stored in "%s" under AWS profile "%s" with contents %o', path, profile, credentials);
  }

  /**
   * Export credentials as JSON output for use with AWS's `credential_process`.
   * See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
   */

  async exportAsJSON(path, profile) {
    this.logger.debug('Outputting data as JSON');

    let credentials = await this.loadCredentials(path, profile);

    if (!credentials) {
      // Return a minimally-valid JSON so that the AWS SDK can return a proper error
      // message instead of a failure parsing the output of this tool.
      return JSON.stringify({ Version: 1 });
    }

    return JSON.stringify({
      Version: 1,
      AccessKeyId: credentials.aws_access_key_id,
      SecretAccessKey: credentials.aws_secret_access_key,
      SessionToken: credentials.aws_session_token,
      Expiration: credentials.aws_session_expiration
    });
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
      this.logger.warn('Found credentials for a different role ARN (found "%s" != received "%s")', credentials.aws_role_arn, roleArn);

      return { isValid: false, expiresAt: null };
    }

    if (!credentials.aws_session_expiration) {
      this.logger.debug('Session expiration date not found');

      return { isValid: false, expiresAt: null };
    }

    if (new Date(credentials.aws_session_expiration).getTime() - this.sessionExpirationDelta > Date.now()) {
      this.logger.info('Session is expected to be valid until %s minus expiration delta of %d seconds', credentials.aws_session_expiration, this.sessionExpirationDelta / 1e3);

      return { isValid: true, expiresAt: new Date(new Date(credentials.aws_session_expiration).getTime() - this.sessionExpirationDelta).toISOString() };
    }

    this.logger.info('Session has expired on %s', credentials.aws_session_expiration);

    return { isValid: false, expiresAt: new Date(credentials.aws_session_expiration).toISOString() };
  }
}
