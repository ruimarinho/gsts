
/**
 * Module dependencies.
 */

import { Parser } from './parser.js';
import { STSClient, AssumeRoleWithSAMLCommand } from '@aws-sdk/client-sts';
import { RoleNotFoundError } from './errors.js';
import { Session } from './session.js';
import { dirname, join } from 'node:path';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import ini from 'ini';

// Regex pattern for duration seconds validation error.
const REGEX_PATTERN_DURATION_SECONDS = /value less than or equal to ([0-9]+)/

/**
 * Process a SAML response and extract all relevant data to be exchanged for an
 * STS token.
 */

export class CredentialsManager {
  constructor(logger, region, cacheDir) {
    this.logger = logger;
    this.parser = new Parser(logger);
    this.credentialsFile = cacheDir ? join(cacheDir, 'credentials') : null;
    this.stsClient = new STSClient({ region })
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

  async assumeRoleWithSAML(samlAssertion, role, profile, customSessionDuration) {
    let sessionDuration = role.sessionDuration;

    if (customSessionDuration) {
      sessionDuration = customSessionDuration;

      try {
        await this.stsClient.send(new AssumeRoleWithSAMLCommand({
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

    const stsResponse = await this.stsClient.send(new AssumeRoleWithSAMLCommand({
      DurationSeconds: sessionDuration,
      PrincipalArn: role.principalArn,
      RoleArn: role.roleArn,
      SAMLAssertion: samlAssertion
    }));

    this.logger.debug('Role ARN "%s" has been assumed %O', role.roleArn, stsResponse);

    const session = new Session({
      accessKeyId: stsResponse.Credentials.AccessKeyId,
      secretAccessKey: stsResponse.Credentials.SecretAccessKey,
      sessionToken: stsResponse.Credentials.SessionToken,
      expiresAt: new Date(stsResponse.Credentials.Expiration),
      role,
      samlAssertion,
      profile
    });

    if (this.credentialsFile) {
      await this.saveCredentials(profile, session);
    }

    return session;
  }

  /**
   * Save AWS credentials to a profile section.
   */

  async saveCredentials(profile, session) {
    const contents = ini.encode(session.toIni(profile));

    await mkdir(dirname(this.credentialsFile), { recursive: true });
    await writeFile(this.credentialsFile, contents);
    await chmod(this.credentialsFile, 0o600)

    this.logger.info('The credentials have been stored in "%s" under AWS profile "%s" with contents %o', this.credentialsFile, profile, contents);
  }

  /**
   * Load AWS credentials from the user home preferences.
   * Optionally accepts a AWS profile (usually a name representing
   * a section on the .ini-like file).
   */
  /**
   * Extract session expiration from AWS credentials file for a given profile.
   * The property `sessionExpirationDelta` represents a safety buffer to avoid requests
   * failing at the exact time of expiration.
   */

  async loadCredentials(profile, roleArn) {
    this.logger.debug('Loading credentials from "%s" for profile "%s".', this.credentialsFile, profile);

    let credentials;

    try {
      credentials = ini.parse(await readFile(this.credentialsFile, 'utf-8'));
    } catch (e) {
      if (e.code === 'ENOENT') {
        this.logger.debug('Credentials file does not exist at %s.', this.credentialsFile)
      }

      throw e;
    }

    if (!credentials[profile]) {
      throw new Error(`Credentials for profile "${profile}" are not available.`);
    }

    const session = Session.fromIni(credentials[profile]);

    if (roleArn && session.role.roleArn)  {
      this.logger.warn('Found profile "%s" credentials for a different role ARN (found "%s" != received "%s")', profile, session.role.roleArn, roleArn);

      throw new Error('Invalid role ARN');
    }

    return session;
  }
}
