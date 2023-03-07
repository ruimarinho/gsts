
/**
 * Module dependencies.
 */

import { Role } from './role.js';

/**
 * Session.
 */

export class Session {
  constructor({ accessKeyId, secretAccessKey, sessionToken, expiresAt, role, samlAssertion }) {
    if (!(expiresAt instanceof Date)) {
      throw new Error('`expiresAt` must be an instance of Date');
    }

    if (!(role instanceof Role)) {
      throw new Error('`role` must be an instance of Role');
    }

    this.version = 1;
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.sessionToken = sessionToken;
    this.expiresAt = expiresAt;;
    this.role = role;
    this.samlAssertion = samlAssertion;
  }

  static fromIni(content) {
    return new Session({
      accessKeyId: content.aws_access_key_id,
      role: new Role(content.aws_role_name, content.aws_role_arn, content.aws_role_principal_arn),
      secretAccessKey: content.aws_secret_access_key,
      expiresAt: new Date(content.aws_session_expiration),
      sessionToken: content.aws_session_token,
      samlAssertion: content.aws_saml_assertion
    });
  }

  isValid() {
    if (!this.accessKeyId || !this.secretAccessKey || !this.sessionToken || !this.expiresAt) {
      return false;
    }

    if (this.expiresAt.getTime() <= Date.now()) {
      return false;
    }

    return true;
  }

  toIni(profile) {
    return {
      [profile]: {
        aws_access_key_id: this.accessKeyId,
        aws_role_arn: this.role.roleArn,
        aws_role_name: this.role.name,
        aws_role_principal_arn: this.role.principalArn,
        aws_secret_access_key: this.secretAccessKey,
        aws_session_expiration: this.expiresAt.toISOString(),
        aws_session_token: this.sessionToken,
        aws_saml_assertion: this.samlAssertion
      }
    }
  }

  /**
   * Export credentials as JSON output for use with third-party tools like
   * AWS's `credential_process`.
   *
   * @See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
   */
  toJSON() {
    return JSON.stringify({
      Version: this.version,
      AccessKeyId: this.accessKeyId,
      SecretAccessKey: this.secretAccessKey,
      SessionToken: this.sessionToken,
      Expiration: this.expiresAt
    });
  }
}
