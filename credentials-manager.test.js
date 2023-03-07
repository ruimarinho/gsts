
/**
 * Tests.
 */



import 'aws-sdk-client-mock-jest';
import { STSClient, AssumeRoleWithSAMLCommand } from '@aws-sdk/client-sts';
import { CredentialsManager } from './credentials-manager.js';
import { RoleNotFoundError } from './errors.js';
import { Role } from './role';
import { mockClient } from 'aws-sdk-client-mock';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { EOL, tmpdir } from 'node:os';
import { join } from 'node:path';
import { jest } from '@jest/globals';
import * as fixtures from './fixtures.js';
import ini from 'ini';

jest.unstable_mockModule('./logger.js', async () => ({
  Logger: function Logger() {
    return {
      format: jest.fn(),
      start: jest.fn(),
      stop: jest.fn(),
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      succeed: jest.fn()
    }
  }
}));

const { Logger } = (await import('./logger.js'));
const logger = new Logger();
const stsMock = mockClient(STSClient);

beforeEach(() => {
  stsMock.reset();
});

describe('prepareRoleWithSAML', () => {
  test('returns first role available if only one role is available', async () => {
    const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC);
    const response = await fixtures.getResponseFromAssertion(assertion);

    const credentialsManager = new CredentialsManager(logger);
    const { roleToAssume, availableRoles, samlAssertion } = await credentialsManager.prepareRoleWithSAML(response);
    const expectedRoleToAssume = new Role('foobar', 'arn:aws:iam::123456789:role/foobar', 'arn:aws:iam::123456789:saml-provider/GSuite');

    await expect(roleToAssume).toEqual(expectedRoleToAssume);
    await expect(availableRoles).toEqual([expectedRoleToAssume]);
    await expect(samlAssertion).toEqual(assertion);
  });

  test('returns all roles available if custom role has not been requested and multiple roles are available', async () => {
    const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
    const response = await fixtures.getResponseFromAssertion(assertion);

    const credentialsManager = new CredentialsManager(logger);
    const { roleToAssume, availableRoles, samlAssertion } = await credentialsManager.prepareRoleWithSAML(response);

    await expect(roleToAssume).toBeNull();
    await expect(availableRoles).toEqual([
      new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      new Role('Admin', 'arn:aws:iam::987654321:role/Admin', 'arn:aws:iam::987654321:saml-provider/GSuite'),
      new Role('Foobiz', 'arn:aws:iam::987654321:role/Foobiz', 'arn:aws:iam::987654321:saml-provider/GSuite')
    ]);
    await expect(samlAssertion).toEqual(assertion);
  });

  test('returns custom role if custom role requested was found', async () => {
    const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
    const response = await fixtures.getResponseFromAssertion(assertion);

    const credentialsManager = new CredentialsManager(logger);
    const { roleToAssume, availableRoles, samlAssertion } = await credentialsManager.prepareRoleWithSAML(response, 'arn:aws:iam::123456789:role/Foobar');

    await expect(roleToAssume).toEqual(new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'));
    await expect(availableRoles).toEqual([
      new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      new Role('Admin', 'arn:aws:iam::987654321:role/Admin', 'arn:aws:iam::987654321:saml-provider/GSuite'),
      new Role('Foobiz', 'arn:aws:iam::987654321:role/Foobiz', 'arn:aws:iam::987654321:saml-provider/GSuite')
    ]);
    await expect(samlAssertion).toEqual(assertion);
  });

  test('throws if custom role is not found', async () => {
    const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
    const response = await fixtures.getResponseFromAssertion(assertion);

    const credentialsManager = new CredentialsManager(logger);

    let error;
    try {
      await credentialsManager.prepareRoleWithSAML(response, 'arn:aws:iam::987654321:role/Foobar');
    } catch (e) {
      error = e;
    }

    const expected = new RoleNotFoundError([
      new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      new Role('Admin', 'arn:aws:iam::987654321:role/Admin', 'arn:aws:iam::987654321:saml-provider/GSuite'),
      new Role('Foobiz', 'arn:aws:iam::987654321:role/Foobiz', 'arn:aws:iam::987654321:saml-provider/GSuite')
    ]);
    await expect(error).toEqual(expected);
    await expect(error.roles).toEqual(expected.roles);
  });
});

describe('assumeRoleWithSAML', () => {
  it('assumes role with SAML and saves credentials', async () => {
    const accessKeyId = 'AAAAAABBBBBBCCCCCCDDDDDD';
    const secretAccessKey = '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4';
    const sessionToken = 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB';
    const sessionExpiration = new Date('2020-04-19T10:32:19.000Z');

    stsMock.on(AssumeRoleWithSAMLCommand).resolves({
      Credentials: {
        AccessKeyId: accessKeyId,
        SecretAccessKey: secretAccessKey,
        Expiration: sessionExpiration,
        SessionToken: sessionToken
      }
    });

    const awsProfile = 'test';
    const awsRegion = 'us-east-1';
    const awsSharedCredentialsFile = join(tmpdir(), 'aws');
    const role = new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite');
    const credentialsManager = new CredentialsManager(logger);
    await credentialsManager.assumeRoleWithSAML('foobar', awsSharedCredentialsFile, awsProfile, awsRegion, role);
    const savedCredentials = await readFile(awsSharedCredentialsFile, 'utf-8');

    expect(stsMock).toHaveReceivedCommandWith(AssumeRoleWithSAMLCommand, {
      PrincipalArn: 'arn:aws:iam::123456789:saml-provider/GSuite',
      RoleArn: 'arn:aws:iam::123456789:role/Foobar',
      SAMLAssertion: 'foobar'
    });

    expect(savedCredentials).toBe(`[${awsProfile}]${EOL}aws_access_key_id=${accessKeyId}${EOL}aws_role_arn=${role.roleArn}${EOL}aws_secret_access_key=${secretAccessKey}${EOL}aws_session_expiration=${sessionExpiration.toISOString()}${EOL}aws_session_token=${sessionToken}${EOL}`);
  });

  it('parses IAM role max session duration if custom session duration is defined', async () => {
    const accessKeyId = 'AAAAAABBBBBBCCCCCCDDDDDD';
    const secretAccessKey = '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4';
    const sessionToken = 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB';
    const sessionExpiration = new Date('2020-04-19T10:32:19.000Z');
    const validationError = new Error(`1 validation error detected: Value '43201' at 'durationSeconds' failed to satisfy constraint: Member must have value less than or equal to 43200`);
    validationError.code = 'ValidationError';

    stsMock
      .on(AssumeRoleWithSAMLCommand)
      .rejectsOnce(validationError)
      .resolvesOnce({
        Credentials: {
          AccessKeyId: accessKeyId,
          SecretAccessKey: secretAccessKey,
          Expiration: sessionExpiration,
          SessionToken: sessionToken
        }
      });

    const awsProfile = 'test';
    const awsRegion = 'us-east-1';
    const awsSharedCredentialsFile = join(tmpdir(), 'aws');
    const role = new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite');
    const credentialsManager = new CredentialsManager(logger);
    await credentialsManager.assumeRoleWithSAML('foobar', awsSharedCredentialsFile, awsProfile, awsRegion, role, 20000);

    expect(stsMock).toHaveReceivedCommandWith(AssumeRoleWithSAMLCommand, {
      DurationSeconds: 20000,
      PrincipalArn: 'arn:aws:iam::123456789:saml-provider/GSuite',
      RoleArn: 'arn:aws:iam::123456789:role/Foobar',
      SAMLAssertion: 'foobar'
    });
  });

  it('uses parsed role session duration if set on IDP', async () => {
    const accessKeyId = 'AAAAAABBBBBBCCCCCCDDDDDD';
    const secretAccessKey = '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4';
    const sessionToken = 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB';
    const sessionExpiration = new Date('2020-04-19T10:32:19.000Z');
    const awsProfile = 'test';
    const awsRegion = 'us-east-1';
    const awsSharedCredentialsFile = join(tmpdir(), 'aws');
    const role = new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite', 10000);

    stsMock
      .on(AssumeRoleWithSAMLCommand).resolves({
        Credentials: {
          AccessKeyId: accessKeyId,
          SecretAccessKey: secretAccessKey,
          Expiration: sessionExpiration,
          SessionToken: sessionToken
        }
      });

    const credentialsManager = new CredentialsManager(logger);
    await credentialsManager.assumeRoleWithSAML('foobar', awsSharedCredentialsFile, awsProfile, awsRegion, role);

    expect(stsMock).toHaveReceivedCommandWith(AssumeRoleWithSAMLCommand, {
      DurationSeconds: 10000,
      PrincipalArn: 'arn:aws:iam::123456789:saml-provider/GSuite',
      RoleArn: 'arn:aws:iam::123456789:role/Foobar',
      SAMLAssertion: 'foobar'
    });
  });

  it('defaults to IAM role max session duration if custom session duration exceeds it', async () => {
    const accessKeyId = 'AAAAAABBBBBBCCCCCCDDDDDD';
    const secretAccessKey = '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4';
    const sessionToken = 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB';
    const sessionExpiration = new Date('2020-04-19T10:32:19.000Z');
    const validationError = new Error(`1 validation error detected: Value '43201' at 'durationSeconds' failed to satisfy constraint: Member must have value less than or equal to 43200`);
    validationError.code = 'ValidationError';

    stsMock
      .on(AssumeRoleWithSAMLCommand)
        .rejectsOnce(validationError)
        .resolvesOnce({
          Credentials: {
            AccessKeyId: accessKeyId,
            SecretAccessKey: secretAccessKey,
            Expiration: sessionExpiration,
            SessionToken: sessionToken
          }
        });

    const awsProfile = 'test';
    const awsRegion = 'us-east-1';
    const awsSharedCredentialsFile = join(tmpdir(), 'aws');
    const role = new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite', 10000);
    const credentialsManager = new CredentialsManager(logger);
    await credentialsManager.assumeRoleWithSAML('foobar', awsSharedCredentialsFile, awsProfile, awsRegion, role, 60000);

    expect(stsMock).toHaveReceivedNthSpecificCommandWith(2, AssumeRoleWithSAMLCommand, {
      DurationSeconds: 43200,
      PrincipalArn: 'arn:aws:iam::123456789:saml-provider/GSuite',
      RoleArn: 'arn:aws:iam::123456789:role/Foobar',
      SAMLAssertion: 'foobar'
    });
  });

  describe('getSessionExpirationFromCredentials', () => {
    it('should return false if credentials are not found', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsRegion = 'us-east-1';
      const awsRoleArn = 'arn:aws:iam::123456789:role/Foobar';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);
      const { isValid, expiresAt } = await credentialsManager.getSessionExpirationFromCredentials(awsSharedCredentialsFile, awsProfile, awsRegion, awsRoleArn);

      expect(isValid).toBe(false);
      expect(expiresAt).toBe(null);
    });

    it('should return false if credentials are for a different role ARN', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsRoleArn = 'arn:aws:iam::987654321:role/Foobar';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, {
        accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        roleArn: 'arn:aws:iam::123456789:role/Foobiz',
        secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        sessionExpiration: new Date('2020-04-19T10:32:19.000Z'),
        sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
      });

      const { isValid, expiresAt } = await credentialsManager.getSessionExpirationFromCredentials(awsSharedCredentialsFile, awsProfile, awsRoleArn);

      expect(isValid).toBe(false);
      expect(expiresAt).toBe(null);
    });

    it('should return false if credentials session expiration is not found', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsRoleArn = 'arn:aws:iam::987654321:role/Foobar';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, {
        accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        roleArn: awsRoleArn,
        secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        sessionExpiration: new Date('2020-04-19T10:32:19.000Z'),
        sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
      });

      const savedCredentials = await readFile(awsSharedCredentialsFile, 'utf-8');
      const parsedCredentials = ini.parse(savedCredentials);
      delete parsedCredentials[awsProfile].aws_session_expiration;

      await writeFile(awsSharedCredentialsFile, ini.encode(parsedCredentials))

      const { isValid, expiresAt } = await credentialsManager.getSessionExpirationFromCredentials(awsSharedCredentialsFile, awsProfile, awsRoleArn);

      expect(isValid).toBe(false);
      expect(expiresAt).toBe(null);
    });

    it('should return false if credentials session expiration has passed', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsRoleArn = 'arn:aws:iam::987654321:role/Foobar';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const awsExpiresAt = new Date();
      const credentialsManager = new CredentialsManager(logger);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, {
        accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        roleArn: awsRoleArn,
        secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        sessionExpiration: awsExpiresAt,
        sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
      });

      const { isValid, expiresAt } = await credentialsManager.getSessionExpirationFromCredentials(awsSharedCredentialsFile, awsProfile, awsRoleArn);

      expect(isValid).toBe(false);
      expect(expiresAt).toBe(awsExpiresAt.toISOString());
    });

    it('should return false if credentials session expiration is inside valid window', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsRoleArn = 'arn:aws:iam::987654321:role/Foobar';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, {
        accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        roleArn: awsRoleArn,
        secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        sessionExpiration: new Date(Date.now() + credentialsManager.sessionExpirationDelta + 10000),
        sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
      });

      const { isValid, expiresAt } = await credentialsManager.getSessionExpirationFromCredentials(awsSharedCredentialsFile, awsProfile, awsRoleArn);

      expect(isValid).toBe(true);
      expect(expiresAt).not.toBe(null);
    });

    it('should return true if credentials are found for unspecified custom role ARN', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsRoleArn = 'arn:aws:iam::987654321:role/Foobar';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);
      const sessionExpiresAt = new Date(new Date().getTime() + 100000000);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, {
        accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        roleArn: 'arn:aws:iam::123456789:role/Foobiz',
        secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        sessionExpiration: sessionExpiresAt,
        sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
      });

      const { isValid, expiresAt } = await credentialsManager.getSessionExpirationFromCredentials(awsSharedCredentialsFile, awsProfile);

      expect(isValid).toBe(true);
      expect(expiresAt).toBe(new Date(sessionExpiresAt.getTime() - credentialsManager.sessionExpirationDelta).toISOString());
    });
  });

  describe('loadCredentials', () => {
    it('should not throw an error if credentials file does not exist', async () => {
      const awsDirectory = join(tmpdir(), Math.random().toString(36).substring(4));
      const awsProfile = 'test';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);
      const credentials = await credentialsManager.loadCredentials(awsSharedCredentialsFile, awsProfile);

      expect(credentials).toBe(undefined);
    });

    it('should not throw an error if credentials profile does not exist', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, {
        accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        roleArn: 'arn:aws:iam::987654321:role/Foobar',
        secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        sessionExpiration: new Date(),
        sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
      });

      const credentials = await credentialsManager.loadCredentials(awsSharedCredentialsFile, 'foobar');

      expect(credentials).toBe(undefined);
    });

    it('should return the full config if credentials profile is not set', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsExpiresAt = new Date();
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, {
        accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        roleArn: 'arn:aws:iam::987654321:role/Foobar',
        secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        sessionExpiration: awsExpiresAt,
        sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
      });

      const credentials = await credentialsManager.loadCredentials(awsSharedCredentialsFile);

      expect(credentials).toMatchObject({
        test: {
          aws_access_key_id: 'AAAAAABBBBBBCCCCCCDDDDDD',
          aws_role_arn: 'arn:aws:iam::987654321:role/Foobar',
          aws_secret_access_key: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
          aws_session_expiration: awsExpiresAt.toISOString(),
          aws_session_token: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
        }
      });
    });
  });

  describe('saveCredentials', () => {
    it('creates directory if it does not exist', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const accessKeyId = 'AAAAAABBBBBBCCCCCCDDDDDD';
      const roleArn = 'arn:aws:iam::987654321:role/Foobar';
      const secretAccessKey = '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4';
      const sessionToken = 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB';
      const sessionExpiration = new Date('2020-04-19T10:32:19.000Z');
      const credentialsManager = new CredentialsManager(logger);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, { accessKeyId, roleArn, secretAccessKey, sessionExpiration, sessionToken });

      await stat(awsSharedCredentialsFile);
    });
  });

  describe('exportAsJSON', () => {
    it('should return a basic json structure when credentials are missing', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);
      const credentials = await credentialsManager.exportAsJSON(awsSharedCredentialsFile);

      expect(credentials).toStrictEqual(JSON.stringify({
        Version: 1
      }));
    });

    it('should return credentials in json format', async () => {
      const awsDirectory = await mkdtemp(join(tmpdir(), 'gsts-'));
      const awsProfile = 'test';
      const awsExpiresAt = new Date();
      const awsSharedCredentialsFile = join(awsDirectory, 'credentials');
      const credentialsManager = new CredentialsManager(logger);

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, {
        accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        roleArn: 'arn:aws:iam::987654321:role/Foobar',
        secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        sessionExpiration: awsExpiresAt,
        sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB'
      });

      const credentials = await credentialsManager.exportAsJSON(awsSharedCredentialsFile, awsProfile);

      expect(credentials).toStrictEqual(JSON.stringify({
        Version: 1,
        AccessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
        SecretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
        SessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB',
        Expiration: awsExpiresAt.toISOString()
      }));
    });
  });
});
