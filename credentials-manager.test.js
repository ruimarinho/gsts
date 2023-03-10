
/**
 * Tests.
 */

import 'aws-sdk-client-mock-jest';
import { STSClient, AssumeRoleWithSAMLCommand } from '@aws-sdk/client-sts';
import { CredentialsManager } from './credentials-manager.js';
import { RoleNotFoundError } from './errors.js';
import { Session } from './session.js';
import { Role } from './role';
import { mockClient } from 'aws-sdk-client-mock';
import { mkdtemp, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { jest } from '@jest/globals';
import * as fixtures from './fixtures.js';

const awsRegion = 'us-east-1';
const awsProfile = 'test';

const mockSessionData = {
  accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
  role: new Role('Foobiz', 'arn:aws:iam::123456789:role/Foobiz', 'arn:aws:iam::123456789:saml-provider/GSuite'),
  secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
  expiresAt: new Date('2020-04-19T10:32:19.000Z'),
  sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB',
  samlAssertion: 'T2NjdXB5IE1hcnMK'
};

const mockAssumeRoleWithSAMLCommandResponse = {
  Credentials: {
    AccessKeyId: mockSessionData.accessKeyId,
    SecretAccessKey: mockSessionData.secretAccessKey,
    Expiration: mockSessionData.expiresAt,
    SessionToken: mockSessionData.sessionToken
  }
};

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
    const credentialsManager = new CredentialsManager(logger, awsRegion);
    const { roleToAssume, availableRoles, samlAssertion } = await credentialsManager.prepareRoleWithSAML(response);
    const expectedRoleToAssume = new Role('foobar', 'arn:aws:iam::123456789:role/foobar', 'arn:aws:iam::123456789:saml-provider/GSuite');

    await expect(roleToAssume).toEqual(expectedRoleToAssume);
    await expect(availableRoles).toEqual([expectedRoleToAssume]);
    await expect(samlAssertion).toEqual(assertion);
  });

  test('returns all roles available if custom role has not been requested and multiple roles are available', async () => {
    const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
    const response = await fixtures.getResponseFromAssertion(assertion);

    const credentialsManager = new CredentialsManager(logger, awsRegion);
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

    const credentialsManager = new CredentialsManager(logger, awsRegion);
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
    const credentialsManager = new CredentialsManager(logger, awsRegion);

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
    const cacheDir = await mkdtemp(join(tmpdir(), 'gsts-'));
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);

    stsMock.on(AssumeRoleWithSAMLCommand).resolves(mockAssumeRoleWithSAMLCommandResponse);

    await credentialsManager.assumeRoleWithSAML(mockSessionData.samlAssertion, mockSessionData.role, awsProfile);

    expect(stsMock).toHaveReceivedCommandWith(AssumeRoleWithSAMLCommand, {
      PrincipalArn: mockSessionData.role.principalArn,
      RoleArn: mockSessionData.role.roleArn,
      SAMLAssertion: mockSessionData.samlAssertion
    });

    expect((await credentialsManager.loadCredentials(awsProfile))).toEqual((new Session(mockSessionData)));
  });

  it('parses IAM role max session duration if custom session duration is defined', async () => {
    const validationError = new Error(`1 validation error detected: Value '43201' at 'durationSeconds' failed to satisfy constraint: Member must have value less than or equal to 43200`);
    validationError.Code = 'ValidationError';

    stsMock.on(AssumeRoleWithSAMLCommand).rejectsOnce(validationError)

    const credentialsManager = new CredentialsManager(logger, awsRegion);

    await expect(credentialsManager.assumeRoleWithSAML(mockSessionData.samlAssertion, mockSessionData.role, mockSessionData.awsProfile))
      .rejects
      .toThrow(`1 validation error detected: Value '43201' at 'durationSeconds' failed to satisfy constraint: Member must have value less than or equal to 43200`);
  });

  it('uses custom role session duration if set', async () => {
    const credentialsManager = new CredentialsManager(logger, awsRegion);

    stsMock.on(AssumeRoleWithSAMLCommand).resolves(mockAssumeRoleWithSAMLCommandResponse);

    await credentialsManager.assumeRoleWithSAML(mockSessionData.samlAssertion, mockSessionData.role, awsProfile, 900);

    expect(stsMock).toHaveReceivedCommandWith(AssumeRoleWithSAMLCommand, {
      DurationSeconds: 900,
      PrincipalArn: mockSessionData.role.principalArn,
      RoleArn: mockSessionData.role.roleArn,
      SAMLAssertion: mockSessionData.samlAssertion
    });
  });

  it('uses IdP-set role session duration if available', async () => {
    const credentialsManager = new CredentialsManager(logger, awsRegion);
    const roleWithCustomDuration = new Role(
      mockSessionData.role.name,
      mockSessionData.role.roleArn,
      mockSessionData.role.principalArn,
      900);

    stsMock.on(AssumeRoleWithSAMLCommand).resolves(mockAssumeRoleWithSAMLCommandResponse);

    await credentialsManager.assumeRoleWithSAML(mockSessionData.samlAssertion, roleWithCustomDuration, awsProfile);

    expect(stsMock).toHaveReceivedCommandWith(AssumeRoleWithSAMLCommand, {
      DurationSeconds: 900,
      PrincipalArn: mockSessionData.role.principalArn,
      RoleArn: mockSessionData.role.roleArn,
      SAMLAssertion: mockSessionData.samlAssertion
    });
  });

  it('saves credentials to cache dir if set', async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), 'gsts-'));

    stsMock.on(AssumeRoleWithSAMLCommand).resolves({
      Credentials: {
        AccessKeyId: mockSessionData.accessKeyId,
        SecretAccessKey: mockSessionData.secretAccessKey,
        Expiration: mockSessionData.expiresAt,
        SessionToken: mockSessionData.sessionToken
      }
    });

    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);
    await credentialsManager.assumeRoleWithSAML(mockSessionData.samlAssertion, mockSessionData.role, awsProfile);

    expect((await credentialsManager.loadCredentials(awsProfile))).toEqual((new Session(mockSessionData)));
  });

  it('does not save credentials to cache dir if not set', async () => {
    stsMock.on(AssumeRoleWithSAMLCommand).resolves(mockAssumeRoleWithSAMLCommandResponse);

    const credentialsManager = new CredentialsManager(logger, awsRegion);
    await credentialsManager.assumeRoleWithSAML(mockSessionData.samlAssertion, mockSessionData.role, awsProfile);

    await expect(credentialsManager.loadCredentials(awsProfile)).rejects.toThrow('ENOENT');
  });
});

describe('loadCredentials', () => {
  it('should throw an error if credentials are not found', async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), 'gsts-'));
    const awsRoleArn = 'arn:aws:iam::123456789:role/Foobar';
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);

    await expect(credentialsManager.loadCredentials(awsProfile, awsRoleArn)).rejects.toThrow('ENOENT');
  });

  it('should throw an error if credentials found are for a different role ARN', async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), 'gsts-'));
    const awsRoleArn = 'arn:aws:iam::987654321:role/Foobar';
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);

    await credentialsManager.saveCredentials(awsProfile, new Session(mockSessionData));

    await expect(credentialsManager.loadCredentials(awsProfile, awsRoleArn)).rejects.toThrow('Received role arn:aws:iam::987654321:role/Foobar but expected arn:aws:iam::123456789:role/Foobiz');
  });

  it('should throw an error if credentials for requested profile are not found', async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), 'gsts-'));
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);

    await credentialsManager.saveCredentials(awsProfile, new Session(mockSessionData));

    await expect(credentialsManager.loadCredentials('test-other')).rejects.toThrow('Profile "test-other" not found in credentials file');
  });

  it('should throw an error if credentials for requested profile are not found', async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), 'gsts-'));
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);

    await credentialsManager.saveCredentials(awsProfile, new Session(mockSessionData));

    await expect(credentialsManager.loadCredentials('test-other')).rejects.toThrow('Profile "test-other" not found in credentials file');
  });

  it('should return the credentials for the requested profile', async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), 'gsts-'));
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);
    const session = new Session(mockSessionData);

    await credentialsManager.saveCredentials(awsProfile, session);

    await expect((await credentialsManager.loadCredentials('test')).toJSON()).toEqual(session.toJSON());
  });
});

describe('saveCredentials', () => {
  it('creates cache directory if it does not exist', async () => {
    const cacheDir = `${tmpdir()}/gsts-${Math.random().toString(16).slice(2, 8)}`;
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);

    await credentialsManager.saveCredentials(awsProfile, new Session(mockSessionData));

    await stat(cacheDir);
  });

  it('stores session with owner read-write permissions only', async () => {
    const cacheDir = `${tmpdir()}/gsts-${Math.random().toString(16).slice(2, 8)}`;
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);
    const session = new Session(mockSessionData);

    await credentialsManager.saveCredentials(awsProfile, session);

    expect((await stat(credentialsManager.credentialsFile)).mode.toString(8)).toEqual(process.platform === "win32" ? '100666' : '100600');
  });

  it('stores session content under credentials files', async () => {
    const cacheDir = `${tmpdir()}/gsts-${Math.random().toString(16).slice(2, 8)}`;
    const credentialsManager = new CredentialsManager(logger, awsRegion, cacheDir);
    const session = new Session(mockSessionData);

    await credentialsManager.saveCredentials(awsProfile, session);

    const savedSession = await credentialsManager.loadCredentials(awsProfile);

    expect(session).toEqual(savedSession);
  });
});
