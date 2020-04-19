
/**
 * Tests.
 */


const STS = require('aws-sdk/clients/sts');

jest.mock('aws-sdk/clients/sts');

const CredentialsManager = require('./credentials-manager');
const Logger = require('./logger')
const Role = require('./role');
const errors = require('./errors');
const fixtures = require('./fixtures');
const fs = require('fs').promises;
const os = require('os');
const path = require('path');

const logger = new Logger(process.stdout, process.stderr, 0);

describe('prepareRoleWithSAML', () => {
  test('returns all roles available if custom role has not been set', async () => {
    const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
    const response = await fixtures.getResponseFromAssertion(assertion);

    const credentialsManager = new CredentialsManager(logger);
    const { roles, samlAssertion, sessionDuration } = await credentialsManager.prepareRoleWithSAML(response);

    await expect(roles).toEqual([
      new Role('arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      new Role('arn:aws:iam::987654321:role/Foobiz', 'arn:aws:iam::987654321:saml-provider/GSuite')
    ]);
    await expect(samlAssertion).toEqual(assertion);
    await expect(sessionDuration).toBeUndefined();
  });

  test('returns default session duration if response does not include one', async () => {
    const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
    const response = await fixtures.getResponseFromAssertion(assertion);
    const sessionDefaultDuration = 20000;

    const credentialsManager = new CredentialsManager(logger, { sessionDefaultDuration });
    const { sessionDuration } = await credentialsManager.prepareRoleWithSAML(response);

    await expect(sessionDuration).toBe(sessionDefaultDuration);
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

    const expected = new errors.RoleNotFoundError([
      new Role('arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      new Role('arn:aws:iam::987654321:role/Foobiz', 'arn:aws:iam::987654321:saml-provider/GSuite')
    ]);
    await expect(error).toEqual(expected);
    await expect(error.roles).toEqual(expected.roles);
  });

  test('returns custom role only if custom role is available', async () => {
    const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
    const response = await fixtures.getResponseFromAssertion(assertion);

    const credentialsManager = new CredentialsManager(logger);
    const { roles, samlAssertion, sessionDuration } = await credentialsManager.prepareRoleWithSAML(response, 'arn:aws:iam::123456789:role/Foobar');

    await expect(roles).toEqual([
      new Role('arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
    ]);
    await expect(samlAssertion).toEqual(assertion);
    await expect(sessionDuration).toBeUndefined();
  });
});

describe('assumeRoleWithSAML', () => {
  it('assumes role with SAML and saves credentials', async () => {
    const accessKeyId = 'AAAAAABBBBBBCCCCCCDDDDDD';
    const secretAccessKey = '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4';
    const sessionToken = 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB';
    const sessionExpiration = new Date('2020-04-19T10:32:19.000Z');
    const assumeRoleWithSAMLPromise = jest.fn().mockReturnValue({
      promise: jest.fn().mockResolvedValue({
        Credentials: {
          AccessKeyId: accessKeyId,
          SecretAccessKey: secretAccessKey,
          Expiration: sessionExpiration,
          SessionToken: sessionToken
        }
      })
    })

    STS.mockImplementation(() => ({
      assumeRoleWithSAML: assumeRoleWithSAMLPromise
    }));

    const awsProfile = 'test';
    const awsSharedCredentialsFile = path.join(os.tmpdir(), 'aws');
    const role = new Role('arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite');
    const credentialsManager = new CredentialsManager(logger);
    await credentialsManager.assumeRoleWithSAML('foobar', awsSharedCredentialsFile, awsProfile, role, 43200);
    const savedCredentials = await fs.readFile(awsSharedCredentialsFile, 'utf-8');

    expect(assumeRoleWithSAMLPromise.mock.calls[0]).toEqual([{
      DurationSeconds: 43200,
      PrincipalArn: 'arn:aws:iam::123456789:saml-provider/GSuite',
      RoleArn: 'arn:aws:iam::123456789:role/Foobar',
      SAMLAssertion: 'foobar'
    }]);
    expect(savedCredentials).toBe(`[${awsProfile}]\naws_access_key_id=${accessKeyId}\naws_secret_access_key=${secretAccessKey}\naws_session_expiration=${sessionExpiration.toISOString()}\naws_session_token=${sessionToken}\n`);
  });

  describe('saveCredentials', () => {
    it('creates directory if it does not exist', async () => {
      const accessKeyId = 'AAAAAABBBBBBCCCCCCDDDDDD';
      const secretAccessKey = '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4';
      const sessionToken = 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB';
      const sessionExpiration = new Date('2020-04-19T10:32:19.000Z');
      const credentialsManager = new CredentialsManager(logger);
      const awsProfile = 'test';
      const awsSharedCredentialsFile = path.join(os.tmpdir(), Math.random().toString(36).substring(4), 'credentials');

      await credentialsManager.saveCredentials(awsSharedCredentialsFile, awsProfile, { accessKeyId, secretAccessKey, sessionExpiration, sessionToken });

      await fs.stat(awsSharedCredentialsFile);
    });
  });
});
