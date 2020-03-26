
/**
 * Dependencies.
 */

const { escape } = require('querystring');
const fs = require('fs').promises;
const Logger = require('./logger')
const Parser = require('./parser');
const parser = new Parser(new Logger(process.stdout, process.stderr, 0));

/**
 * Samples
 */

/**
 * SAML response with a single role ARN.
 */

const SAML_SESSION_BASIC = 'saml-session-basic';

/**
 * SAML response with a custom session duration parameter.
 */

const SAML_SESSION_BASIC_WITH_SESSION_DURATION = 'saml-session-basic-with-session-duration';

/**
 * SAML response with multiple roles.
 */

const SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES = 'saml-session-basic-with-multiple-roles';

/**
 * Tests.
 */

test('parses principal and role arns from saml response', async () => {
  const assertion = await getSampleAssertion(SAML_SESSION_BASIC);
  const response = await getResponseFromAssertion(assertion);
  const {
    principalArn,
    roleArn,
    samlAssertion,
    sessionDuration
  } = await parser.parseSamlResponse(response)

  expect(principalArn).toBe('arn:aws:iam::123456789:saml-provider/GSuite');
  expect(roleArn).toBe('arn:aws:iam::123456789:role/foobar');
  expect(samlAssertion).toBe(assertion);
  expect(sessionDuration).toBe(3600);
});

test('parses custom session duration from saml response', async () => {
  const assertion = await getSampleAssertion(SAML_SESSION_BASIC_WITH_SESSION_DURATION);
  const response = await getResponseFromAssertion(assertion);
  const { sessionDuration } = await parser.parseSamlResponse(response)

  expect(sessionDuration).toBe(43200);
});

test('accepts custom role if multiple roles are available', async () => {
  const assertion = await getSampleAssertion(SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
  const response = await getResponseFromAssertion(assertion);
  const { principalArn, roleArn } = await parser.parseSamlResponse(response, 'arn:aws:iam::987654321:role/Foobiz');

  expect(principalArn).toBe('arn:aws:iam::987654321:saml-provider/GSuite');
  expect(roleArn).toBe('arn:aws:iam::987654321:role/Foobiz');
});

test('throws if custom role is not found', async () => {
  const assertion = await getSampleAssertion(SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
  const response = await getResponseFromAssertion(assertion);

  await expect(parser.parseSamlResponse(response, 'arn:aws:iam::987654321:role/Foobar')).rejects.toThrow(Parser.errors.ROLE_NOT_FOUND_ERROR);
});

/**
 * Test helpers.
 */

async function getResponseFromAssertion(assertion) {
  return `SAMLResponse=${escape(assertion)}`;
}

async function getSampleAssertion(name) {
  return Buffer.from(await fs.readFile(`fixtures/${name}.xml`, 'utf-8'), 'ascii').toString('base64')
}
