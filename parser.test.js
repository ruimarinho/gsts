
/**
 * Dependencies.
 */


import { Logger } from './logger.js';
import { jest } from '@jest/globals';
import { Parser } from './parser.js';
import { Role } from './role.js';
import * as fixtures from './fixtures.js';

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

const logger = new Logger();
const parser = new Parser(logger);

/**
 * Tests.
 */

test('parses a single role from saml response', async () => {
  const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC);
  const response = await fixtures.getResponseFromAssertion(assertion);
  const {
    roles,
    samlAssertion,
    sessionDuration
  } = await parser.parseSamlResponse(response)

  const expected = [new Role('foobar', 'arn:aws:iam::123456789:role/foobar', 'arn:aws:iam::123456789:saml-provider/GSuite')];

  expect(roles).toMatchObject(expected);
  expect(samlAssertion).toBe(assertion);
  expect(sessionDuration).toBeUndefined();
});

test('parses multiple roles from saml response', async () => {
  const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
  const response = await fixtures.getResponseFromAssertion(assertion);
  const { roles } = await parser.parseSamlResponse(response);

  // Note: The order of the role's are as defined in the assertion
  const expected = [
    new Role('Foobiz', 'arn:aws:iam::987654321:role/Foobiz', 'arn:aws:iam::987654321:saml-provider/GSuite'),
    new Role('Admin', 'arn:aws:iam::987654321:role/Admin', 'arn:aws:iam::987654321:saml-provider/GSuite'),
    new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite')
  ];

  expect(roles).toMatchObject(expected);
});

test('parses custom session duration from saml response', async () => {
  const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_SESSION_DURATION);
  const response = await fixtures.getResponseFromAssertion(assertion);
  const { roles } = await parser.parseSamlResponse(response)

  expect(roles[0].sessionDuration).toBe(43200);
});

test('parses AWS GovCloud (US) ARNs', async () => {
  const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_GOV_CLOUD_US);
  const response = await fixtures.getResponseFromAssertion(assertion);
  const { roles } = await parser.parseSamlResponse(response)

  await expect(roles).toEqual([
    new Role('Foobar', 'arn:aws-us-gov:iam:us-gov-west-1:123456789012:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
  ]);
});

test('parses AWS CN ARNs', async () => {
  const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_CN);
  const response = await fixtures.getResponseFromAssertion(assertion);
  const { roles } = await parser.parseSamlResponse(response)

  await expect(roles).toEqual([
    new Role('Foobar', 'arn:aws-cn:iam::123456789012:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
  ]);
});
