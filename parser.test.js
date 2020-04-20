
/**
 * Dependencies.
 */


const Logger = require('./logger');
const Parser = require('./parser');
const Role = require('./role');
const fixtures = require('./fixtures');

jest.mock('./logger');

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

  const expected = [
    new Role('Foobar', 'arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
    new Role('Foobiz', 'arn:aws:iam::987654321:role/Foobiz', 'arn:aws:iam::987654321:saml-provider/GSuite')
  ];

  expect(roles).toMatchObject(expected);
});

test('parses custom session duration from saml response', async () => {
  const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_SESSION_DURATION);
  const response = await fixtures.getResponseFromAssertion(assertion);
  const { roles } = await parser.parseSamlResponse(response)

  expect(roles[0].sessionDuration).toBe(43200);
});
