
/**
 * Dependencies.
 */

const fixtures = require('./fixtures');
const Logger = require('./logger')
const Parser = require('./parser');
const Role = require('./role');
const parser = new Parser(new Logger(process.stdout, process.stderr, 0));

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

  const expected = [new Role('arn:aws:iam::123456789:role/foobar', 'arn:aws:iam::123456789:saml-provider/GSuite')];

  expect(roles).toMatchObject(expected);
  expect(samlAssertion).toBe(assertion);
  expect(sessionDuration).toBeUndefined();
});

test('parses multiple roles from saml response', async () => {
  const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES);
  const response = await fixtures.getResponseFromAssertion(assertion);
  const { roles } = await parser.parseSamlResponse(response);

  const expected = [
    new Role('arn:aws:iam::123456789:role/Foobar', 'arn:aws:iam::123456789:saml-provider/GSuite'),
    new Role('arn:aws:iam::987654321:role/Foobiz', 'arn:aws:iam::987654321:saml-provider/GSuite')
  ];

  expect(roles).toMatchObject(expected);
});

test('parses custom session duration from saml response', async () => {
  const assertion = await fixtures.getSampleAssertion(fixtures.SAML_SESSION_BASIC_WITH_SESSION_DURATION);
  const response = await fixtures.getResponseFromAssertion(assertion);
  const { sessionDuration } = await parser.parseSamlResponse(response)

  expect(sessionDuration).toBe(43200);
});
