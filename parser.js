
/**
 * Module dependencies.
 */

const { parse } = require('querystring');
const Saml = require('libsaml');

// Default session duration, as states on AWS documentation.
// See https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/.
const DEFAULT_SESSION_DURATION = 3600 // 1 hour

// Regex pattern for Role.
const REGEX_PATTERN_ROLE = /arn:aws:iam:[^:]*:[0-9]+:role\/[^,]+/i;

// Regex pattern for Principal (SAML Provider).
const REGEX_PATTERN_PRINCIPAL = /arn:aws:iam:[^:]*:[0-9]+:saml-provider\/[^,]+/i;

/**
 * Process a SAML response and extract all relevant data to be exchanged for an
 * STS token.
 */

class Parser {
  constructor(logger) {
    this.logger = logger;
  }

  async parseSamlResponse(response, role) {
    const samlAssertion = unescape(parse(response).SAMLResponse);
    const saml = new Saml(samlAssertion);

    this.logger.debug('Parsed SAML assertion %O', saml.parsedSaml);

    const isTargetRole = (element) => element.match(role || REGEX_PATTERN_ROLE)
    const attribute = saml.getAttribute('https://aws.amazon.com/SAML/Attributes/Role').find(isTargetRole);

    if (!attribute) {
      throw new Error(Parser.errors.ROLE_NOT_FOUND_ERROR);
    }

    const roleArn = attribute.match(REGEX_PATTERN_ROLE)[0];
    const principalArn = attribute.match(REGEX_PATTERN_PRINCIPAL)[0];

    let sessionDuration = DEFAULT_SESSION_DURATION;

    if (saml.parsedSaml.attributes) {
      for (const attribute of saml.parsedSaml.attributes) {
        if (attribute.name === 'https://aws.amazon.com/SAML/Attributes/SessionDuration') {
          sessionDuration = Number(attribute.value[0]);
          this.logger.debug('Found SessionDuration attribute %s', sessionDuration);
        }
      }
    }

    this.logger.debug('Found Role ARN %s', roleArn);
    this.logger.debug('Found Principal ARN %s', principalArn);

    return {
      sessionDuration,
      principalArn,
      roleArn,
      samlAssertion
    };
  }
}

/**
 * Errors
 */

Parser.errors = {
  ROLE_NOT_FOUND_ERROR: 'ROLE_NOT_FOUND_ERROR'
}

module.exports = Parser;
