
/**
 * Module dependencies.
 */

const { parse } = require('querystring');
const Role = require('./role');
const Saml = require('libsaml');

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

  async parseSamlResponse(response) {
    const samlAssertion = unescape(parse(response).SAMLResponse);
    const saml = new Saml(samlAssertion);
    const roles = [];

    this.logger.debug('Parsed SAML assertion %o', saml.parsedSaml);

    for (const attribute of saml.getAttribute('https://aws.amazon.com/SAML/Attributes/Role')) {
      let principalMatches = attribute.match(REGEX_PATTERN_PRINCIPAL);
      let roleMatches = attribute.match(REGEX_PATTERN_ROLE);

      if (!principalMatches || !roleMatches) {
        return;
      }

      roles.push(new Role(roleMatches[0], principalMatches[0]))
    }

    this.logger.debug('Parsed Role attribute with value %o', roles);

    let [sessionDuration] = saml.getAttribute('https://aws.amazon.com/SAML/Attributes/SessionDuration');

    if (sessionDuration) {
      sessionDuration = Number(sessionDuration);

      this.logger.debug('Parsed SessionDuration attribute with value %d', sessionDuration);
    }

    return {
      sessionDuration,
      roles,
      samlAssertion
    };
  }
}

/**
 * Exports
 */

module.exports = Parser;
