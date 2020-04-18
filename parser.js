
/**
 * Module dependencies.
 */

const { parse } = require('querystring');
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

    let sessionDuration;

    if (saml.parsedSaml.attributes) {
      for (const attribute of saml.parsedSaml.attributes) {
        if (attribute.name === 'https://aws.amazon.com/SAML/Attributes/SessionDuration') {
          sessionDuration = Number(attribute.value[0]);
          this.logger.debug('Parsed SessionDuration attribute with value %d', sessionDuration);
        }
      }
    }


    return {
      sessionDuration,
      roles,
      samlAssertion
    };
  }
}

class Role {
  constructor(roleArn, principalArn) {
    this.roleArn = roleArn;
    this.principalArn = principalArn;
  }
}

/**
 * Exports
 */

module.exports = Parser;
