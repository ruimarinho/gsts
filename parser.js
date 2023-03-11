
/**
 * Module dependencies.
 */

import { Role } from './role.js';
import Saml from 'libsaml';

// Regex pattern for Role.
const REGEX_PATTERN_ROLE = /(arn:(aws|aws-us-gov|aws-cn):iam:[^:]*:[0-9]+:role\/([^,]+))/i;

// Regex pattern for Principal (SAML Provider).
const REGEX_PATTERN_PRINCIPAL = /(arn:aws:iam:[^:]*:[0-9]+:saml-provider\/[^,]+)/i;

/**
 * Process a SAML response and extract all relevant data to be exchanged for an
 * STS token.
 */

export class Parser {
  constructor(logger) {
    this.logger = logger;
  }

  async parseSamlResponse(response) {
    const samlAssertion = response.SAMLResponse;
    const saml = new Saml(samlAssertion);
    const roles = [];

    this.logger.debug('Parsed SAML assertion %o', saml.parsedSaml);

    let [idpSessionDuration] = saml.getAttribute('https://aws.amazon.com/SAML/Attributes/SessionDuration');

    if (idpSessionDuration) {
      idpSessionDuration = Number(idpSessionDuration);

      this.logger.debug('Parsed `SessionDuration` attribute with value %d', idpSessionDuration);
    }

    for (const attribute of saml.getAttribute('https://aws.amazon.com/SAML/Attributes/Role')) {
      let principalMatches = attribute.match(REGEX_PATTERN_PRINCIPAL);
      let roleMatches = attribute.match(REGEX_PATTERN_ROLE);

      if (!principalMatches || !roleMatches) {
        continue;
      }

      let roleArn = roleMatches[1];
      let roleName = roleMatches[3];
      let samlProvider = principalMatches[1];

      roles.push(new Role(roleName, roleArn, samlProvider, idpSessionDuration))
    }

    this.logger.debug('Parsed `Role` attribute with value %o', roles);

    return {
      roles,
      samlAssertion
    };
  }
}
