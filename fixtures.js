
/**
 * Module dependencies.
 */

import { readFile } from 'node:fs/promises';

/**
 * Samples
 */

/**
 * SAML response with a single role ARN.
 */

const SAML_SESSION_BASIC = 'saml-session-basic';

/**
 * SAML response with a single AWS GovCloud (US) role ARN.
 */

const SAML_SESSION_BASIC_GOV_CLOUD_US = 'saml-session-basic-gov-cloud-us';

/**
 * SAML response with a single AWS China role ARN.
 */

const SAML_SESSION_BASIC_CN = 'saml-session-basic-cn';

/**
 * SAML response with a custom session duration parameter.
 */

const SAML_SESSION_BASIC_WITH_SESSION_DURATION = 'saml-session-basic-with-session-duration';

/**
 * SAML response with multiple roles.
 */

const SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES = 'saml-session-basic-with-multiple-roles';

/**
 * Test helpers.
 */

async function getResponseFromAssertion(assertion) {
  return {
    SAMLResponse: assertion
  };
}

async function getSampleAssertion(name) {
  return Buffer.from(await readFile(`fixtures/${name}.xml`, 'utf-8'), 'ascii').toString('base64')
}

/**
 * Exports.
 */

export {
  SAML_SESSION_BASIC,
  SAML_SESSION_BASIC_GOV_CLOUD_US,
  SAML_SESSION_BASIC_CN,
  SAML_SESSION_BASIC_WITH_SESSION_DURATION,
  SAML_SESSION_BASIC_WITH_MULTIPLE_ROLES,
  getResponseFromAssertion,
  getSampleAssertion
};
