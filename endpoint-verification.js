import { promises } from 'fs';
import { compare, coerce } from 'semver';
import { join } from 'path';

export class EndpointVerification {
  constructor(logger) {
    this.logger = logger;
  }

  async huntForExtension() {
    let extensionsDirectory = join(
      process.env.HOME,
      'Library/Application Support/Google/Chrome/Default/Extensions'
    );
    let extensionIdentifier = 'callobklhcbilhphinckomhgkigmfocg';
    let endpointVerificationExtensionDirectory = join(
      extensionsDirectory,
      extensionIdentifier
    );

    try {
      const files = await promises.readdir(
        endpointVerificationExtensionDirectory
      );

      if (files && files.length > 0) {
        let latestExtensionVersion = files.toSorted((x, y) => {
          return compare(coerce(y), coerce(x));
        })[0];

        this.logger.debug('ENDPOINT VERIFICATION ENABLED');
        this.logger.debug(
          `Found Endpoint Verification Extension version installed: ${latestExtensionVersion}`
        );

        return join(
          endpointVerificationExtensionDirectory,
          latestExtensionVersion
        );
      } else {
        return null;
      }
    } catch (error) {
      this.logger.error('WARNING');
      this.logger.error(
        `Endpoint verification requested but plugin not found at ${endpointVerificationExtensionDirectory}`
      );
      this.logger.error(
        'Please make sure you have installed the Google Endpoint Verification Chrome Extension at: https://chrome.google.com/webstore/detail/endpoint-verification/callobklhcbilhphinckomhgkigmfocg?hl=en'
      );

      return null;
    }
  }
}
