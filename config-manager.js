
/**
 * Module dependencies.
 */

import { camalize } from './utils.js'
import config from '@smithy/shared-ini-file-loader';

/**
 * Process config using the following order:
 *
 * 1. `gsts` command line arguments.
 * 2. `gsts` environment variables (`GSTS_*`).
 * 3. `aws` cli configuration settings, [in the same order processed by the the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence):
 *   1. `aws` cli environment variables
 *   2. `aws` cli configuration file (i.e. those in `~/.aws/config`)
 */

export async function processConfig(cliParameters, argv, env, isTTY) {
  // Load the AWS config file taking into consideration the `$AWS_CONFIG_FILE` environment
  // variable as supported by the `aws` cli.
  const awsConfig = await config.loadSharedConfigFiles();

  // If defined, `$AWS_REGION` overrides the values in the environment variable
  // `$AWS_DEFAULT_REGION` and the profile setting region. You can override `$AWS_REGION`
  // by using the `--aws-region` command line parameter.
  argv.awsRegion = argv['aws-region'] = argv['aws-region'] || env.AWS_REGION || env.AWS_DEFAULT_REGION;

  // If defined, `$AWS_PROFILE` overrides the behavior of using the profile named [default] in
  // the `aws` cli configuration file. You can override this environment variable by using the
  // `--aws-profile` command line parameter.
  argv.awsProfile = argv['aws-profile'] = argv['aws-profile'] || env.AWS_PROFILE || 'default';

  for (let parameterKey in cliParameters) {
    // Test if this specific command line parameter is supported via the `aws` cli profile configuration.
    if (!cliParameters[parameterKey]?.awsConfigKey) {
      continue;
    }

    // If supported, and this specific command line parameter has not been set previously by `aws` cli-supported
    // environement variables, proceed with parsing values from the `aws` cli configuration file.
    // Some `gsts` parameters offer default values, so we need to allow customizing those as well.
    if (argv[parameterKey] === undefined || argv[parameterKey] === cliParameters[parameterKey].default) {
      // Read value from `aws` cli profile configuration settings.
      const value = awsConfig.configFile[argv.awsProfile]?.[cliParameters[parameterKey].awsConfigKey];
      // Get expected value type.
      const type = cliParameters[parameterKey]?.type;
      // Coerce into expected value type.
      switch (type) {
        case 'number':
          argv[parameterKey] = Number(value);
          break;
        case 'boolean':
          argv[parameterKey] = Boolean(value);
          break;
        default:
          argv[parameterKey] = value;
          break;
      }

      // Normalize into yargs structure.
      argv[parameterKey] = argv[camalize(parameterKey)];
    }
  }

  // Automatically enable json output format if `gsts` is not inside an
  // interactive shell to enable compatibility with third-party tools
  // like the `aws` cli.
  if (argv.output == undefined && !isTTY) {
    argv.output = 'json';
  }

  return argv;
};
