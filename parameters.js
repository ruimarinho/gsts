// Define all available cli options.
export function generateCliParameters(paths) {
  return {
    'aws-profile': {
      description: 'AWS profile name to associate credentials with',
      required: true
    },
    'aws-role-arn': {
      description: 'AWS role ARN to authenticate with',
      awsConfigKey: 'gsts.role_arn'
    },
    'aws-session-duration': {
      description: `AWS session duration in seconds (defaults to the value provided by the IDP, if set)`,
      type: 'number',
      awsConfigKey: 'duration_seconds'
    },
    'aws-region': {
      description: 'AWS region to send requests to',
      required: true,
      awsConfigKey: 'region',
    },
    'cache-dir': {
      description: 'Where to store cached data',
      default: paths.cache,
      awsConfigKey: 'gsts.cache_dir'
    },
    'clean': {
      type: 'boolean',
      config: false,
      description: 'Start authorization from a clean session state',
      awsConfigKey: 'gsts.clean'
    },
    'credentials-cache': {
      type: 'boolean',
      default: true,
      hidden: true,
    },
    'force': {
      type: 'boolean',
      default: false,
      description: 'Force re-authorization even with valid session',
      awsConfigKey: 'gsts.force',
    },
    'headful': {
      type: 'boolean',
      config: false,
      description: 'headful',
      hidden: true
    },
    'idp-id': {
      description: 'Identity Provider ID (IdP ID)',
      required: true,
      awsConfigKey: 'gsts.idp_id'
    },
    'no-credentials-cache': {
      description: 'Disable default behaviour of storing credentials in --cache-dir',
      type: 'boolean'
    },
    'output': {
      alias: 'o',
      description: `Output format`,
      choices: ['json', 'none']
    },
    'playwright-engine': {
      description: 'Set playwright browser engine',
      choices: ['chromium', 'firefox', 'webkit'],
      default: 'chromium',
      awsConfigKey: 'gsts.playwright_engine'
    },
    'playwright-engine-executable-path': {
      description: 'Set playwright executable path for browser engine',
      awsConfigKey: 'gsts.playwright_engine_executable_path'
    },
    'playwright-engine-channel': {
      description: 'Set playwright browser engine channel',
      choices: ['chrome', 'chrome-beta', 'msedge-beta', 'msedge-dev'],
      awsConfigKey: 'gsts.playwright_engine_channel'
    },
    'sp-id': {
      description: 'Service Provider ID (SP ID)',
      type: 'string',
      required: true,
      awsConfigKey: 'gsts.sp_id'
    },
    'username': {
      description: 'Username to auto pre-fill during login',
      awsConfigKey: 'gsts.username'
    },
    'verbose': {
      description: 'Log verbose output',
      awsConfigKey: 'gsts.verbose',
      type: 'count',
      alias: 'v'
    }
  };
}
