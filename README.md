<p align="center">
    <img src="images/logo/cover.png" height="96">
  <p align="center">AWS STS credentials via Google Workspace</p>
</p>

`gsts` (short for `Google STS`) is an AWS CLI credential provider based on browser automation to seamlessly obtain and store AWS STS credentials to interact with Amazon services via Google Workspace SAML federation.

This allows you to configure AWS to rely on Google Workspace as your Identity Provider, moving the responsibility away from Amazon into Google to validate your login credentials (federated identity). This is a wildly popular solution when looking to offer Single-Sign On capabilities inside organizations.

Instead of having to go through a flow tailored for the web browser, this tool enables developer productivity by keeping everything on the command line.

#### Features:

* Seamless integration with the `aws` cli tool for secure, continuous and non-interactive STS session renewals.
* Only once headful design for interactively entering your Google Workspace credentials.
* Full support for all 2FA methods as provided by Google, including Security Keys (Yubikeys, etc.).
* Persistent headless re-authentication system.
* Offers a quick action to open the AWS console from the command-line.
* Support for AWS China (`aws-cn`) and AWS GovCloud (US) (`aws-us-gov`) ARNs.
* Compatible with Amazon ECR and EKS.

## Installation

### macOS

```shell
brew tap ruimarinho/tap
brew install gsts
```

### nix flakes

```shell
nix shell github:ruimarinho/gsts
```

### Other Platforms

Install the package via `npm`:

```sh
npm install --global gsts
```

or via `yarn`:

```
yarn global add gsts
```

## Usage

`gsts` is optimized to run as a [credential source](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) provider for the `aws` cli. This ensures a seamless, automated and secure way of obtaining fresh session tokens without any kind of system interaction.

There are three key options or variables you need know about (you can read more about how to discover them below):

1. Google's Identity Provider ID, or IdP ID (`--idp-id`).
1. Google's Service Provider ID, or SP ID (`--sp-id`).
2. The AWS ARN role(s) to authenticate with.

Assuming the following scenario:

1. You're using the `default` AWS profile name.
2. You're using the default `~/.aws/config` for configuring the `aws` cli.
3. The AWS ARN role you're trying to authenticate with is `arn:aws:iam::123456789012:role/role-name` and it's the only role you have access to.

You would then proceed to add the following `credential_process` entry to your `~/.aws/config` file under the `[default]` profile section:

```sh
[default]
credential_process = gsts --idp-id=<your_idp_id> --sp-id=<your_sp_id>
```

The

**Note**: if you are using a custom profile name other than `default` (for example, `sts`), then your configuration would slightly differ (notice the change to the `[profile <name>]` format):

```sh
[profile sts]
credential_process = gsts --idp-id=<your_idp_id> --sp-id=<your_sp_id>
```

If your user has access to more than one AWS ARN role, you may specify which one to use on each profile by defining `--aws-role-arn`:

```sh
[default]
credential_process = gsts --idp-id=<your_idp_id> --sp-id=<your_sp_id> --aws-role-arn=arn:aws:iam::111111112222222:role/role-name
```

You can then call any `aws` cli command and `gsts` will be spawned automatically:

```sh
aws sts get-caller-identity
```

That's it! With this setup, you're not supposed to call `gsts` manually ever. The first authentication will be performed directly on a headful browser where all of the authentication challenges generated by Google are natively supported (TOTP, Push, SMS, Security Keys, etc). Subsequent runs use an existing session to obtain fresh STS credentials every time it is executed.

### In-memory (Cacheless) Credentials

For increased security, `gsts` supports passing over credentials to the `aws` cli without ever storing a copy of the credentials locally on its own cache dir via `--no-credentials-cache`.

The only downside is that every `aws` command will require re-authentication via `gsts`, which in some scenarios could generate too many authentication requests.

### Configuration Settings Precedence

To avoid redundancy and potentially inconsistent configuration, such as having `gsts` obtain credentials for a different region than the one specified on the AWS profile settings, there are a few special `aws` cli environment variables that are automatically processed if defined.

The `gsts` configuration settings take precedence in the following order:

1. `gsts` command line arguments.
2. `gsts` environment variables (`GSTS_*`).
3. `aws` cli configuration settings, [in the same order processed by the the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence):
   1. `aws` cli environment variables
   2. `aws` cli configuration file (i.e. those in `~/.aws/config`)

#### AWS CLI Supported Environment Variables

Environment variables supported by `aws` cli and processed by `gsts`:

* `AWS_CONFIG_FILE`: if defined, this environment variable overrides the behavior of `gsts` to read the config file from its default path at `~/.aws/config`.

* `AWS_PROFILE`: if defined, this environment variable overrides the behavior of using the profile named `[default]` in the configuration and credentials files. You can override this environment variable by using the `GSTS_AWS_PROFILE` environment variable or the `--aws-profile` command line parameter.

* `AWS_DEFAULT_REGION`: if defined, this environment variable overrides the value for the profile setting region. You can override this environment variable by using the `GSTS_AWS_REGION` environment variable or the `--aws-region` command line parameter.

* `AWS_REGION`: if defined, this environment variable overrides the values in the environment variable `AWS_DEFAULT_REGION`
and the profile setting region. You can override this environment variable by using the `GSTS_AWS_REGION` environment variable or the `--aws-region` command line parameter.

#### AWS CLI Supported Profile Configuration Settings

Profile configuration settings supported by `aws` cli and processed by `gsts`:

* `duration_seconds`: the duration, in seconds, of the role session. You can override this profile configuration setting by using the `GSTS_AWS_SESSION_DURATION` environment variable or the `--aws-session-duration` command line parameter.

* `region`: You can override this profile configuration setting by using the `GSTS_AWS_REGION`, `AWS_REGION` or `AWS_DEFAULT_REGION` environment variables as explained above or the `--aws-region` command line parameter.

Notably, `output` is not supported since it could break `gsts` support for `credential_process` if its value is not `json` and setting `role_arn` makes the `aws` cli incompatible with `credential_process`.

## Amazon ECR

If you'd like to automatically authenticate your Docker installation before pulling private images from Amazon ECR, you can use the fantastic [ECR Docker Credential Helper](https://github.com/awslabs/amazon-ecr-credential-helper) in combination with `gsts`.

1. Install `docker-credential-helper-ecr` (on macOS, you can do it via Homebrew using `brew install docker-credential-helper-ecr`).
2. Add the following config to your `~/.docker/config.json` file:

    ```json
    {
      "credHelpers" : {
        "<ACCOUNT_ID>.dkr.ecr.<ECR_REGION>.amazonaws.com" : "ecr-login"
      }
    }
    ```

The config entry `ecr-login` maps to the binary `docker-credential-ecr-login` which must be available under your `$PATH`.

The next step a `docker pull` for an image from an ECR registry matching the string above is called, Docker will invisibly call `gsts` and perform authentication on your behalf.

## Amazon EKS

If you'd like to automatically authenticate your Kubernetes authentication via Amazon EKS, add the following `exec` config under the `users` property of your `~/.kube/config` file:.

```yaml
apiVersion: v1
clusters:
  - [...]
kind: Config
preferences: {}
users:
- name: arn:aws:eks:us-west-1:111122223333:cluster/my-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      args:
      - eks
      - get-token
      - --region
      - eu-west-1
      - --cluster-name
      - my-cluster
      command: aws
      env:
      - name: AWS_PROFILE
        value: default
      interactiveMode: Never
      provideClusterInfo: false
```

In this particularly case, the `AWS_PROFILE` env setting isn't strictly necessary as the default value would be used.

## Quick Actions

`gsts` offer a quick way to open the Amazon AWS console via the command line:

```sh
gsts console
```

## Reference

```sh
❯ gsts --help

Commands:
  gsts console  Authenticate via SAML and open Amazon AWS console in the default browser

Options:
      --help                               Show help                                                                                         [boolean]
      --version                            Show version number                                                                               [boolean]
      --aws-profile                        AWS profile name to associate credentials with                                                   [required]
      --aws-role-arn                       AWS role ARN to authenticate with
      --aws-session-duration               AWS session duration in seconds (defaults to the value provided by the IDP, if set)                [number]
      --aws-region                         AWS region to send requests to                                                                   [required]
      --cache-dir                          Where to store cached data                                               [default: "~/Library/Caches/gsts"]
      --clean                              Start authorization from a clean session state                                                    [boolean]
      --force                              Force re-authorization even with valid session                                   [boolean] [default: false]
      --idp-id                             Identity Provider ID (IdP ID)                                                                    [required]
      --no-credentials-cache               Disable default behaviour of storing credentials in --cache-dir                                   [boolean]
  -o, --output                             Output format                                                                     [choices: "json", "none"]
      --playwright-engine                  Set playwright browser engine              [choices: "chromium", "firefox", "webkit"] [default: "chromium"]
      --playwright-engine-executable-path  Set playwright executable path for browser engine
      --playwright-engine-channel          Set playwright browser engine channel       [choices: "chrome", "chrome-beta", "msedge-beta", "msedge-dev"]
      --sp-id                              Service Provider ID (SP ID)                                                             [string] [required]
      --username                           Username to auto pre-fill during login
  -v, --verbose                            Log verbose output                                                                                  [count]
```

## Discovery of IdP and SP IDs

If you're the admin of Google Workspace, after configuring the SAML application for AWS you can extract the SP ID by looking at the `service` parameter of the SAML AWS application page.

<img src="images/google-workspace-sp-id.png" width="800px">

The IDP ID can be found under _Security > Set up single sign-on (SSO) for SAML applications_ as the parameter `idpid`.

<img src="images/google-workspace-idp-id.png" width="800px">

In case you are using a pre-configured AWS SAML application as traditionally available under the dotted menu on any Google app (Gmail, Calendar and so on) you can instead right-click the AWS icon and copy the link:

<img src="images/google-workspace-aws-app.png" width="300px">

The copied URL will be in the format of `https://accounts.google.com/o/saml2/initsso?idpid=<IDP_ID>&spid=<SP_ID>&forceauthn=false`.

## Troubleshooting

**gsts conflicts with an alias from oh-my-zsh's git plugin**

[ohmyzsh's git plugin](https://github.com/ohmyzsh/ohmyzsh/tree/master/plugins/git) includes an alias named `gsts` as a shorthand for `git stash show --text`. You can either disable the `git` plugin entirely or, alternatively, add `unalias gsts` at the end of your dotfiles if you don't use this git command often.

**"Error when retrieving credentials from custom-process: Error: Failed to launch the browser process!" when using the aws-cli with credential_process**

Although seamingly unrelated to `gsts`, try unsetting `LD_LIBRARY_PATH` before calling it, like so:

```bash
credential_process = bash -c "unset LD_LIBRARY_PATH; gsts --aws-role-arn arn:aws:iam::123456789012:role/role-name --sp-id 12345 --idp-id A12bc34d5"
```

## License

MIT
