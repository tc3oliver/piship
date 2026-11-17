# Security policy

## Supported versions

PiShip is pre-release. Security fixes go to `main` and, as a new release, to the latest release (currently v0.13.0, the [production-validation baseline](docs/status.md#v0130-production-validation-baseline)). Earlier releases get no fixes; update to the latest.

## Reporting a vulnerability

Report it privately at <https://github.com/tc3oliver/piship/security/advisories/new> (GitHub's **Security → Advisories → Report a vulnerability** flow). Do not open a public Issue for a suspected vulnerability. See [maintainer setup](docs/maintainers/github.md) for repository security settings.

## What must not be posted publicly

Never include API keys, OIDC tokens, gateway credentials, company secrets, proprietary source code, or sensitive logs in Issues, Discussions, or pull requests. Share only a sanitized reproduction through the private reporting channel.

## Security scope

Reports involving manifest or lock integrity, Pi integration, extension execution, credentials, distribution isolation, or the build and release chain are in scope. Current controls and limitations are described in [security architecture](docs/security.md).

## Disclosure process

Maintainers will acknowledge a private report, assess impact, coordinate a fix and regression test, and publish an advisory after a remedy is available. Timing depends on severity and available maintainers. Please allow coordinated disclosure before making details public.
