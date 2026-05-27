# OSINT

OSINT is an AWS CDK project that deploys an invite-only, Cognito-protected domain monitoring app.

Users sign in with Cognito, manage watchlist domains, and receive digest emails when matching OSINT feeds are found.

## What You Get

- Secure web app at `https://osint.4n6ir.com`
- Cognito hosted login with OAuth code flow
- Watchlist management for domain monitoring
- Feed ingestion, normalization, compilation, and SQLite search
- Digest alerts delivered by email

## Quick Start

### Prerequisites

- Linux or macOS shell environment
- Python 3.11+ (Lambda target is Python 3.13)
- Node.js and AWS CDK CLI (`cdk`)
- AWS credentials with permission to bootstrap and deploy

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
npm install -g aws-cdk
```

### Configure

Most deployment settings live in `config.py`. Before deploying to a new environment, review the domain, region, qualifier, package bucket, and Cognito/email defaults.

### Deploy

```bash
export CDK_DEFAULT_ACCOUNT=<aws-account-id>
export CDK_DEFAULT_REGION=us-east-2

cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/us-east-1 --qualifier lukach
cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/us-east-2 --qualifier lukach
cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/us-west-2 --qualifier lukach

cdk synth
cdk deploy --all
```

To remove the stacks:

```bash
cdk destroy --all
```

### Test

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Project Layout

- `app.py`: CDK app entry point.
- `config.py`: Shared deployment configuration.
- `osint/`: CDK stack definitions.
- `domains/`: Source-specific feed handlers.
- `action/`, `auth/`, `compile/`, `create/`, `daily/`, `digest/`, `download/`, `home/`, `insert/`, `root/`, `search/`, `sqlite/`, `tld/`, `unzip/`, `ses_email/`: Runtime Lambda code.
- `tests/`: Unit and integration tests.

## Stack Overview

- `OsintDns`: Route53 hosted zone and ACM/DNS setup.
- `OsintLayers`: Shared Lambda layers.
- `OsintIdp`: Cognito auth and login flow.
- `OsintHome`: Authenticated home UI.
- `OsintApi`: HTTP API, custom domain, routes, authorizer.
- `OsintDb`: DynamoDB tables.
- `OsintS3`: S3 buckets, SQS queues, and notifications.
- `OsintDownload`, `OsintUnzip`, `OsintCompile`, `OsintSqlite`, `OsintInsert`, `OsintSearch`, `OsintCreate`, `OsintDaily`, `OsintDigest`, `OsintTld`: Feed collection, processing, search, and digest pipelines.
- `OsintOidc`: GitHub OIDC federation for CI/CD.

## Supported Feeds

The project currently ingests these sources:

- c2intelfeeds, certpl, disposableemails, inversiondnsbl, oisd, openphish, phishingarmy, phishtank, threatfox, threatview, ultimatehosts, urlhaus
- 1hosts, hagezi, shadowwhisperer, stevenblack
- `domainsmonitor` is subscription-based.
- Some feeds may be retired over time.

For implementation details, see the source handlers in `domains/` and the stack definitions in `osint/domains/`.

## Domains

This section is kept for attribution of the OSINT lists used by the project.

| id | name | url |
| :-: | :---- | :-- |
| A | c2intelfeeds | [https://github.com/drb-ra/C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) |
| B | certpl | [https://cert.pl](https://cert.pl) |
| C | disposableemails | [https://github.com/disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) |
| D | inversiondnsbl | [https://github.com/elliotwutingfeng/Inversion-DNSBL-Blocklists](https://github.com/elliotwutingfeng/Inversion-DNSBL-Blocklists) |
| E | oisd | [https://oisd.nl](https://oisd.nl) |
| F | openphish | [https://openphish.com](https://openphish.com) |
| G | phishingarmy | [https://phishing.army](https://phishing.army) |
| H | phishtank | [https://phishtank.com](https://phishtank.com) |
| I | threatfox | [https://threatfox.abuse.ch](https://threatfox.abuse.ch) |
| J | threatview | [https://threatview.io](https://threatview.io) |
| K | ultimatehosts | [https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist](https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist) |
| L | urlhaus | [https://urlhaus.abuse.ch](https://urlhaus.abuse.ch) |
| M | domainsmonitor **$** | [https://domains-monitor.com](https://domains-monitor.com) |
| N | 1hosts | [https://github.com/badmojr/1Hosts](https://github.com/badmojr/1Hosts) |
| O | hagezi | [https://github.com/hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) |
| P | shadowwhisperer | [https://github.com/ShadowWhisperer/BlockLists](https://github.com/ShadowWhisperer/BlockLists) |
| Q | stevenblack | [https://github.com/StevenBlack/hosts](https://github.com/StevenBlack/hosts) |

**$** subscription  
**+** retired feed
