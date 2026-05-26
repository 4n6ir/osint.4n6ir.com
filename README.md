# OSINT

OSINT is an AWS CDK project that builds an invite-only, Cognito-protected threat intelligence application for domain monitoring.

It ingests domain feeds, normalizes and compiles data, builds SQLite search indexes, matches user watchlists, and sends digest emails.

## What This Project Does

- Hosts a secure web app at `https://osint.4n6ir.com`
- Uses Cognito hosted login with OAuth code flow
- Lets users manage watchlist domains
- Generates typo/permutation candidates and correlates against OSINT feeds
- Stores findings in DynamoDB and SQLite
- Sends periodic digest alerts by email

## High-Level Architecture

1. Ingestion Lambdas pull source lists into S3.
2. Raw feed files are normalized and deduplicated.
3. CSV is converted into SQLite (`osint.sqlite3`) for fast search.
4. S3/DynamoDB events trigger fanout and search jobs through SQS.
5. Search writes matched findings and updates watchlist metadata.
6. Digest pipeline aggregates events and sends SES-backed emails.
7. HTTP API + Lambda renders the user interface and JSON actions.

## API Surface

The HTTP API stack defines these routes:

- `GET /`:
	Landing page and sign-in entry (`root/root.py`).
- `GET /auth`:
	OAuth callback and login/logout transitions (`auth/auth.py`).
- `GET /home`:
	Authenticated HTML app view (`home/home.py`).
- `POST /home`:
	Authenticated JSON actions (domain sections, permutations, CRUD-like actions).

`/home` is protected by a Lambda authorizer that validates the bearer token against Cognito user info.

## Project Layout

- `app.py`: CDK app entry point, stack composition and dependencies.
- `config.py`: Central deployment and naming configuration.
- `osint/`: CDK stack definitions for each subsystem (including source stacks in `osint/domains/`).
- `domains/`: Source-specific runtime feed handlers used by ingestion components.
- Runtime Lambda code directories:
	`action/`, `auth/`, `authorizer/`, `compile/`, `create/`, `daily/`, `digest/`, `download/`, `home/`, `insert/`, `root/`, `search/`, `sqlite/`, `tld/`, `unzip/`, `ses_email/`.
- `tests/`: Unit/integration tests for handlers and CDK stacks.

## CDK Stacks Overview

- `OsintDns`: Route53 hosted zone, DNS query logs, ACM cert + SSM params.
- `OsintLayers`: Publishes shared `requests` Lambda layer ARN to SSM.
- `OsintIdp`: Cognito pool/client/domain, auth and root lambdas, credentials secret.
- `OsintHome`: Home Lambda with DynamoDB read/write permissions.
- `OsintApi`: API Gateway HTTP API, custom domain, routes, authorizer.
- `OsintDb`: DynamoDB tables (`watchlist`, `users`, `osint`, `digest`, and others).
- `OsintS3`: S3 buckets + S3 event notifications + SQS queues.
- `OsintDownload`: Scheduled feed download to S3.
- `OsintUnzip`: SQS-driven zip extraction and partitioned CSV output.
- `OsintCompile`: Hourly dedupe/merge of source files into compiled CSV.
- `OsintSqlite`: Converts CSV uploads into SQLite artifacts.
- `OsintInsert`: DynamoDB stream to SQS fanout on new watchlist entries.
- `OsintSearch`: SQS-driven matching/search worker.
- `OsintCreate`: Triggered when SQLite index is refreshed to enqueue broad rescans.
- `OsintDaily`: Scheduled sponsor-based scan enqueue.
- `OsintDigest`: Aggregation + digest creation + SES email sender.
- `OsintTld`: Scheduled IANA TLD sync into DynamoDB.
- `OsintOidc`: GitHub OIDC federation role for CI/CD access.
- Domain source stacks in `osint/domains/`: Source-specific feed collection components.

## Prerequisites

- Linux or macOS shell environment
- Python 3.11+ (project targets Lambda Python 3.13)
- Node.js and AWS CDK CLI (`cdk`)
- AWS credentials with permissions for CDK bootstrap/deploy

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
npm install -g aws-cdk
```

## Configuration

Most runtime/deployment settings live in `config.py`.

Key values:

- `DOMAIN`, `SUBDOMAIN`, `API_DOMAIN`
- `DNS_REGION`, `IDP_REGION`, `OIDC_REGION`
- `CDK_QUALIFIER` (currently `lukach`)
- `PACKAGES_BUCKET` and layer parameter paths
- Cognito and email defaults

Before deploying to a new environment, review and adjust these settings.

## Bootstrap and Deploy

Export your target account/region context (example):

```bash
export CDK_DEFAULT_ACCOUNT=<aws-account-id>
export CDK_DEFAULT_REGION=us-east-2
```

Bootstrap required regions for the qualifier used by this project:

```bash
cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/us-east-1 --qualifier lukach
cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/us-east-2 --qualifier lukach
cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/us-west-2 --qualifier lukach
```

Synthesize templates:

```bash
cdk synth
```

Deploy everything:

```bash
cdk deploy --all
```

Destroy (careful, this removes non-retained resources):

```bash
cdk destroy --all
```

## Testing

Run unit tests with `unittest` discovery:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

`pytest`-style tests are also present (including optional Playwright integration). If Playwright is missing, related tests are skipped by design.

## Data Flow Details

1. Feed collectors download source content into `osint-download-*` and `osint-zipped-*` buckets.
2. Unzip/normalize workers emit CSV rows in `sld,tld,source` format.
3. Compile worker deduplicates recent source files and writes `osint.csv`.
4. SQLite worker builds `osint.sqlite3` plus metadata/indexes.
5. SQLite refresh triggers create fanout for sponsor groups.
6. Insert and daily jobs enqueue search messages with subscription-aware flags.
7. Search evaluates domains/permutations, writes findings and counters.
8. Action + digest + SES pipeline sends periodic alert summaries.

## Security and Operational Notes

- Cognito client credentials are stored in Secrets Manager.
- API auth uses bearer token validation against Cognito userInfo.
- Buckets are private, encrypted, SSL-enforced, and short-retention.
- DynamoDB tables include TTL where needed for rolling data expiry.
- Logs are created per Lambda/API with one-week retention (Route53 logs longer).

## Known Operational Requirements

- The Lambda `requests` layer artifact (`requests.zip`) must exist in the configured packages bucket.
- SES sending identity for `hello@4n6ir.com` must be verified in the deployment region(s).
- `domainsmonitor` secret must contain a valid API token for subscription feed ingestion.

## Domains

| id | name | url |
| :-: | :---- | :-- |
| A | c2intelfeeds | [https://github.com/drb-ra/C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) |
| B | certpl | [https://cert.pl](https://cert.pl) |
| C. | disposableemails | [https://github.com/disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) |
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
