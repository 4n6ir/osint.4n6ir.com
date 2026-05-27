from datetime import datetime, timezone


# Central configuration for all OSINT stacks.
# Customize these values for different deployments.
class Config:
    # Organization and naming
    ORGANIZATION = "4n6ir.com"
    ALIAS = "osint"
    GITHUB_OWNER = "4n6ir"
    GITHUB_REPO = "osint.4n6ir.com"
    GITHUB_URL = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}"
    CDN_BASE_URL = "https://cdn.4n6ir.com"

    # CDK Settings
    CDK_QUALIFIER = "lukach"

    # Regions
    DNS_REGION = "us-east-1"
    IDP_REGION = "us-east-2"
    OIDC_REGION = "us-east-2"

    # Domain
    DOMAIN = "osint.4n6ir.com"
    SUBDOMAIN = f"hello.{DOMAIN}"

    # API Gateway Settings (single-region, apex domain)
    API_REGION = IDP_REGION  # us-east-2
    API_DOMAIN = DOMAIN  # osint.4n6ir.com
    API_STAGE_NAME = "prod"
    API_GATEWAY_NAME = f"{ALIAS}-api"

    # S3 Buckets
    PACKAGES_BUCKET = "packages-use2-lukach-io"
    REQUESTS_LAYER_PARAM = "/layer/requests"
    REQUESTS_LAYER_DESCRIPTION = "Requests Layer"

    @staticmethod
    def requests_layer_description() -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"{Config.REQUESTS_LAYER_DESCRIPTION} {timestamp}"

    # Parameter Store paths (stored in DNS_REGION)
    ROUTE53_PARAM = "/route53/osint"
    ACM_PARAM = "/acm/osint"

    # CloudWatch Logs
    ROUTE53_LOGS_GROUP = "/aws/route53/osint"

    # Route53 DNS - Apex and subdomain records
    ROUTE53_APEX_RECORD = DOMAIN  # osint.4n6ir.com
    ROUTE53_COGNITO_RECORD = SUBDOMAIN  # hello.osint.4n6ir.com

    # Cognito Settings
    COGNITO_USER_POOL_NAME = "osint"
    COGNITO_APP_CLIENT_NAME = "osint"
    COGNITO_FROM_EMAIL = "hello@4n6ir.com"
    COGNITO_REDIRECT_URI = f"https://{API_DOMAIN}/auth"
    ACCESS_TOKEN_COOKIE_NAME = "osint_prod_at"
    # True: users can self-register via /auth. False: invite-only (sign-in only).
    AUTH_SELF_SIGN_UP_ENABLED = True
