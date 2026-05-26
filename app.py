#!/usr/bin/env python3
import importlib
import os

import aws_cdk as cdk

from config import Config
from osint.osint_compile import OsintCompile
from osint.domains.osint_c2intelfeeds import OsintC2IntelFeeds
from osint.domains.osint_certpl import OsintCertPl
from osint.osint_db import OsintDb
from osint.osint_dns import OsintDns
from osint.domains.osint_disposableemails import OsintDisposableEmails
from osint.osint_download import OsintDownload
from osint.osint_idp import OsintIdp
from osint.domains.osint_inversiondnsbl import OsintInversionDnsbl
from osint.domains.osint_hagezi import OsintHagezi
from osint.domains.osint_onehosts import OsintOneHosts
from osint.domains.osint_oisd import OsintOisd
from osint.domains.osint_openphish import OsintOpenPhish
from osint.osint_oidc import OsintOidc
from osint.osint_layers import OsintLayers
from osint.domains.osint_phishingarmy import OsintPhishingArmy
from osint.domains.osint_phishtank import OsintPhishTank
from osint.osint_s3 import OsintS3
from osint.domains.osint_shadowwhisperer import OsintShadowWhisperer
from osint.osint_sqlite import OsintSqlite
from osint.osint_tld import OsintTld
from osint.osint_unzip import OsintUnzip
from osint.domains.osint_stevenblack import OsintStevenBlack
from osint.domains.osint_threatfox import OsintThreatFox
from osint.domains.osint_threatview import OsintThreatView
from osint.domains.osint_ultimatehosts import OsintUltimateHosts
from osint.domains.osint_urlhaus import OsintUrlHaus
from osint.osint_home import OsintHome
from osint.osint_api import OsintApi
from osint.osint_search import OsintSearch
from osint.osint_insert import OsintInsert
from osint.osint_create import OsintCreate
from osint.osint_daily import OsintDaily

OsintDigest = importlib.import_module('osint.osint_digest').OsintDigest

app = cdk.App()

dns_stack = OsintDns(
    app, 'OsintDns',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.DNS_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    ),
    cross_region_references = True
)

layers_stack = OsintLayers(
    app, 'OsintLayers',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

idp_stack = OsintIdp(
    app, 'OsintIdp',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)
idp_stack.add_dependency(layers_stack)
idp_stack.add_dependency(dns_stack)

home_stack = OsintHome(
    app, 'OsintHome',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)
home_stack.add_dependency(layers_stack)

api_stack = OsintApi(
    app, 'OsintApi',
    dns_stack = dns_stack,
    auth_lambda = idp_stack.auth,
    home_lambda = home_stack.home,
    root_lambda = idp_stack.root,
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    ),
    cross_region_references = True
)
api_stack.add_dependency(idp_stack)
api_stack.add_dependency(home_stack)
api_stack.add_dependency(dns_stack)

db_stack = OsintDb(
    app, 'OsintDb',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

insert_stack = OsintInsert(
    app, 'OsintInsert',
    watchlist_table = db_stack.watchlist,
    state_table = db_stack.state,
    subscription_table = db_stack.subscription,
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

insert_stack.add_dependency(db_stack)

tld_stack = OsintTld(
    app, 'OsintTld',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

tld_stack.add_dependency(layers_stack)
tld_stack.add_dependency(db_stack)

s3_stack = OsintS3(
    app, 'OsintS3',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

sqlite_stack = OsintSqlite(
    app, 'OsintSqlite',
    download_queue = s3_stack.download_queue,
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

search_stack = OsintSearch(
    app, 'OsintSearch',
    search_queue = insert_stack.search_queue,
    watchlist_table = db_stack.watchlist,
    osint_table = db_stack.osint,
    users_table = db_stack.users,
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

search_stack.add_dependency(s3_stack)
search_stack.add_dependency(insert_stack)

unzip_stack = OsintUnzip(
    app, 'OsintUnzip',
    zipped_queue = s3_stack.zipped_queue,
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

unzip_stack.add_dependency(s3_stack)

download_stack = OsintDownload(
    app, 'OsintDownload',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

download_stack.add_dependency(layers_stack)
download_stack.add_dependency(s3_stack)

daily_stack = OsintDaily(
    app, 'OsintDaily',
    search_queue = insert_stack.search_queue,
    users_table = db_stack.users,
    watchlist_table = db_stack.watchlist,
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

daily_stack.add_dependency(s3_stack)
daily_stack.add_dependency(db_stack)
daily_stack.add_dependency(insert_stack)

create_stack = OsintCreate(
    app, 'OsintCreate',
    create_queue = s3_stack.create_queue,
    search_queue = insert_stack.search_queue,
    users_table = db_stack.users,
    watchlist_table = db_stack.watchlist,
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

create_stack.add_dependency(s3_stack)
create_stack.add_dependency(db_stack)
create_stack.add_dependency(insert_stack)

digest_stack = OsintDigest(
    app, 'OsintDigest',
    dailyremove_table=db_stack.dailyremove,
    dailyupdate_table=db_stack.dailyupdate,
    digest_table=db_stack.digest,
    malware_table=db_stack.malware,
    osint_table=db_stack.osint,
    env=cdk.Environment(
        account=os.getenv('CDK_DEFAULT_ACCOUNT'),
        region=Config.IDP_REGION
    ),
    synthesizer=cdk.DefaultStackSynthesizer(
        qualifier=Config.CDK_QUALIFIER
    )
)

digest_stack.add_dependency(db_stack)

compile_stack = OsintCompile(
    app, 'OsintCompile',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

compile_stack.add_dependency(s3_stack)

c2intelfeeds_stack = OsintC2IntelFeeds(
    app, 'OsintC2IntelFeeds',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

c2intelfeeds_stack.add_dependency(layers_stack)
c2intelfeeds_stack.add_dependency(s3_stack)

certpl_stack = OsintCertPl(
    app, 'OsintCertPl',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

certpl_stack.add_dependency(layers_stack)
certpl_stack.add_dependency(s3_stack)

disposableemails_stack = OsintDisposableEmails(
    app, 'OsintDisposableEmails',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

disposableemails_stack.add_dependency(layers_stack)
disposableemails_stack.add_dependency(s3_stack)

inversiondnsbl_stack = OsintInversionDnsbl(
    app, 'OsintInversionDnsbl',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

inversiondnsbl_stack.add_dependency(layers_stack)
inversiondnsbl_stack.add_dependency(s3_stack)

onehosts_stack = OsintOneHosts(
    app, 'OsintOneHosts',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

onehosts_stack.add_dependency(layers_stack)
onehosts_stack.add_dependency(s3_stack)

hagezi_stack = OsintHagezi(
    app, 'OsintHagezi',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

hagezi_stack.add_dependency(layers_stack)
hagezi_stack.add_dependency(s3_stack)

oisd_stack = OsintOisd(
    app, 'OsintOisd',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

oisd_stack.add_dependency(layers_stack)
oisd_stack.add_dependency(s3_stack)

openphish_stack = OsintOpenPhish(
    app, 'OsintOpenPhish',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

openphish_stack.add_dependency(layers_stack)
openphish_stack.add_dependency(s3_stack)

phishingarmy_stack = OsintPhishingArmy(
    app, 'OsintPhishingArmy',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

phishingarmy_stack.add_dependency(layers_stack)
phishingarmy_stack.add_dependency(s3_stack)

phishtank_stack = OsintPhishTank(
    app, 'OsintPhishTank',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

phishtank_stack.add_dependency(layers_stack)
phishtank_stack.add_dependency(s3_stack)

threatfox_stack = OsintThreatFox(
    app, 'OsintThreatFox',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

threatfox_stack.add_dependency(layers_stack)
threatfox_stack.add_dependency(s3_stack)

threatview_stack = OsintThreatView(
    app, 'OsintThreatView',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

threatview_stack.add_dependency(layers_stack)
threatview_stack.add_dependency(s3_stack)

ultimatehosts_stack = OsintUltimateHosts(
    app, 'OsintUltimateHosts',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

ultimatehosts_stack.add_dependency(layers_stack)
ultimatehosts_stack.add_dependency(s3_stack)

urlhaus_stack = OsintUrlHaus(
    app, 'OsintUrlHaus',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

urlhaus_stack.add_dependency(layers_stack)
urlhaus_stack.add_dependency(s3_stack)

shadowwhisperer_stack = OsintShadowWhisperer(
    app, 'OsintShadowWhisperer',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

shadowwhisperer_stack.add_dependency(layers_stack)
shadowwhisperer_stack.add_dependency(s3_stack)

stevenblack_stack = OsintStevenBlack(
    app, 'OsintStevenBlack',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.IDP_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

stevenblack_stack.add_dependency(layers_stack)
stevenblack_stack.add_dependency(s3_stack)

OsintOidc(
    app, 'OsintOidc',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = Config.OIDC_REGION
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = Config.CDK_QUALIFIER
    )
)

cdk.Tags.of(app).add('Alias', Config.ALIAS)
cdk.Tags.of(app).add('GitHub', Config.GITHUB_URL)
cdk.Tags.of(app).add('Org', Config.ORGANIZATION)

app.synth()