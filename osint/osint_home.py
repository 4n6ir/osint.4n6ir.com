from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_ssm as _ssm
)

from constructs import Construct
from config import Config

class OsintHome(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        table_arns = [
            f'arn:aws:dynamodb:{region}:{account}:table/tld',
            f'arn:aws:dynamodb:{region}:{account}:table/users',
            f'arn:aws:dynamodb:{region}:{account}:table/watchlist',
            f'arn:aws:dynamodb:{region}:{account}:table/subscription',
            f'arn:aws:dynamodb:{region}:{account}:table/osint',
            f'arn:aws:dynamodb:{region}:{account}:table/malware',
            f'arn:aws:dynamodb:{region}:{account}:table/dailyremove',
            f'arn:aws:dynamodb:{region}:{account}:table/dailyupdate',
            f'arn:aws:dynamodb:{region}:{account}:table/weeklyremove',
            f'arn:aws:dynamodb:{region}:{account}:table/weeklyupdate',
            f'arn:aws:dynamodb:{region}:{account}:table/monthlyremove',
            f'arn:aws:dynamodb:{region}:{account}:table/monthlyupdate',
        ]

        # Requests layer
        layer = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'layer',
            parameter_name = Config.REQUESTS_LAYER_PARAM
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self, 'requests',
            layer_version_arn = layer.string_value
        )

        # IAM Role
        role = _iam.Role(
            self, 'role',
            assumed_by = _iam.ServicePrincipal(
                'lambda.amazonaws.com'
            )
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'dynamodb:GetItem',
                    'dynamodb:PutItem',
                    'dynamodb:DeleteItem',
                    'dynamodb:Query'
                ],
                resources = table_arns
            )
        )

        # Home Lambda Function
        home = _lambda.Function(
            self, 'home',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('home'),
            handler = 'home.handler',
            environment = dict(
                API_ENDPOINT = f"https://{Config.API_DOMAIN}/home",
                LOGOUT_ENDPOINT = f"https://{Config.API_DOMAIN}/auth?action=logout",
                USER_INFO_ENDPOINT = f"https://{Config.SUBDOMAIN}/oauth2/userInfo",
                OSINT_TABLE = 'osint',
                WM_OSINT = 'osint',
                WM_MALWARE = 'malware',
                WM_DAILYUPDATE = 'dailyupdate',
                WM_DAILYREMOVE = 'dailyremove',
                WM_WEEKLYUPDATE = 'weeklyupdate',
                WM_WEEKLYREMOVE = 'weeklyremove',
                WM_MONTHLY = 'monthlyupdate',
                WM_MONTHLYUPDATE = 'monthlyupdate',
                WM_MONTHLYREMOVE = 'monthlyremove',
            ),
            timeout = Duration.seconds(30),
            memory_size = 256,
            role = role,
            layers = [
                requests
            ]
        )

        self.homelogs = _logs.LogGroup(
            self, 'homelogs',
            log_group_name = '/aws/lambda/' + home.function_name,
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        # Export lambda for API stack attachment
        self.home = home
