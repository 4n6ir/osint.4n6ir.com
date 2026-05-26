from aws_cdk import (
    Duration,
    RemovalPolicy,
    SecretValue,
    Size,
    Stack,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_s3 as _s3,
    aws_secretsmanager as _secrets,
    aws_ssm as _ssm
)

from constructs import Construct
from config import Config

class OsintDownload(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        layer = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'layer',
            parameter_name = Config.REQUESTS_LAYER_PARAM
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self, 'requests',
            layer_version_arn = layer.string_value
        )

        download_bucket_name = f'osint-download-{region}-{account}'
        zipped_bucket_name = f'osint-zipped-{region}-{account}'

        download_bucket = _s3.Bucket.from_bucket_name(
            self, 'downloadbucket',
            bucket_name = download_bucket_name
        )

        zipped_bucket = _s3.Bucket.from_bucket_name(
            self, 'zippedbucket',
            bucket_name = zipped_bucket_name
        )

    ### SECRET MANAGER ###

        secret = _secrets.Secret(
            self, 'secret',
            secret_name = 'domainsmonitor',
            secret_object_value = {
                "token": SecretValue.unsafe_plain_text("<EMPTY>")
            }
        )

    ### IAM ROLE ###

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

        download_bucket.grant_put(role)
        zipped_bucket.grant_put(role)

        secret.grant_read(role)

    ### LAMBDA FUNCTION ###

        download = _lambda.Function(
            self, 'download',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('download'),
            handler = 'download.handler',
            environment = dict(
                S3_BUCKET_NAME = download_bucket_name,
                S3_ZIPPED_BUCKET_NAME = zipped_bucket_name,
                SECRET_MGR_ARN = secret.secret_arn,
                GITHUB_URL = Config.GITHUB_URL
            ),
            timeout = Duration.seconds(900),
            memory_size = 1024,
            role = role,
            layers = [
                requests
            ]
        )

        _logs.LogGroup(
            self, 'logs',
            log_group_name = '/aws/lambda/'+download.function_name,
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        event = _events.Rule(
            self, 'event',
            schedule = _events.Schedule.cron(
                minute = '0',
                hour = '1',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )

        event.add_target(
            _targets.LambdaFunction(download)
        )