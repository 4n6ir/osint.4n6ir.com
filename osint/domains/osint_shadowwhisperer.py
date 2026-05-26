from aws_cdk import (
    Duration,
    Size,
    Stack,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_s3 as _s3,
    aws_ssm as _ssm,
)

from constructs import Construct
from config import Config


class OsintShadowWhisperer(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        layer = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'layer',
            parameter_name=Config.REQUESTS_LAYER_PARAM
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self, 'requests',
            layer_version_arn=layer.string_value
        )

        domains_bucket_name = f'osint-domains-{region}-{account}'

        domains_bucket = _s3.Bucket.from_bucket_name(
            self,
            'domainsbucket',
            bucket_name=domains_bucket_name,
        )

        role = _iam.Role(
            self,
            'role',
            assumed_by=_iam.ServicePrincipal('lambda.amazonaws.com'),
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole',
            )
        )

        domains_bucket.grant_put(role)

        shadowwhisperer = _lambda.Function(
            self,
            'shadowwhisperer',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('domains/shadowwhisperer'),
            handler='shadowwhisperer.handler',
            environment=dict(
                S3_DOMAINS_BUCKET=domains_bucket_name,
                GITHUB_URL=Config.GITHUB_URL,
            ),
            timeout=Duration.seconds(900),
            memory_size=512,
            role=role,
            layers=[
                requests,
            ],
        )

        _logs.LogGroup(
            self,
            'logs',
            log_group_name='/aws/lambda/' + shadowwhisperer.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
        )

        event = _events.Rule(
            self,
            'event',
            schedule=_events.Schedule.cron(
                minute='0',
                hour='*',
                month='*',
                week_day='*',
                year='*',
            ),
        )

        event.add_target(_targets.LambdaFunction(shadowwhisperer))
