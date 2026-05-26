from aws_cdk import (
    Duration,
    RemovalPolicy,
    Size,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_ssm as _ssm,
)

from constructs import Construct
from config import Config


class OsintTld(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        layer = _ssm.StringParameter.from_string_parameter_attributes(
            self,
            'layer',
            parameter_name=Config.REQUESTS_LAYER_PARAM,
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self,
            'requests',
            layer_version_arn=layer.string_value,
        )

        table = _dynamodb.TableV2.from_table_name(
            self,
            'table',
            table_name='tld',
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

        role.add_to_policy(
            _iam.PolicyStatement(
                actions=[
                    'dynamodb:Query',
                    'dynamodb:PutItem',
                    'dynamodb:DeleteItem',
                ],
                resources=[
                    table.table_arn,
                ],
            )
        )

        tld = _lambda.Function(
            self,
            'tld',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('tld'),
            handler='tld.handler',
            environment=dict(
                TLD_TABLE='tld',
                GITHUB_URL=Config.GITHUB_URL,
            ),
            timeout=Duration.seconds(900),
            memory_size=256,
            role=role,
            layers=[
                requests,
            ],
        )

        _logs.LogGroup(
            self,
            'logs',
            log_group_name='/aws/lambda/' + tld.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        event = _events.Rule(
            self,
            'event',
            schedule=_events.Schedule.cron(
                minute='0',
                hour='10',
                month='*',
                week_day='*',
                year='*',
            ),
        )

        event.add_target(_targets.LambdaFunction(tld))
