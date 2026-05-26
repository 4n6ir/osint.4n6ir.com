from aws_cdk import (
    Duration,
    RemovalPolicy,
    Size,
    Stack,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_s3 as _s3,
)

from constructs import Construct


class OsintCompile(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        domains_bucket_name = f'osint-domains-{region}-{account}'
        download_bucket_name = f'osint-download-{region}-{account}'

        domains_bucket = _s3.Bucket.from_bucket_name(
            self,
            'domainsbucket',
            bucket_name=domains_bucket_name,
        )

        download_bucket = _s3.Bucket.from_bucket_name(
            self,
            'downloadbucket',
            bucket_name=download_bucket_name,
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

        domains_bucket.grant_read(role)
        download_bucket.grant_put(role)

        compile_lambda = _lambda.Function(
            self,
            'compile',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('compile'),
            handler='compile.handler',
            environment=dict(
                S3_DOMAINS_BUCKET=domains_bucket_name,
                S3_DOWNLOAD_BUCKET=download_bucket_name,
            ),
            ephemeral_storage_size=Size.gibibytes(3),
            timeout=Duration.seconds(900),
            memory_size=1024,
            role=role,
        )

        _logs.LogGroup(
            self,
            'logs',
            log_group_name='/aws/lambda/' + compile_lambda.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        event = _events.Rule(
            self,
            'event',
            schedule=_events.Schedule.cron(
                minute='5',
                hour='*',
                month='*',
                week_day='*',
                year='*',
            ),
        )

        event.add_target(_targets.LambdaFunction(compile_lambda))
