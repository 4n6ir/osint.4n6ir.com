from __future__ import annotations

from aws_cdk import (
	Duration,
	RemovalPolicy,
	Size,
	Stack,
	aws_iam as _iam,
	aws_lambda as _lambda,
	aws_lambda_event_sources as _event_sources,
	aws_logs as _logs,
	aws_sqs as _sqs,
)

from constructs import Construct


class OsintSqlite(Stack):

    def __init__(self, scope: Construct, construct_id: str, download_queue: _sqs.IQueue, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        download_bucket_name = f'osint-download-{region}-{account}'
        sqlite_bucket_name = f'osint-sqlite-{region}-{account}'

        role = _iam.Role(
            self, 'role',
            assumed_by=_iam.ServicePrincipal('lambda.amazonaws.com'),
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole',
            )
        )

        # Grant S3 permissions using IAM policy statements to avoid circular dependencies
        role.add_to_policy(
            _iam.PolicyStatement(
                actions=[
                    's3:GetObject',
                    's3:PutObject',
                    's3:PutObjectAcl',
                ],
                resources=[
                    f'arn:aws:s3:::{download_bucket_name}/*',
                    f'arn:aws:s3:::{sqlite_bucket_name}/*',
                ],
            )
        )

        download_queue.grant_consume_messages(role)

        sqlite = _lambda.Function(
            self, 'sqlite',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('sqlite'),
            handler='sqlite.handler',
            environment=dict(
                S3_SQLITE_BUCKET_NAME=sqlite_bucket_name,
            ),
            ephemeral_storage_size=Size.gibibytes(3),
            timeout=Duration.seconds(900),
            memory_size=2048,
            role=role,
        )

        sqlite.add_event_source(
            _event_sources.SqsEventSource(
                download_queue,
                batch_size=1,
                report_batch_item_failures=True,
            )
        )

        _logs.LogGroup(
            self, 'logs',
            log_group_name='/aws/lambda/' + sqlite.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

