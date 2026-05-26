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
    aws_s3 as _s3,
    aws_sqs as _sqs,
)

from constructs import Construct


class OsintUnzip(Stack):

    def __init__(self, scope: Construct, construct_id: str, zipped_queue: _sqs.IQueue, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        zipped_bucket_name = f'osint-zipped-{region}-{account}'
        download_bucket_name = f'osint-download-{region}-{account}'

        zipped_bucket = _s3.Bucket.from_bucket_name(
            self,
            'zippedbucket',
            bucket_name=zipped_bucket_name,
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

        zipped_bucket.grant_read(role)
        download_bucket.grant_put(role)

        zipped_queue.grant_consume_messages(role)

        unzip = _lambda.Function(
            self,
            'unzip',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('unzip'),
            handler='unzip.handler',
            environment=dict(
                S3_DOWNLOAD_BUCKET=download_bucket_name,
                LINES_PER_FILE='10000000',
            ),
            timeout=Duration.seconds(900),
            memory_size=1024,
            role=role,
        )

        unzip.add_event_source(
            _event_sources.SqsEventSource(
                zipped_queue,
                batch_size=1,
                report_batch_item_failures=True,
            )
        )

        _logs.LogGroup(
            self,
            'logs',
            log_group_name='/aws/lambda/' + unzip.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )
