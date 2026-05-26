from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_lambda_event_sources as _event_sources,
    aws_logs as _logs,
    aws_sqs as _sqs,
)

from constructs import Construct


class OsintCreate(Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        create_queue: _sqs.IQueue,
        search_queue: _sqs.IQueue,
        users_table: _dynamodb.ITableV2,
        watchlist_table: _dynamodb.ITableV2,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

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

        create_queue.grant_consume_messages(role)
        search_queue.grant_send_messages(role)
        users_table.grant_read_data(role)
        watchlist_table.grant_read_data(role)

        create = _lambda.Function(
            self,
            'create',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('create'),
            handler='create.handler',
            timeout=Duration.seconds(900),
            memory_size=256,
            role=role,
            environment={
                'USERS_TABLE': users_table.table_name,
                'WATCHLIST_TABLE': watchlist_table.table_name,
                'SEARCH_SQS_URL': search_queue.queue_url,
                'USER_SPONSOR_INDEX': 'Sponsor-SK-index',
            },
        )

        create.add_event_source(
            _event_sources.SqsEventSource(
                create_queue,
                batch_size=1,
                report_batch_item_failures=True,
            )
        )

        _logs.LogGroup(
            self,
            'logs',
            log_group_name='/aws/lambda/' + create.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )
