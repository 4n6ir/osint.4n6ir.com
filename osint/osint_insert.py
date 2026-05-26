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


class OsintInsert(Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        watchlist_table: _dynamodb.ITableV2,
        state_table: _dynamodb.ITableV2,
        subscription_table: _dynamodb.ITableV2,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        region = Stack.of(self).region

        search_dlq = _sqs.Queue(
            self,
            'SearchDLQ',
            queue_name=f'osint-search-dlq-{region}',
            retention_period=Duration.days(14),
        )

        search_sqs = _sqs.Queue(
            self,
            'SearchSQS',
            queue_name=f'osint-search-{region}',
            dead_letter_queue=_sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=search_dlq,
            ),
            visibility_timeout=Duration.minutes(30),
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
                actions=['dynamodb:GetItem'],
                resources=[subscription_table.table_arn],
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions=['dynamodb:GetItem', 'dynamodb:PutItem'],
                resources=[state_table.table_arn],
            )
        )

        watchlist_table.grant_stream_read(role)
        search_sqs.grant_send_messages(role)

        insert = _lambda.Function(
            self,
            'insert',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('insert'),
            handler='insert.handler',
            timeout=Duration.seconds(900),
            memory_size=256,
            role=role,
            environment={
                'STATE_TABLE': state_table.table_name,
                'SUBSCRIPTION_TABLE': subscription_table.table_name,
                'SEARCH_SQS_URL': search_sqs.queue_url,
                'DLQ_URL': search_dlq.queue_url,
            },
        )

        insert.add_event_source(
            _event_sources.DynamoEventSource(
                watchlist_table,
                starting_position=_lambda.StartingPosition.LATEST,
                batch_size=1,
                report_batch_item_failures=True,
            )
        )

        _logs.LogGroup(
            self,
            'logs',
            log_group_name='/aws/lambda/' + insert.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.insert = insert
        self.search_queue = search_sqs
