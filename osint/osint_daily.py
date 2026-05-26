from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_sqs as _sqs,
)

from constructs import Construct


class OsintDaily(Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
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

        search_queue.grant_send_messages(role)
        users_table.grant_read_data(role)
        watchlist_table.grant_read_data(role)

        daily = _lambda.Function(
            self,
            'daily',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('daily'),
            handler='daily.handler',
            environment=dict(
                USERS_TABLE=users_table.table_name,
                WATCHLIST_TABLE=watchlist_table.table_name,
                SEARCH_SQS_URL=search_queue.queue_url,
                USER_SPONSOR_INDEX='Sponsor-SK-index',
            ),
            timeout=Duration.seconds(900),
            memory_size=256,
            role=role,
        )

        _logs.LogGroup(
            self,
            'logs',
            log_group_name='/aws/lambda/' + daily.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        event = _events.Rule(
            self,
            'event',
            schedule=_events.Schedule.cron(
                minute='20',
                hour='1',
                month='*',
                week_day='*',
                year='*',
            ),
        )

        event.add_target(_targets.LambdaFunction(daily))
