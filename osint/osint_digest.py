from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_lambda_event_sources as _event_sources,
    aws_logs as _logs,
    aws_sqs as _sqs,
)

from constructs import Construct


class OsintDigest(Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        dailyremove_table: _dynamodb.ITableV2,
        dailyupdate_table: _dynamodb.ITableV2,
        digest_table: _dynamodb.ITableV2,
        malware_table: _dynamodb.ITableV2,
        osint_table: _dynamodb.ITableV2,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        region = Stack.of(self).region

        dlq = _sqs.Queue(
            self,
            'dlq',
            queue_name=f'osint-email-dlq-{region}',
            retention_period=Duration.days(14),
        )

        queue = _sqs.Queue(
            self,
            'queue',
            queue_name=f'osint-email-{region}',
            visibility_timeout=Duration.seconds(900),
            dead_letter_queue=_sqs.DeadLetterQueue(
                queue=dlq,
                max_receive_count=1,
            ),
        )

        action_role = _iam.Role(
            self,
            'actionrole',
            assumed_by=_iam.ServicePrincipal('lambda.amazonaws.com'),
        )
        action_role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        for table in [dailyremove_table, dailyupdate_table, malware_table, osint_table]:
            table.grant_stream_read(action_role)

        digest_table.grant_read_write_data(action_role)

        action = _lambda.Function(
            self,
            'action',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('action'),
            handler='action.handler',
            environment={
                'DIGEST_TABLE': digest_table.table_name,
            },
            timeout=Duration.seconds(900),
            memory_size=256,
            role=action_role,
        )

        _logs.LogGroup(
            self,
            'actionlogs',
            log_group_name='/aws/lambda/' + action.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        insert_filter = _lambda.FilterCriteria.filter(
            {'eventName': _lambda.FilterRule.is_equal('INSERT')}
        )

        for table in [dailyremove_table, dailyupdate_table, malware_table, osint_table]:
            action.add_event_source(
                _event_sources.DynamoEventSource(
                    table,
                    starting_position=_lambda.StartingPosition.LATEST,
                    filters=[insert_filter],
                    batch_size=10,
                    report_batch_item_failures=True,
                    retry_attempts=2,
                )
            )

        digest_role = _iam.Role(
            self,
            'digestrole',
            assumed_by=_iam.ServicePrincipal('lambda.amazonaws.com'),
        )
        digest_role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        digest_table.grant_read_write_data(digest_role)
        queue.grant_send_messages(digest_role)

        digest = _lambda.Function(
            self,
            'digest',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('digest'),
            handler='digest.handler',
            environment={
                'DIGEST_TABLE': digest_table.table_name,
                'EMAIL_QUEUE_URL': queue.queue_url,
                'FROM_EMAIL': 'hello@4n6ir.com',
                'DIGEST_SUBJECT': 'OSINT: Alert Digest',
            },
            timeout=Duration.seconds(900),
            memory_size=256,
            role=digest_role,
        )

        _logs.LogGroup(
            self,
            'digestlogs',
            log_group_name='/aws/lambda/' + digest.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        email_role = _iam.Role(
            self,
            'emailrole',
            assumed_by=_iam.ServicePrincipal('lambda.amazonaws.com'),
        )
        email_role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        queue.grant_consume_messages(email_role)
        email_role.add_to_policy(
            _iam.PolicyStatement(
                actions=['ses:SendEmail'],
                resources=['*'],
            )
        )

        email = _lambda.Function(
            self,
            'email',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('ses_email'),
            handler='ses_sender.handler',
            environment={
                'FROM_EMAIL': 'hello@4n6ir.com',
            },
            retry_attempts=0,
            timeout=Duration.seconds(900),
            memory_size=256,
            role=email_role,
        )

        _logs.LogGroup(
            self,
            'emaillogs',
            log_group_name='/aws/lambda/' + email.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        email.add_event_source(
            _event_sources.SqsEventSource(
                queue,
                batch_size=1,
                report_batch_item_failures=True,
            )
        )

        event = _events.Rule(
            self,
            'event',
            schedule=_events.Schedule.cron(
                minute='0/15',
                hour='*',
                month='*',
                week_day='*',
                year='*',
            ),
        )

        event.add_target(_targets.LambdaFunction(digest))
