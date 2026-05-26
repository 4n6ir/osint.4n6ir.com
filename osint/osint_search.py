from aws_cdk import (
    Duration,
    RemovalPolicy,
    Size,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_lambda_event_sources as _event_sources,
    aws_logs as _logs,
    aws_s3 as _s3,
    aws_sqs as _sqs,
)

from constructs import Construct


class OsintSearch(Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        search_queue: _sqs.IQueue,
        watchlist_table: _dynamodb.ITableV2,
        osint_table: _dynamodb.ITableV2,
        users_table: _dynamodb.ITableV2,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        sqlite_bucket_name = f'osint-sqlite-{region}-{account}'
        sqlite_bucket = _s3.Bucket.from_bucket_name(
            self,
            'sqlitebucket',
            bucket_name=sqlite_bucket_name,
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

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaVPCAccessExecutionRole',
            )
        )

        search = _lambda.Function(
            self,
            'search',
            runtime=_lambda.Runtime.PYTHON_3_13,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('search'),
            handler='search.handler',
            environment={
                'S3_SQLITE_BUCKET_NAME': sqlite_bucket_name,
                'TARGET_SQLITE_KEY': 'osint.sqlite3',
                'WATCHLIST_TABLE': watchlist_table.table_name,
                'OSINT_TABLE': osint_table.table_name,
                'MALWARE_TABLE': 'malware',
                'DAILYREMOVE_TABLE': 'dailyremove',
                'DAILYUPDATE_TABLE': 'dailyupdate',
                'WEEKLYREMOVE_TABLE': 'weeklyremove',
                'WEEKLYUPDATE_TABLE': 'weeklyupdate',
                'MONTHLYREMOVE_TABLE': 'monthlyremove',
                'MONTHLYUPDATE_TABLE': 'monthlyupdate',
                'USERS_TABLE': users_table.table_name,
            },
            ephemeral_storage_size=Size.gibibytes(3),
            timeout=Duration.seconds(900),
            memory_size=2048,
            role=role,
        )

        sqlite_bucket.grant_read(role)
        watchlist_table.grant_read_write_data(role)
        osint_table.grant_read_write_data(role)
        users_table.grant_read_data(role)
        role.add_to_policy(
            _iam.PolicyStatement(
                actions=[
                    'dynamodb:GetItem',
                    'dynamodb:PutItem',
                    'dynamodb:DeleteItem',
                    'dynamodb:Query',
                    'dynamodb:BatchWriteItem',
                ],
                resources=[
                    f'arn:aws:dynamodb:{region}:{account}:table/malware',
                    f'arn:aws:dynamodb:{region}:{account}:table/dailyremove',
                    f'arn:aws:dynamodb:{region}:{account}:table/dailyupdate',
                    f'arn:aws:dynamodb:{region}:{account}:table/weeklyremove',
                    f'arn:aws:dynamodb:{region}:{account}:table/weeklyupdate',
                    f'arn:aws:dynamodb:{region}:{account}:table/monthlyremove',
                    f'arn:aws:dynamodb:{region}:{account}:table/monthlyupdate',
                ],
            )
        )

        _logs.LogGroup(
            self,
            'logs',
            log_group_name='/aws/lambda/' + search.function_name,
            retention=_logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        search.add_event_source(
            _event_sources.SqsEventSource(
                search_queue,
                batch_size=1,
                report_batch_item_failures=True,
            )
        )

        self.search = search
