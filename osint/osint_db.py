from aws_cdk import (
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
)

from constructs import Construct


class OsintDb(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        tables = {}
        stream_enabled_namespaces = {
            'dailyremove',
            'dailyupdate',
            'malware',
            'osint',
        }
        for namespace in [
            'dailyremove',
            'dailyupdate',
            'digest',
            'malware',
            'monthlyremove',
            'monthlyupdate',
            'osint',
            'subscription',
            'state',
            'weeklyremove',
            'weeklyupdate',
        ]:
            table_kwargs = {}
            if namespace in stream_enabled_namespaces:
                table_kwargs['dynamo_stream'] = _dynamodb.StreamViewType.NEW_IMAGE

            table = _dynamodb.TableV2(
                self,
                namespace,
                table_name=f'{namespace}',
                partition_key={
                    'name': 'pk',
                    'type': _dynamodb.AttributeType.STRING,
                },
                sort_key={
                    'name': 'sk',
                    'type': _dynamodb.AttributeType.STRING,
                },
                billing=_dynamodb.Billing.on_demand(),
                removal_policy=RemovalPolicy.DESTROY,
                point_in_time_recovery_specification=_dynamodb.PointInTimeRecoverySpecification(
                    point_in_time_recovery_enabled=True,
                ),
                deletion_protection=False,
                time_to_live_attribute='ttl',
                **table_kwargs,
            )
            tables[namespace] = table

        _dynamodb.TableV2(
            self,
            'tld',
            table_name='tld',
            partition_key={
                'name': 'pk',
                'type': _dynamodb.AttributeType.STRING,
            },
            sort_key={
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING,
            },
            billing=_dynamodb.Billing.on_demand(),
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=_dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True,
            ),
            deletion_protection=False,
        )

        watchlist_table = _dynamodb.TableV2(
            self,
            'watchlist',
            table_name='watchlist',
            partition_key={
                'name': 'pk',
                'type': _dynamodb.AttributeType.STRING,
            },
            sort_key={
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING,
            },
            billing=_dynamodb.Billing.on_demand(),
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=_dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True,
            ),
            deletion_protection=False,
            dynamo_stream=_dynamodb.StreamViewType.NEW_IMAGE,
        )

        # Add users table with secondary index
        users_table = _dynamodb.TableV2(
            self,
            'users',
            table_name='users',
            partition_key={
                'name': 'pk',
                'type': _dynamodb.AttributeType.STRING,
            },
            sort_key={
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING,
            },
            billing=_dynamodb.Billing.on_demand(),
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=_dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True,
            ),
            deletion_protection=False,
        )

        users_table.add_global_secondary_index(
            index_name='Sponsor-SK-index',
            partition_key={
                'name': 'sponsor',
                'type': _dynamodb.AttributeType.STRING,
            },
            sort_key={
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING,
            },
            projection_type=_dynamodb.ProjectionType.ALL,
        )

        self.watchlist = watchlist_table
        self.dailyremove = tables['dailyremove']
        self.dailyupdate = tables['dailyupdate']
        self.digest = tables['digest']
        self.malware = tables['malware']
        self.state = tables['state']
        self.subscription = tables['subscription']
        self.osint = tables['osint']
        self.users = users_table
