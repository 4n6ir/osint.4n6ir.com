import unittest

from aws_cdk import App, Stack, assertions
from aws_cdk import aws_dynamodb as _dynamodb

from osint.osint_insert import OsintInsert


class OsintInsertStackTests(unittest.TestCase):
    def _build_template(self):
        app = App()
        db_stack = Stack(app, 'DbTestStack')
        watchlist = _dynamodb.TableV2(
            db_stack,
            'Watchlist',
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
            dynamo_stream=_dynamodb.StreamViewType.NEW_IMAGE,
        )

        state = _dynamodb.TableV2(
            db_stack,
            'State',
            table_name='state',
            partition_key={
                'name': 'pk',
                'type': _dynamodb.AttributeType.STRING,
            },
            sort_key={
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING,
            },
            billing=_dynamodb.Billing.on_demand(),
        )

        subscription = _dynamodb.TableV2(
            db_stack,
            'Subscription',
            table_name='subscription',
            partition_key={
                'name': 'pk',
                'type': _dynamodb.AttributeType.STRING,
            },
            sort_key={
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING,
            },
            billing=_dynamodb.Billing.on_demand(),
        )

        insert_stack = OsintInsert(
            app,
            'InsertTestStack',
            watchlist_table=watchlist,
            state_table=state,
            subscription_table=subscription,
        )

        return assertions.Template.from_stack(insert_stack)

    def test_creates_search_queue_and_dlq(self):
        template = self._build_template()

        queues = template.find_resources('AWS::SQS::Queue')
        self.assertEqual(len(queues), 2)

        redrive_queues = [
            queue
            for queue in queues.values()
            if 'RedrivePolicy' in queue.get('Properties', {})
        ]
        self.assertEqual(len(redrive_queues), 1)

    def test_lambda_has_required_environment_variables(self):
        template = self._build_template()

        template.has_resource_properties(
            'AWS::Lambda::Function',
            {
                'Environment': {
                    'Variables': {
                        'STATE_TABLE': assertions.Match.any_value(),
                        'SUBSCRIPTION_TABLE': assertions.Match.any_value(),
                        'SEARCH_SQS_URL': assertions.Match.any_value(),
                    }
                }
            },
        )

    def test_role_policy_includes_dynamodb_and_sqs_permissions(self):
        template = self._build_template()

        policies = template.find_resources('AWS::IAM::Policy')
        statements = []
        for policy in policies.values():
            doc = policy.get('Properties', {}).get('PolicyDocument', {})
            stmts = doc.get('Statement', [])
            if isinstance(stmts, dict):
                statements.append(stmts)
            else:
                statements.extend(stmts)

        flattened_actions = []
        for statement in statements:
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                flattened_actions.append(actions)
            else:
                flattened_actions.extend(actions)

        self.assertIn('dynamodb:GetItem', flattened_actions)
        self.assertIn('dynamodb:PutItem', flattened_actions)
        self.assertIn('sqs:SendMessage', flattened_actions)


if __name__ == '__main__':
    unittest.main()
