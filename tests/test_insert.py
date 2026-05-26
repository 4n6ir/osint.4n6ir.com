# pyright: reportPrivateUsage=none

import importlib
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('STATE_TABLE', 'state-table')
os.environ.setdefault('SUBSCRIPTION_TABLE', 'subscription-table')
os.environ.setdefault('SEARCH_SQS_URL', 'https://sqs.us-east-1.amazonaws.com/111122223333/osint-search')


class FakeDynamoDbClient:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.get_item_calls = []
        self.put_item_calls = []

    def get_item(self, **kwargs):
        self.get_item_calls.append(kwargs)
        if self.responses:
            return self.responses.pop(0)
        return {}

    def put_item(self, **kwargs):
        self.put_item_calls.append(kwargs)
        return {'ResponseMetadata': {'HTTPStatusCode': 200}}


class FakeSqsClient:
    def __init__(self):
        self.send_message_calls = []

    def send_message(self, **kwargs):
        self.send_message_calls.append(kwargs)
        return {'MessageId': 'msg-1'}


def _insert_event(email='user@example.com', domain='example.com', osintsearch='NO'):
    return {
        'Records': [
            {
                'eventName': 'INSERT',
                'dynamodb': {
                    'NewImage': {
                        'email': {'S': email},
                        'domain': {'S': domain},
                        'osintsearch': {'S': osintsearch},
                    }
                },
            }
        ]
    }


class InsertLambdaTests(unittest.TestCase):
    def setUp(self):
        self.insert_lambda = importlib.import_module('insert.insert')
        self.insert_lambda = importlib.reload(self.insert_lambda)

    def test_skips_when_lastday_is_today(self):
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        fake_dynamodb = FakeDynamoDbClient(
            responses=[
                {'Item': {'lastday': {'S': today}}},
            ]
        )
        fake_sqs = FakeSqsClient()

        with patch.object(self.insert_lambda, 'dynamodb', fake_dynamodb), patch.object(self.insert_lambda, 'sqs', fake_sqs):
            result = self.insert_lambda.handler(_insert_event(), None)

        self.assertEqual(result['insert_records'], 1)
        self.assertEqual(len(fake_dynamodb.get_item_calls), 1)
        self.assertEqual(len(fake_sqs.send_message_calls), 0)
        self.assertEqual(len(fake_dynamodb.put_item_calls), 0)

    def test_enqueues_and_updates_state_when_due_and_subscription_active(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%d')
        fake_dynamodb = FakeDynamoDbClient(
            responses=[
                {'Item': {'lastday': {'S': yesterday}}},
                {'Item': {'pk': {'S': 'OSINT#'}, 'sk': {'S': 'OSINT#DM#alice@example.com#'}}},
            ]
        )
        fake_sqs = FakeSqsClient()

        with patch.object(self.insert_lambda, 'dynamodb', fake_dynamodb), patch.object(self.insert_lambda, 'sqs', fake_sqs):
            self.insert_lambda.handler(_insert_event(email='alice@example.com', domain='acme.test'), None)

        self.assertEqual(len(fake_sqs.send_message_calls), 1)
        send_call = fake_sqs.send_message_calls[0]
        self.assertEqual(send_call['QueueUrl'], os.environ['SEARCH_SQS_URL'])
        body = json.loads(send_call['MessageBody'])
        self.assertEqual(body['domain'], 'acme.test')
        self.assertEqual(body['email'], 'alice@example.com')
        self.assertEqual(body['subscription'], 'YES')
        self.assertEqual(body['osintsearch'], 'YES')

        self.assertEqual(len(fake_dynamodb.get_item_calls), 2)
        self.assertEqual(fake_dynamodb.get_item_calls[1]['TableName'], os.environ['SUBSCRIPTION_TABLE'])

        self.assertEqual(len(fake_dynamodb.put_item_calls), 1)
        put_call = fake_dynamodb.put_item_calls[0]
        self.assertEqual(put_call['TableName'], os.environ['STATE_TABLE'])
        self.assertEqual(put_call['Item']['pk']['S'], 'OSINT#')
        self.assertEqual(put_call['Item']['sk']['S'], 'OSINT#alice@example.com#acme.test#')
        self.assertIn('ttl', put_call['Item'])
        ttl_value = int(put_call['Item']['ttl']['N'])
        now_ts = int(datetime.now(timezone.utc).timestamp())
        self.assertGreaterEqual(ttl_value, now_ts + (7 * 24 * 60 * 60) - 5)
        self.assertLessEqual(ttl_value, now_ts + (7 * 24 * 60 * 60) + 5)

    def test_enqueues_with_inactive_subscription_when_due(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%d')
        fake_dynamodb = FakeDynamoDbClient(
            responses=[
                {'Item': {'lastday': {'S': yesterday}}},
                {},
            ]
        )
        fake_sqs = FakeSqsClient()

        with patch.object(self.insert_lambda, 'dynamodb', fake_dynamodb), patch.object(self.insert_lambda, 'sqs', fake_sqs):
            self.insert_lambda.handler(_insert_event(), None)

        self.assertEqual(len(fake_sqs.send_message_calls), 1)
        body = json.loads(fake_sqs.send_message_calls[0]['MessageBody'])
        self.assertEqual(body['subscription'], 'NO')
        self.assertEqual(body['osintsearch'], 'YES')
        self.assertEqual(len(fake_dynamodb.put_item_calls), 1)


if __name__ == '__main__':
    unittest.main()
