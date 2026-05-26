# pyright: reportPrivateUsage=none

import importlib
import json
import os
import unittest
from unittest.mock import patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('USERS_TABLE', 'users-table')
os.environ.setdefault('WATCHLIST_TABLE', 'watchlist-table')
os.environ.setdefault('SEARCH_SQS_URL', 'https://sqs.us-east-1.amazonaws.com/111122223333/osint-search')
os.environ.setdefault('USER_SPONSOR_INDEX', 'Sponsor-SK-index')


class _FakeUsersTable:
    def __init__(self):
        self.calls = []
        self._responses = [
            {'Items': [{'email': 'core@example.com'}]},
            {'Items': [{'email': 'data@example.com'}]},
        ]

    def query(self, **kwargs):
        self.calls.append(kwargs)
        if self._responses:
            return self._responses.pop(0)
        return {'Items': []}


class _FakeWatchlistTable:
    def __init__(self):
        self.calls = []
        self._responses = [
            {'Items': [{'email': 'core@example.com', 'domain': 'core.io'}]},
            {'Items': [{'email': 'data@example.com', 'domain': 'data.io'}]},
        ]

    def query(self, **kwargs):
        self.calls.append(kwargs)
        if self._responses:
            return self._responses.pop(0)
        return {'Items': []}


class _FakeDynamodbResource:
    def __init__(self, users_table, watchlist_table):
        self.users_table = users_table
        self.watchlist_table = watchlist_table

    def Table(self, table_name):
        if table_name == os.environ['USERS_TABLE']:
            return self.users_table
        if table_name == os.environ['WATCHLIST_TABLE']:
            return self.watchlist_table
        raise AssertionError(f'Unexpected table requested: {table_name}')


class _FakeSqsClient:
    def __init__(self):
        self.send_message_calls = []

    def send_message(self, **kwargs):
        self.send_message_calls.append(kwargs)
        return {'MessageId': f'msg-{len(self.send_message_calls)}'}


def _create_event(bucket='osint-sqlite-us-east-1-111122223333', key='osint.sqlite3', message_id='m-1'):
    return {
        'Records': [
            {
                'messageId': message_id,
                'body': json.dumps(
                    {
                        'Records': [
                            {
                                'eventSource': 'aws:s3',
                                'eventName': 'ObjectCreated:Put',
                                's3': {
                                    'bucket': {'name': bucket},
                                    'object': {'key': key},
                                },
                            }
                        ]
                    }
                ),
            }
        ]
    }


class CreateLambdaTests(unittest.TestCase):
    def setUp(self):
        self.create_lambda = importlib.import_module('create.create')
        self.create_lambda = importlib.reload(self.create_lambda)

    def test_s3_osint_object_event_fans_out_core_and_data_sponsors(self):
        users_table = _FakeUsersTable()
        watchlist_table = _FakeWatchlistTable()
        fake_ddb = _FakeDynamodbResource(users_table, watchlist_table)
        fake_sqs = _FakeSqsClient()

        with patch.object(self.create_lambda, 'DYNAMODB', fake_ddb), patch.object(self.create_lambda, 'SQS_CLIENT', fake_sqs):
            result = self.create_lambda.handler(_create_event(), None)

        self.assertEqual(result['batchItemFailures'], [])
        self.assertEqual(result['queued'], 2)
        self.assertEqual(len(result['processed']), 1)
        self.assertEqual(len(fake_sqs.send_message_calls), 2)

        first_body = json.loads(fake_sqs.send_message_calls[0]['MessageBody'])
        second_body = json.loads(fake_sqs.send_message_calls[1]['MessageBody'])

        self.assertEqual(first_body['osintsearch'], 'YES')
        self.assertEqual(first_body['subscription'], 'NO')
        self.assertEqual(second_body['osintsearch'], 'YES')
        self.assertEqual(second_body['subscription'], 'NO')

    def test_ignores_non_target_key(self):
        users_table = _FakeUsersTable()
        watchlist_table = _FakeWatchlistTable()
        fake_ddb = _FakeDynamodbResource(users_table, watchlist_table)
        fake_sqs = _FakeSqsClient()

        with patch.object(self.create_lambda, 'DYNAMODB', fake_ddb), patch.object(self.create_lambda, 'SQS_CLIENT', fake_sqs):
            result = self.create_lambda.handler(_create_event(key='other.sqlite3'), None)

        self.assertEqual(result['queued'], 0)
        self.assertEqual(result['processed'], [])
        self.assertEqual(len(fake_sqs.send_message_calls), 0)


if __name__ == '__main__':
    unittest.main()
