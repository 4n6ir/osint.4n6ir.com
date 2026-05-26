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
            {'Items': [{'email': 'basic@example.com'}]},
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
            {'Items': [{'email': 'basic@example.com', 'domain': 'basic.io'}]},
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


class DailyLambdaTests(unittest.TestCase):
    def setUp(self):
        self.daily_lambda = importlib.import_module('daily.daily')
        self.daily_lambda = importlib.reload(self.daily_lambda)

    def test_enqueues_basic_and_data_with_expected_flags(self):
        users_table = _FakeUsersTable()
        watchlist_table = _FakeWatchlistTable()
        fake_ddb = _FakeDynamodbResource(users_table, watchlist_table)
        fake_sqs = _FakeSqsClient()

        with patch.object(self.daily_lambda, 'DYNAMODB', fake_ddb), patch.object(self.daily_lambda, 'SQS_CLIENT', fake_sqs):
            result = self.daily_lambda.handler({}, None)

        self.assertEqual(result['basic_queued'], 1)
        self.assertEqual(result['data_queued'], 1)
        self.assertEqual(result['queued'], 2)
        self.assertEqual(len(fake_sqs.send_message_calls), 2)

        first_body = json.loads(fake_sqs.send_message_calls[0]['MessageBody'])
        second_body = json.loads(fake_sqs.send_message_calls[1]['MessageBody'])

        by_email = {
            first_body['email']: first_body,
            second_body['email']: second_body,
        }

        self.assertEqual(by_email['basic@example.com']['osintsearch'], 'YES')
        self.assertEqual(by_email['basic@example.com']['subscription'], 'NO')
        self.assertEqual(by_email['data@example.com']['osintsearch'], 'NO')
        self.assertEqual(by_email['data@example.com']['subscription'], 'YES')


if __name__ == '__main__':
    unittest.main()
