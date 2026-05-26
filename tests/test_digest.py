import importlib
import json
import os
import unittest
from unittest.mock import patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('DIGEST_TABLE', 'digest-table')
os.environ.setdefault('EMAIL_QUEUE_URL', 'https://sqs.us-east-1.amazonaws.com/111122223333/osint-email')
os.environ.setdefault('FROM_EMAIL', 'hello@4n6ir.com')


class _FakeBatchWriter:
    def __init__(self):
        self.deleted = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def delete_item(self, Key):
        self.deleted.append(Key)


class _FakeDigestTable:
    def __init__(self, items):
        self.items = items
        self.batch = _FakeBatchWriter()
        self.last_query_kwargs = None

    def query(self, **kwargs):
        self.last_query_kwargs = kwargs
        return {'Items': self.items}

    def batch_writer(self):
        return self.batch


class _FakeDdbResource:
    def __init__(self, table):
        self._table = table

    def Table(self, _table_name):
        return self._table


class _FakeSqs:
    def __init__(self):
        self.messages = []

    def send_message(self, **kwargs):
        self.messages.append(kwargs)
        return {'MessageId': str(len(self.messages))}


class DigestLambdaTests(unittest.TestCase):
    def setUp(self):
        self.digest_lambda = importlib.import_module('digest.digest')
        self.digest_lambda = importlib.reload(self.digest_lambda)

    def test_groups_digest_items_and_queues_email(self):
        items = [
            {'pk': 'OSINT#', 'sk': 'OSINT#alice@example.com#alpha.com#dailyupdate#alpha-new.com#', 'email': 'alice@example.com', 'tbl': 'dailyupdate', 'result': 'alpha-new.com'},
            {'pk': 'OSINT#', 'sk': 'OSINT#alice@example.com#beta.com#dailyremove#beta-old.com#', 'email': 'alice@example.com', 'tbl': 'dailyremove', 'result': 'beta-old.com'},
            {'pk': 'OSINT#', 'sk': 'OSINT#alice@example.com#gamma.com#malware#gamma-bad.com#', 'email': 'alice@example.com', 'tbl': 'malware', 'result': 'gamma-bad.com'},
        ]
        table = _FakeDigestTable(items)
        fake_sqs = _FakeSqs()

        with patch.object(self.digest_lambda, 'DYNAMODB', _FakeDdbResource(table)), patch.object(self.digest_lambda, 'SQS', fake_sqs):
            result = self.digest_lambda.handler({}, None)

        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(len(fake_sqs.messages), 1)

        payload = json.loads(fake_sqs.messages[0]['MessageBody'])
        self.assertEqual(payload['to'], 'alice@example.com')
        self.assertIn('New Domains', payload['body'])
        self.assertIn('alpha-new.com', payload['body'])
        self.assertIn('Expired Domains', payload['body'])
        self.assertIn('beta-old.com', payload['body'])
        self.assertIn('Suspect Domains', payload['body'])
        self.assertIn('gamma-bad.com', payload['body'])
        self.assertEqual(len(table.batch.deleted), 3)
        self.assertEqual(
            table.last_query_kwargs.get('ProjectionExpression'),
            '#pk, #sk, #email, #tbl, #result',
        )
        self.assertEqual(
            table.last_query_kwargs.get('ExpressionAttributeNames'),
            {
                '#pk': 'pk',
                '#sk': 'sk',
                '#email': 'email',
                '#tbl': 'tbl',
                '#result': 'result',
            },
        )


if __name__ == '__main__':
    unittest.main()
