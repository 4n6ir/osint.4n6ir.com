import importlib
import os
import unittest
from unittest.mock import patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('DIGEST_TABLE', 'digest-table')


class _FakeDigestTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item):
        self.items.append(Item)


class ActionLambdaTests(unittest.TestCase):
    def setUp(self):
        self.action_lambda = importlib.import_module('action.action')
        self.action_lambda = importlib.reload(self.action_lambda)

    def test_insert_event_writes_digest_entry(self):
        fake_digest = _FakeDigestTable()
        event = {
            'Records': [
                {
                    'eventName': 'INSERT',
                    'eventSourceARN': 'arn:aws:dynamodb:us-east-1:111122223333:table/dailyupdate/stream/2026-01-01T00:00:00.000',
                    'dynamodb': {
                        'NewImage': {
                            'email': {'S': 'User@Example.COM'},
                            'domain': {'S': 'Example.COM'},
                            'result': {'S': 'New.Example.COM'},
                        }
                    },
                }
            ]
        }

        with patch.object(self.action_lambda, 'DIGEST', fake_digest):
            result = self.action_lambda.handler(event, None)

        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['processed'], 1)
        self.assertEqual(len(fake_digest.items), 1)
        self.assertEqual(fake_digest.items[0]['email'], 'user@example.com')
        self.assertEqual(fake_digest.items[0]['result'], 'new.example.com')
        self.assertEqual(fake_digest.items[0]['tbl'], 'dailyupdate')
        self.assertNotIn('domain', fake_digest.items[0])
        self.assertIn('OSINT#user@example.com#example.com#dailyupdate#new.example.com#', fake_digest.items[0]['sk'])

    def test_insert_event_without_result_is_skipped(self):
        fake_digest = _FakeDigestTable()
        event = {
            'Records': [
                {
                    'eventName': 'INSERT',
                    'eventSourceARN': 'arn:aws:dynamodb:us-east-1:111122223333:table/osint/stream/2026-01-01T00:00:00.000',
                    'dynamodb': {
                        'NewImage': {
                            'email': {'S': 'user@example.com'},
                            'domain': {'S': 'example.com'},
                        }
                    },
                }
            ]
        }

        with patch.object(self.action_lambda, 'DIGEST', fake_digest):
            result = self.action_lambda.handler(event, None)

        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['skipped'], 1)
        self.assertEqual(len(fake_digest.items), 0)

    def test_multiple_results_create_separate_entries(self):
        fake_digest = _FakeDigestTable()
        event = {
            'Records': [
                {
                    'eventName': 'INSERT',
                    'eventSourceARN': 'arn:aws:dynamodb:us-east-1:111122223333:table/osint/stream/2026-01-01T00:00:00.000',
                    'dynamodb': {
                        'NewImage': {
                            'email': {'S': 'user@example.com'},
                            'domain': {'S': 'example.com'},
                            'result': {'S': 'evil1.com'},
                        }
                    },
                },
                {
                    'eventName': 'INSERT',
                    'eventSourceARN': 'arn:aws:dynamodb:us-east-1:111122223333:table/osint/stream/2026-01-01T00:00:00.000',
                    'dynamodb': {
                        'NewImage': {
                            'email': {'S': 'user@example.com'},
                            'domain': {'S': 'example.com'},
                            'result': {'S': 'evil2.com'},
                        }
                    },
                },
            ]
        }

        with patch.object(self.action_lambda, 'DIGEST', fake_digest):
            result = self.action_lambda.handler(event, None)

        self.assertEqual(result['processed'], 2)
        sks = {item['sk'] for item in fake_digest.items}
        self.assertIn('OSINT#user@example.com#example.com#osint#evil1.com#', sks)
        self.assertIn('OSINT#user@example.com#example.com#osint#evil2.com#', sks)


if __name__ == '__main__':
    unittest.main()
