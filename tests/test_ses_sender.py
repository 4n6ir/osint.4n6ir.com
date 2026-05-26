import importlib
import json
import os
import unittest
from unittest.mock import patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('FROM_EMAIL', 'hello@4n6ir.com')


class _FakeSesClient:
    def __init__(self):
        self.calls = []

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        return {'MessageId': '1'}


class SesSenderLambdaTests(unittest.TestCase):
    def setUp(self):
        self.email_lambda = importlib.import_module('ses_email.ses_sender')
        self.email_lambda = importlib.reload(self.email_lambda)

    def test_sends_email_and_defangs_numbered_domains(self):
        fake_ses = _FakeSesClient()
        event = {
            'Records': [
                {
                    'messageId': '1',
                    'body': json.dumps(
                        {
                            'to': 'user@example.com',
                            'subject': 'OSINT: Alert Digest',
                            'body': 'New Domains\n1. alpha.com\n2. beta.net',
                        }
                    ),
                }
            ]
        }

        with patch('boto3.client', return_value=fake_ses):
            result = self.email_lambda.handler(event, None)

        self.assertEqual(result['batchItemFailures'], [])
        self.assertEqual(result['sent'], 1)
        sent_body = fake_ses.calls[0]['Message']['Body']['Text']['Data']
        self.assertIn('1. alpha[.]com', sent_body)
        self.assertIn('2. beta[.]net', sent_body)


if __name__ == '__main__':
    unittest.main()
