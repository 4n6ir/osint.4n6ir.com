import json
import os
import re

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def _parse_record_body(record):
    body = record.get('body', '{}')
    if isinstance(body, str):
        return json.loads(body)
    return body


def _defang_domain_lines(body_text):
    lines = []
    for line in str(body_text or '').splitlines():
        match = re.match(r'^(\d+\.\s+)(.+)$', line)
        if not match:
            lines.append(line)
            continue

        prefix, value = match.groups()
        lines.append(prefix + value.replace('.', '[.]'))

    return '\n'.join(lines)


def handler(event, _context):
    ses = boto3.client('ses')
    default_from = os.environ.get('FROM_EMAIL', 'hello@4n6ir.com')

    failures = []
    sent = 0

    for record in event.get('Records', []):
        message_id = record.get('messageId')
        try:
            payload = _parse_record_body(record)
            from_address = payload.get('from', default_from)
            to_address = payload['to']
            subject = payload.get('subject', 'OSINT: Alert Digest')
            body_text = _defang_domain_lines(payload.get('body', ''))

            ses.send_email(
                Source=from_address,
                Destination={'ToAddresses': [to_address]},
                Message={
                    'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                    'Body': {'Text': {'Data': body_text, 'Charset': 'UTF-8'}},
                },
            )
            sent += 1
        except (KeyError, TypeError, json.JSONDecodeError, BotoCoreError, ClientError):
            if message_id:
                failures.append({'itemIdentifier': message_id})

    return {
        'batchItemFailures': failures,
        'sent': sent,
    }
