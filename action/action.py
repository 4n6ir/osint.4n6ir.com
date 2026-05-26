import os
import time

import boto3
from boto3.dynamodb.types import TypeDeserializer


DIGEST_TABLE = os.environ.get('DIGEST_TABLE', 'digest')
TTL_SECONDS = 7 * 24 * 60 * 60
DYNAMODB = boto3.resource('dynamodb')
DIGEST = DYNAMODB.Table(DIGEST_TABLE)
DESERIALIZER = TypeDeserializer()


def _deserialize(raw):
    return {key: DESERIALIZER.deserialize(value) for key, value in raw.items()}


def _normalize_email(value):
    return str(value or '').strip().lower()


def _normalize_domain(value):
    return str(value or '').strip().lower().strip('#')


def _extract_table_name(record):
    source_arn = str(record.get('eventSourceARN', '') or '')
    if ':table/' in source_arn:
        after_table = source_arn.split(':table/', 1)[1]
        return after_table.split('/')[0]
    return ''


def _ttl_epoch_7_days():
    return int(time.time()) + TTL_SECONDS


def handler(event, context):
    del context

    processed = 0
    skipped = 0

    for record in event.get('Records', []):
        if record.get('eventName') != 'INSERT':
            skipped += 1
            continue

        new_image = record.get('dynamodb', {}).get('NewImage', {})
        if not new_image:
            skipped += 1
            continue

        item = _deserialize(new_image)
        email = _normalize_email(item.get('email', ''))
        domain = _normalize_domain(item.get('domain', ''))
        result = _normalize_domain(item.get('result', ''))
        table_name = (_extract_table_name(record) or item.get('tbl', '') or '').strip().lower()

        if not email or not domain or not table_name or not result:
            skipped += 1
            continue

        digest_sk = f'OSINT#{email}#{domain}#{table_name}#{result}#'
        DIGEST.put_item(
            Item={
                'pk': 'OSINT#',
                'sk': digest_sk,
                'email': email,
                'tbl': table_name,
                'result': result,
                'ttl': _ttl_epoch_7_days(),
            }
        )
        processed += 1

    return {
        'statusCode': 200,
        'processed': processed,
        'skipped': skipped,
    }
