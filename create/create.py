import json
import os
from urllib.parse import unquote_plus

import boto3
from boto3.dynamodb.conditions import Key


TARGET_KEY = 'osint.sqlite3'
USERS_TABLE = os.environ.get('USERS_TABLE', 'users')
WATCHLIST_TABLE = os.environ.get('WATCHLIST_TABLE', 'watchlist')
SEARCH_SQS_URL = os.environ.get('SEARCH_SQS_URL', '')
USER_SPONSOR_INDEX = os.environ.get('USER_SPONSOR_INDEX', 'Sponsor-SK-index')

DYNAMODB = boto3.resource('dynamodb')
SQS_CLIENT = boto3.client('sqs')


def _iter_user_emails(users_table, sponsors):
    seen = set()

    for sponsor in sponsors:
        query_kwargs = {
            'IndexName': USER_SPONSOR_INDEX,
            'KeyConditionExpression': Key('sponsor').eq(sponsor) & Key('sk').begins_with('OSINT#'),
            'ProjectionExpression': '#email',
            'ExpressionAttributeNames': {'#email': 'email'},
        }

        while True:
            response = users_table.query(**query_kwargs)
            for item in response.get('Items', []):
                email = str(item.get('email', '')).strip().lower()
                if email and email not in seen:
                    seen.add(email)
                    yield email

            last_evaluated_key = response.get('LastEvaluatedKey')
            if not last_evaluated_key:
                break
            query_kwargs['ExclusiveStartKey'] = last_evaluated_key


def _iter_watchlist_entries(watchlist_table, email):
    query_kwargs = {
        'KeyConditionExpression': Key('pk').eq('OSINT#') & Key('sk').begins_with(f'OSINT#{email}#'),
        'ProjectionExpression': '#domain, #email',
        'ExpressionAttributeNames': {
            '#domain': 'domain',
            '#email': 'email',
        },
    }

    while True:
        response = watchlist_table.query(**query_kwargs)
        for item in response.get('Items', []):
            domain = str(item.get('domain', '')).strip().lower()
            if not domain:
                continue

            watchlist_email = str(item.get('email', '')).strip().lower() or email
            yield watchlist_email, domain

        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break
        query_kwargs['ExclusiveStartKey'] = last_evaluated_key


def _enqueue_messages(sponsors):
    if not SEARCH_SQS_URL:
        raise RuntimeError('SEARCH_SQS_URL environment variable is required')

    users_table = DYNAMODB.Table(USERS_TABLE)
    watchlist_table = DYNAMODB.Table(WATCHLIST_TABLE)

    sent = 0
    users_total = 0
    watchlist_entries_total = 0
    seen_messages = set()
    sponsors_queried = []

    for email in _iter_user_emails(users_table, sponsors):
        users_total += 1
        for watchlist_email, domain in _iter_watchlist_entries(watchlist_table, email):
            watchlist_entries_total += 1
            dedupe_key = (watchlist_email, domain)
            if dedupe_key in seen_messages:
                continue
            seen_messages.add(dedupe_key)

            SQS_CLIENT.send_message(
                QueueUrl=SEARCH_SQS_URL,
                MessageBody=json.dumps(
                    {
                        'domain': domain,
                        'email': watchlist_email,
                        'osintsearch': 'YES',
                        'subscription': 'NO',
                    }
                ),
            )
            sent += 1

    sponsors_queried.extend(sponsors)

    return {
        'sponsors': sponsors_queried,
        'users_scanned': users_total,
        'watchlist_entries_scanned': watchlist_entries_total,
        'messages_queued': sent,
    }


def handler(event, context):
    del context

    failures = []
    processed = []

    for record in event.get('Records', []):
        message_id = record.get('messageId', '')
        try:
            body = json.loads(record.get('body', '{}'))
            for s3_record in body.get('Records', []):
                if s3_record.get('eventSource') != 'aws:s3':
                    continue

                event_name = s3_record.get('eventName', '')
                if not event_name.startswith('ObjectCreated:'):
                    continue

                bucket_name = s3_record.get('s3', {}).get('bucket', {}).get('name', '')
                key = unquote_plus(s3_record.get('s3', {}).get('object', {}).get('key', ''))
                if key != TARGET_KEY:
                    continue

                print(f'Received create event for s3://{bucket_name}/{key}')
                processed.append(
                    {
                        'bucket': bucket_name,
                        'key': key,
                    }
                )
        except ValueError:
            if message_id:
                failures.append({'itemIdentifier': message_id})

    queue_stats = {
        'sponsors': [],
        'users_scanned': 0,
        'watchlist_entries_scanned': 0,
        'messages_queued': 0,
    }
    if processed:
        queue_stats = _enqueue_messages(['Core', 'Data'])

    print(
        json.dumps(
            {
                'event': 'create_fanout_summary',
                'processed_s3_records': len(processed),
                'failed_sqs_records': len(failures),
                **queue_stats,
            }
        )
    )

    return {
        'batchItemFailures': failures,
        'processed': processed,
        'queued': queue_stats['messages_queued'],
    }