import json
import os

import boto3
from boto3.dynamodb.conditions import Key


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


def _enqueue_messages_for_sponsor(sponsor, osintsearch, subscription):
    users_table = DYNAMODB.Table(USERS_TABLE)
    watchlist_table = DYNAMODB.Table(WATCHLIST_TABLE)

    sent = 0
    users_total = 0
    watchlist_entries_total = 0
    seen_messages = set()

    for email in _iter_user_emails(users_table, [sponsor]):
        users_total += 1
        for watchlist_email, domain in _iter_watchlist_entries(watchlist_table, email):
            watchlist_entries_total += 1
            dedupe_key = (watchlist_email, domain, osintsearch, subscription)
            if dedupe_key in seen_messages:
                continue
            seen_messages.add(dedupe_key)

            SQS_CLIENT.send_message(
                QueueUrl=SEARCH_SQS_URL,
                MessageBody=json.dumps(
                    {
                        'domain': domain,
                        'email': watchlist_email,
                        'osintsearch': osintsearch,
                        'subscription': subscription,
                    }
                ),
            )
            sent += 1

    return {
        'sponsor': sponsor,
        'users_scanned': users_total,
        'watchlist_entries_scanned': watchlist_entries_total,
        'messages_queued': sent,
        'osintsearch': osintsearch,
        'subscription': subscription,
    }


def handler(event, context):
    del event
    del context

    if not SEARCH_SQS_URL:
        raise RuntimeError('SEARCH_SQS_URL environment variable is required')

    basic_stats = _enqueue_messages_for_sponsor('Basic', 'YES', 'NO')
    data_stats = _enqueue_messages_for_sponsor('Data', 'NO', 'YES')

    print(
        json.dumps(
            {
                'event': 'daily_fanout_summary',
                'sponsors': [basic_stats, data_stats],
                'users_scanned': basic_stats['users_scanned'] + data_stats['users_scanned'],
                'watchlist_entries_scanned': (
                    basic_stats['watchlist_entries_scanned'] + data_stats['watchlist_entries_scanned']
                ),
                'messages_queued': basic_stats['messages_queued'] + data_stats['messages_queued'],
            }
        )
    )

    return {
        'basic_queued': basic_stats['messages_queued'],
        'data_queued': data_stats['messages_queued'],
        'queued': basic_stats['messages_queued'] + data_stats['messages_queued'],
    }