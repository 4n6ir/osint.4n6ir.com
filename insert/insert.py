import boto3
import json
import os
from datetime import datetime, timezone
from botocore.exceptions import BotoCoreError, ClientError

dynamodb = boto3.client('dynamodb')
sqs = boto3.client('sqs')

STATE_TABLE = os.environ['STATE_TABLE']
SUBSCRIPTION_TABLE = os.environ['SUBSCRIPTION_TABLE']
SEARCH_SQS_URL = os.environ['SEARCH_SQS_URL']
TTL_SECONDS = 7 * 24 * 60 * 60


def _ttl_epoch_7_days():
    return int(datetime.now(timezone.utc).timestamp()) + TTL_SECONDS


def _subscription_exists(subscription_item):
    return bool(subscription_item)


def _get_subscription_item(pk, email):
    normalized_email = str(email or '').strip().lower()
    if not normalized_email:
        return {}

    subscription_sk = f'OSINT#DM#{normalized_email}#'
    subscription_result = dynamodb.get_item(
        TableName=SUBSCRIPTION_TABLE,
        Key={
            'pk': {'S': pk},
            'sk': {'S': subscription_sk}
        }
    )
    return subscription_result.get('Item', {})

def handler(event, context):
    del context

    print(event)

    insert_records = []
    for record in event.get('Records', []):
        if record.get('eventName') == 'INSERT':
            insert_records.append(record)

    for record in insert_records:
        domain = record['dynamodb']['NewImage']['domain']['S']
        email = record['dynamodb']['NewImage']['email']['S']

        pk = 'OSINT#'
        sk = f'OSINT#{email}#{domain}#'
        state_response = dynamodb.get_item(
            TableName=STATE_TABLE,
            Key={
                'pk': {'S': pk},
                'sk': {'S': sk}
            }
        )

        current_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        lastday = state_response.get('Item', {}).get('lastday', {}).get('S')

        if lastday != current_date:
            subscription_item = _get_subscription_item(pk, email)
            has_subscription = _subscription_exists(subscription_item)

            message = {
                'domain': domain,
                'email': email,
                'subscription': 'YES' if has_subscription else 'NO',
                'osintsearch': 'YES',
            }

            try:
                sqs.send_message(
                    QueueUrl=SEARCH_SQS_URL,
                    MessageBody=json.dumps(message)
                )
                print(f"Message sent to Search SQS: {message}")
            except (BotoCoreError, ClientError) as e:
                print(f"Failed to send message to SQS: {e}")
                continue

            dynamodb.put_item(
                TableName=STATE_TABLE,
                Item={
                    'pk': {'S': pk},
                    'sk': {'S': sk},
                    'lastday': {'S': current_date},
                    'ttl': {'N': str(_ttl_epoch_7_days())},
                }
            )

    return {
        'insert_records': len(insert_records),
    }
