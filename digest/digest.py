import json
import os

import boto3
from boto3.dynamodb.conditions import Key


DIGEST_TABLE = os.environ.get('DIGEST_TABLE', 'digest')
EMAIL_QUEUE_URL = os.environ.get('EMAIL_QUEUE_URL', '')
FROM_EMAIL = os.environ.get('FROM_EMAIL', 'hello@4n6ir.com')
SUBJECT = os.environ.get('DIGEST_SUBJECT', 'OSINT: Alert Digest')

DYNAMODB = boto3.resource('dynamodb')
SQS = boto3.client('sqs')


def _query_all(table, key_expr, projection=None, expression_names=None):
    kwargs = {'KeyConditionExpression': key_expr}
    if projection:
        kwargs['ProjectionExpression'] = projection
    if expression_names:
        kwargs['ExpressionAttributeNames'] = expression_names

    response = table.query(**kwargs)
    items = response.get('Items', [])

    while 'LastEvaluatedKey' in response:
        kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
        response = table.query(**kwargs)
        items.extend(response.get('Items', []))

    return items


def _build_body(new_domains, expired_domains, suspect_domains):
    lines = []

    sections = [
        ('New Domains', new_domains),
        ('Expired Domains', expired_domains),
        ('Suspect Domains', suspect_domains),
    ]

    for header, domains in sections:
        if not domains:
            continue

        lines.append(header)
        for index, domain in enumerate(domains, start=1):
            lines.append(f'{index}. {domain}')
        lines.append('')

    return '\n'.join(lines).strip()


def handler(_event, _context):
    if not EMAIL_QUEUE_URL:
        raise RuntimeError('EMAIL_QUEUE_URL environment variable is required')

    digest_table = DYNAMODB.Table(DIGEST_TABLE)

    digest_items = _query_all(
        digest_table,
        Key('pk').eq('OSINT#'),
        projection='#pk, #sk, #email, #tbl, #result',
        expression_names={
            '#pk': 'pk',
            '#sk': 'sk',
            '#email': 'email',
            '#tbl': 'tbl',
            '#result': 'result',
        },
    )

    emails = sorted(
        {
            str(item.get('email', '')).strip().lower()
            for item in digest_items
            if item.get('email')
        }
    )

    queued = 0

    for email in emails:
        email_items = [
            item for item in digest_items
            if str(item.get('email', '')).strip().lower() == email
        ]
        if not email_items:
            continue

        new_domains = sorted(
            {
                str(item.get('result', '')).strip().lower()
                for item in email_items
                if 'dailyupdate' in str(item.get('tbl', '')).lower() and item.get('result')
            }
        )

        expired_domains = sorted(
            {
                str(item.get('result', '')).strip().lower()
                for item in email_items
                if 'dailyremove' in str(item.get('tbl', '')).lower() and item.get('result')
            }
        )

        suspect_domains = sorted(
            {
                str(item.get('result', '')).strip().lower()
                for item in email_items
                if (
                    'malware' in str(item.get('tbl', '')).lower()
                    or 'osint' in str(item.get('tbl', '')).lower()
                ) and item.get('result')
            }
        )

        if not (new_domains or expired_domains or suspect_domains):
            continue

        body = _build_body(new_domains, expired_domains, suspect_domains)

        SQS.send_message(
            QueueUrl=EMAIL_QUEUE_URL,
            MessageBody=json.dumps(
                {
                    'from': FROM_EMAIL,
                    'to': email,
                    'subject': SUBJECT,
                    'body': body,
                }
            ),
        )
        queued += 1

        with digest_table.batch_writer() as batch:
            for item in email_items:
                batch.delete_item(
                    Key={
                        'pk': item['pk'],
                        'sk': item['sk'],
                    }
                )

    return {
        'statusCode': 200,
        'body': json.dumps({'queued': queued, 'emails_seen': len(emails)}),
    }
