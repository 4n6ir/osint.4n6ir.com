import boto3
import json
import os
import requests
from boto3.dynamodb.conditions import Key

def handler(event, context):

    headers = {'User-Agent': 'OSINT - https://github.com/4n6ir/dev.osint.4n6ir.com'}
    response = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', headers=headers, timeout=10)
    data = response.text

    tlds = []

    for line in data.splitlines():
        if line.startswith('#'):
            continue
        else:
            tlds.append(line.lower())
    
    print('TLDs: '+str(len(tlds)))

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['TLD_TABLE'])

    response = table.query(
        KeyConditionExpression = Key('pk').eq('TLD#')
    )
    responsedata = response['Items']
    while 'LastEvaluatedKey' in response:
        response = table.query(
            KeyConditionExpression = Key('pk').eq('TLD#'),
            ExclusiveStartKey = response['LastEvaluatedKey']
        )
        responsedata.extend(response['Items'])

    print('DynamoDB: '+str(len(responsedata)))

    for entry in tlds:

        if entry not in responsedata:

            table.put_item(
                Item = {
                    'pk': 'TLD#',
                    'sk': entry
                }
            )

    for entry in responsedata:

        if entry['sk'] not in tlds:

            table.delete_item(
                Key = {
                    'pk': 'TLD#',
                    'sk': entry['sk']
                }
            )

    return {
        'statusCode': 200,
        'body': json.dumps('Check List of Top-Level Domains')
    }