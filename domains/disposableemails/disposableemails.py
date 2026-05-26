import boto3
import datetime
import json
import os
import requests
import tempfile


def extract_sld(domain):
    hostname = domain.strip().strip('.').lower()
    parts = [part for part in hostname.split('.') if part]

    if not parts:
        return ''

    if len(parts) == 1:
        return parts[0]

    return '.'.join(parts[:-1])


def extract_tld(domain):
    hostname = domain.strip().strip('.').lower()
    parts = [part for part in hostname.split('.') if part]

    if len(parts) >= 1:
        return parts[-1]
    return ''


def handler(event, context):

    count = 0

    year = datetime.datetime.now().strftime('%Y')
    month = datetime.datetime.now().strftime('%m')
    day = datetime.datetime.now().strftime('%d')
    hour = datetime.datetime.now().strftime('%H')
    minute = datetime.datetime.now().strftime('%M')

    github_url = os.environ['GITHUB_URL']
    headers = {'User-Agent': f'OSINT ({github_url})'}

    response = requests.get('https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/refs/heads/main/disposable_email_blocklist.conf', headers=headers, timeout=60)
    print(f'HTTP Status Code: {response.status_code}')
    data = response.text

    fname = f'{year}-{month}-{day}-{hour}-{minute}-disposableemails.csv'

    with tempfile.TemporaryDirectory(dir='/tmp') as tmpdir:
        fpath = os.path.join(tmpdir, fname)

        with open(fpath, 'w', encoding='utf-8') as f:
            for line in data.splitlines():
                if line.startswith('#'):
                    continue
                else:
                    domain = line.strip()
                    sld = extract_sld(domain)
                    tld = extract_tld(domain)
                    f.write(f"{sld},{tld},C\n")
                    count += 1

        print(f'{count} Domains')

        s3 = boto3.resource('s3')

        s3.meta.client.upload_file(
            fpath,
            os.environ['S3_DOMAINS_BUCKET'],
            f'disposableemails/{fname}',
            ExtraArgs = {
                'ContentType': "text/csv"
            }
        )

    return {
        'statusCode': 200,
        'body': json.dumps('Completed!')
    }
