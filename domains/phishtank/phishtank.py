import boto3
import csv
import datetime
import json
import os
import requests
import tempfile
from urllib.parse import urlparse


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


def extract_domain_from_row(row):
    if len(row) < 2:
        return None

    url = row[1].strip()
    if not url:
        return None

    hostname = urlparse(url).hostname
    if not hostname:
        return None

    return hostname.lower().strip('.')


def handler(event, context):

    count = 0

    year = datetime.datetime.now().strftime('%Y')
    month = datetime.datetime.now().strftime('%m')
    day = datetime.datetime.now().strftime('%d')
    hour = datetime.datetime.now().strftime('%H')
    minute = datetime.datetime.now().strftime('%M')

    github_url = os.environ['GITHUB_URL']
    headers = {'User-Agent': f'OSINT ({github_url})'}

    response = requests.get('http://data.phishtank.com/data/online-valid.csv', headers=headers, timeout=60)
    print(f'HTTP Status Code: {response.status_code}')
    if response.status_code == 429:
        print('PhishTank API rate limited (429). Skipping this run.')
        return {
            'statusCode': 200,
            'body': json.dumps('Rate limited by PhishTank. Skipped this run.')
        }

    if response.status_code != 200:
        print(f'Unexpected response from PhishTank ({response.status_code}). Skipping this run.')
        return {
            'statusCode': 200,
            'body': json.dumps(f'PhishTank fetch failed ({response.status_code}). Skipped this run.')
        }

    data = response.text

    fname = f'{year}-{month}-{day}-{hour}-{minute}-phishtank.csv'

    domains = []

    rows = csv.reader(data.splitlines())

    for row in rows:
        if not row:
            continue

        # CSV header and comments from feed metadata.
        if row[0].startswith('#') or row[0] == 'phish_id':
            continue

        domain = extract_domain_from_row(row)
        if domain:
            domains.append(domain)
            count += 1

    domains = list(set(domains))

    with tempfile.TemporaryDirectory(dir='/tmp') as tmpdir:
        fpath = os.path.join(tmpdir, fname)

        with open(fpath, 'w', encoding='utf-8') as f:
            for domain in domains:
                sld = extract_sld(domain)
                tld = extract_tld(domain)
                f.write(f"{sld},{tld},H\n")

        print(f'{count} Domains')
        print(f'{len(domains)} Unique Domains')

        s3 = boto3.resource('s3')

        s3.meta.client.upload_file(
            fpath,
            os.environ['S3_DOMAINS_BUCKET'],
            f'phishtank/{fname}',
            ExtraArgs = {
                'ContentType': "text/csv"
            }
        )

    return {
        'statusCode': 200,
        'body': json.dumps('Completed!')
    }
