import boto3
import datetime
import ipaddress
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


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_domain(line):
    cleaned = line.strip().lower()

    if not cleaned:
        return None

    if cleaned.startswith('#'):
        return None

    if '#' in cleaned:
        cleaned = cleaned.split('#', 1)[0].strip()

    if not cleaned:
        return None

    tokens = cleaned.split()

    if not tokens:
        return None

    if is_ip(tokens[0]):
        if len(tokens) < 2:
            return None
        domain = tokens[1].strip('.')
    else:
        domain = tokens[0].strip('.')

    if domain in {'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback'}:
        return None

    if '.' not in domain:
        return None

    return domain


def handler(event, context):

    count = 0

    year = datetime.datetime.now().strftime('%Y')
    month = datetime.datetime.now().strftime('%m')
    day = datetime.datetime.now().strftime('%d')
    hour = datetime.datetime.now().strftime('%H')
    minute = datetime.datetime.now().strftime('%M')

    github_url = os.environ['GITHUB_URL']
    headers = {'User-Agent': f'OSINT ({github_url})'}

    response = requests.get('https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/RAW/Malware', headers=headers, timeout=60)
    print(f'HTTP Status Code: {response.status_code}')
    data = response.text

    fname = f'{year}-{month}-{day}-{hour}-{minute}-shadowwhisperer.csv'

    with tempfile.TemporaryDirectory(dir='/tmp') as tmpdir:
        fpath = os.path.join(tmpdir, fname)

        with open(fpath, 'w', encoding='utf-8') as f:
            for line in data.splitlines():
                domain = parse_domain(line)

                if domain is None:
                    continue

                sld = extract_sld(domain)
                tld = extract_tld(domain)
                f.write(f"{sld},{tld},P\n")
                count += 1

        print(f'{count} Domains')

        s3 = boto3.resource('s3')

        s3.meta.client.upload_file(
            fpath,
            os.environ['S3_DOMAINS_BUCKET'],
            f'shadowwhisperer/{fname}',
            ExtraArgs = {
                'ContentType': "text/csv"
            }
        )

    return {
        'statusCode': 200,
        'body': json.dumps('Completed!')
    }
