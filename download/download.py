import boto3
import io
import json
import os
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ChunkedEncodingError, ConnectionError as RequestsConnectionError, Timeout
from urllib3.util.retry import Retry


ITEMS = [
    'dailyupdate',
    'weeklyupdate',
    'monthlyupdate',
    'dailyremove',
    'weeklyremove',
    'monthlyremove',
    'malware'
]

#FULL_LIST_ITEM = 'full'


def _normalize_domain(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    return (value or '').strip().lower().rstrip('.')


def _extract_sld(domain):
    parts = [part for part in domain.split('.') if part]
    if len(parts) >= 2:
        return '.'.join(parts[:-1])
    if len(parts) == 1:
        return parts[0]
    return ''


def _extract_tld(domain):
    parts = [part for part in domain.split('.') if part]
    if len(parts) >= 1:
        return parts[-1]
    return ''


def _format_domains_csv(lines):
    output = io.StringIO()

    for raw_line in lines:
        domain = _normalize_domain(raw_line)
        if not domain:
            continue
        sld = _extract_sld(domain)
        if not sld:
            continue
        tld = _extract_tld(domain)
        if not tld:
            continue
        output.write(f'{sld},{tld},M\n')

    return output.getvalue().encode('utf-8')


def _build_session():
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(['GET']),
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session


def _download_and_format_csv(session, url, headers, timeout=(10, 120), max_attempts=4):
    for attempt in range(1, max_attempts + 1):
        try:
            with session.get(url, headers=headers, stream=True, timeout=timeout) as response:
                response.raise_for_status()
                lines = response.iter_lines(decode_unicode=True)
                return _format_domains_csv(lines)
        except (ChunkedEncodingError, RequestsConnectionError, Timeout) as error:
            if attempt == max_attempts:
                raise
            print(f'Retrying download after transient network error (attempt {attempt}/{max_attempts}): {error}')
        except Exception:
            raise


def handler(event, context):
    _ = event
    _ = context

    secret = boto3.client('secretsmanager')

    getsecret = secret.get_secret_value(
        SecretId = os.environ['SECRET_MGR_ARN']
    )

    login = json.loads(getsecret['SecretString'])

    github_url = os.environ['GITHUB_URL']
    headers = {'User-Agent': f'OSINT ({github_url})'}

    s3 = boto3.client('s3')
    session = _build_session()
    downloaded = []

    for item in ITEMS:

        print(f'Downloading {item} list...')

        url = 'https://domains-monitor.com/api/v1/'+login['token']+'/get/'+item+'/list/text/'

        fname = f'{item}.csv'
        body = _download_and_format_csv(session, url, headers)
        print(f'Download complete: {fname}')

        s3.put_object(
            Bucket = os.environ['S3_BUCKET_NAME'],
            Key = fname,
            Body = body,
            ContentType = 'text/csv'
        )

        downloaded.append(fname)

    #print('Downloading full list zip...')

    #full_zip_url = 'https://domains-monitor.com/api/v1/'+login['token']+'/get/full/list/zip/'
    #full_zip_name = f'{FULL_LIST_ITEM}.zip'
    #full_zip_path = f'/tmp/{full_zip_name}'

    #_download_to_file(session, full_zip_url, headers, full_zip_path)
    #print(f'Download complete: {full_zip_name}')

    #try:
    #    s3.upload_file(
    #        full_zip_path,
    #        os.environ['S3_ZIPPED_BUCKET_NAME'],
    #        full_zip_name,
    #        ExtraArgs = {
    #            'ContentType': 'application/zip'
    #        }
    #    )
    #finally:
    #    if os.path.exists(full_zip_path):
    #        os.remove(full_zip_path)
    #        print(f'Cleaned up: {full_zip_name}')

    session.close()

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Downloaded',
            'count': len(downloaded),
            'files': downloaded,
            #'zip_file': full_zip_name,
            #'zip_bucket': os.environ['S3_ZIPPED_BUCKET_NAME']
        })
    }