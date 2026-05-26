import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import boto3


logger = logging.getLogger(__name__)
S3_CLIENT = boto3.client('s3')

DOMAIN_SOURCE_DESCRIPTIONS = [
    ('A', 'c2intelfeeds', 'https://github.com/drb-ra/C2IntelFeeds'),
    ('B', 'certpl', 'https://cert.pl'),
    ('C', 'disposableemails', 'https://github.com/disposable-email-domains/disposable-email-domains'),
    ('D', 'inversiondnsbl', 'https://github.com/elliotwutingfeng/Inversion-DNSBL-Blocklists'),
    ('E', 'oisd', 'https://oisd.nl'),
    ('F', 'openphish', 'https://openphish.com'),
    ('G', 'phishingarmy', 'https://phishing.army'),
    ('H', 'phishtank', 'https://phishtank.com'),
    ('I', 'threatfox', 'https://threatfox.abuse.ch'),
    ('J', 'threatview', 'https://threatview.io'),
    ('K', 'ultimatehosts', 'https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist'),
    ('L', 'urlhaus', 'https://urlhaus.abuse.ch'),
    ('M', 'domainsmonitor', 'https://domains-monitor.com'),
]


def _normalize_domain(value: str) -> str:
    return (value or '').strip().lower().rstrip('.')


def _parse_domain_row(raw_line: str) -> tuple[str, str, str] | None:
    line = (raw_line or '').strip()
    if not line:
        return None

    parts = [part.strip() for part in line.split(',')]
    if len(parts) < 3:
        return None

    sld = _normalize_domain(parts[0])
    tld = _normalize_domain(parts[1])
    letter = (parts[2] or '').strip()
    if not sld or not tld or not letter:
        return None

    return sld, tld, letter


def _flush_rows(db: sqlite3.Connection, rows: list[tuple[str, str, str]]) -> None:
    if not rows:
        return
    db.executemany(
        'INSERT OR IGNORE INTO domains (sld, tld, letter) VALUES (?, ?, ?)',
        rows,
    )
    rows.clear()


def _upload_sqlite_to_s3(sqlite_path: str, bucket: str, key: str) -> None:
    S3_CLIENT.upload_file(sqlite_path, bucket, key)


def _upsert_domains_metadata(db: sqlite3.Connection, source_key: str) -> None:
    db.execute(
        'CREATE TABLE IF NOT EXISTS descriptions ('
        'id TEXT PRIMARY KEY, '
        'name TEXT NOT NULL, '
        'url TEXT NOT NULL'
        ')'
    )
    db.executemany(
        'INSERT OR REPLACE INTO descriptions (id, name, url) VALUES (?, ?, ?)',
        DOMAIN_SOURCE_DESCRIPTIONS,
    )

    db.execute(
        'CREATE TABLE IF NOT EXISTS lastupdated ('
        'name TEXT PRIMARY KEY, '
        'last TEXT NOT NULL, '
        'source_key TEXT NOT NULL'
        ')'
    )
    db.execute(
        'INSERT OR REPLACE INTO lastupdated (name, last, source_key) VALUES (?, ?, ?)',
        (
            'domains',
            datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            source_key,
        ),
    )


def _build_sqlite_from_csv(source_bucket: str, source_key: str) -> dict:
    source_basename = source_key.rsplit('/', 1)[-1]
    source_stem = source_basename.rsplit('.', 1)[0]
    sqlite_key = f'{source_stem}.sqlite3'
    sqlite_path = f'/tmp/{sqlite_key}'

    if os.path.exists(sqlite_path):
        os.remove(sqlite_path)

    db = sqlite3.connect(sqlite_path)
    db.execute('PRAGMA journal_mode = OFF')
    db.execute('PRAGMA synchronous = OFF')
    db.execute('PRAGMA temp_store = MEMORY')
    db.execute('PRAGMA locking_mode = EXCLUSIVE')
    db.execute('PRAGMA cache_size = -200000')
    db.execute('BEGIN')
    db.execute(
        'CREATE TABLE IF NOT EXISTS domains ('
        'pk INTEGER PRIMARY KEY, '
        'sld TEXT NOT NULL UNIQUE, '
        'tld TEXT NOT NULL, '
        'letter TEXT NOT NULL'
        ')'
    )

    rows = []
    inserted_rows = 0
    batch_size = 50_000
    source_object = S3_CLIENT.get_object(Bucket=source_bucket, Key=source_key)
    body = source_object['Body']
    for raw_line in body.iter_lines(chunk_size=1024 * 1024):
        if isinstance(raw_line, bytes):
            raw_line = raw_line.decode('utf-8', errors='replace')

        parsed = _parse_domain_row(raw_line)
        if parsed is None:
            continue

        rows.append(parsed)
        inserted_rows += 1
        if len(rows) >= batch_size:
            _flush_rows(db, rows)

    _flush_rows(db, rows)

    db.execute('CREATE INDEX IF NOT EXISTS idx_domains_letter ON domains (letter)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_domains_sld ON domains (sld)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_domains_tld ON domains (tld)')

    _upsert_domains_metadata(db, source_key)

    try:
        db.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS domains_fts USING fts5(sld, content='domains', content_rowid='pk', tokenize='trigram')"
        )
        db.execute("INSERT INTO domains_fts(domains_fts) VALUES ('rebuild')")
        print('Built FTS index: domains_fts')
    except sqlite3.OperationalError as error:
        print('FTS index unavailable, continuing without FTS: ' + str(error))

    db.execute('ANALYZE')
    db.execute('PRAGMA optimize')

    db.commit()
    db.close()

    if os.path.getsize(sqlite_path) == 0:
        raise RuntimeError(f'Generated SQLite file is empty for {source_key}')

    try:
        _upload_sqlite_to_s3(sqlite_path, os.environ['S3_SQLITE_BUCKET_NAME'], sqlite_key)
    finally:
        if os.path.exists(sqlite_path):
            os.remove(sqlite_path)

    return {
        'source_key': source_key,
        'sqlite_key': sqlite_key,
        'inserted_rows': inserted_rows,
    }


def handler(event, _context):
    failures = []
    processed = []

    for record in event.get('Records', []):
        message_id = record.get('messageId', '')
        current_source_bucket = ''
        current_source_key = ''
        try:
            body = json.loads(record.get('body', '{}'))
            for s3_record in body.get('Records', []):
                if s3_record.get('eventSource') != 'aws:s3':
                    continue

                event_name = s3_record.get('eventName', '')
                if not event_name.startswith('ObjectCreated:'):
                    continue

                source_bucket = s3_record.get('s3', {}).get('bucket', {}).get('name', '')
                source_key = unquote_plus(
                    s3_record.get('s3', {}).get('object', {}).get('key', '')
                )
                current_source_bucket = source_bucket
                current_source_key = source_key

                if not source_key.endswith('.csv'):
                    continue

                result = _build_sqlite_from_csv(
                    source_bucket,
                    source_key,
                )
                processed.append(result)
        except (OSError, ValueError, sqlite3.Error):
            logger.exception(
                'ERROR Failed processing SQS message %s for s3://%s/%s. Traceback follows.',
                message_id,
                current_source_bucket,
                current_source_key,
            )
            if message_id:
                failures.append({'itemIdentifier': message_id})

    return {
        'batchItemFailures': failures,
        'processed': processed,
    }
