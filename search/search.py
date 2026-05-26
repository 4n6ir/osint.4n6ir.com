import json
import logging
import os
import re
import sqlite3
import time

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


_DYNAMODB_CONFIG = Config(
    retries={
        'mode': 'adaptive',
        'max_attempts': 10,
    },
    max_pool_connections=64,
)

DYNAMODB = boto3.resource('dynamodb', config=_DYNAMODB_CONFIG)
DYNAMODB_CLIENT = boto3.client('dynamodb', config=_DYNAMODB_CONFIG)
S3_CLIENT = boto3.client('s3')
TABLE_CACHE = {}
TTL_SECONDS = 7 * 24 * 60 * 60

WATCHLIST_TABLE = os.environ.get('WATCHLIST_TABLE', 'watchlist')
OSINT_TABLE = os.environ.get('OSINT_TABLE', 'osint')
MALWARE_TABLE = os.environ.get('MALWARE_TABLE', 'malware')
DAILYREMOVE_TABLE = os.environ.get('DAILYREMOVE_TABLE', 'dailyremove')
DAILYUPDATE_TABLE = os.environ.get('DAILYUPDATE_TABLE', 'dailyupdate')
WEEKLYREMOVE_TABLE = os.environ.get('WEEKLYREMOVE_TABLE', 'weeklyremove')
WEEKLYUPDATE_TABLE = os.environ.get('WEEKLYUPDATE_TABLE', 'weeklyupdate')
MONTHLYREMOVE_TABLE = os.environ.get('MONTHLYREMOVE_TABLE', 'monthlyremove')
MONTHLYUPDATE_TABLE = os.environ.get('MONTHLYUPDATE_TABLE', 'monthlyupdate')
USERS_TABLE = os.environ.get('USERS_TABLE', 'users')
SQLITE_BUCKET_NAME = os.environ.get('S3_SQLITE_BUCKET_NAME', '')

# Ordered list of SQLite files searched when subscription=YES.
# Index 0 is the base OSINT file; the final entry is the threshold/count
# gate for watchlist writes when both osintsearch and subscription are YES.
SQLITE_FILES_ORDERED = [
    'osint.sqlite3',
    'malware.sqlite3',
    'dailyremove.sqlite3',
    'dailyupdate.sqlite3',
    'weeklyremove.sqlite3',
    'weeklyupdate.sqlite3',
    'monthlyremove.sqlite3',
    'monthlyupdate.sqlite3',
]
SQLITE_FINAL_KEY = SQLITE_FILES_ORDERED[-1]  # monthlyupdate.sqlite3

SQLITE_TARGET_TABLE_BY_KEY = {
    'osint.sqlite3': OSINT_TABLE,
    'malware.sqlite3': MALWARE_TABLE,
    'dailyremove.sqlite3': DAILYREMOVE_TABLE,
    'dailyupdate.sqlite3': DAILYUPDATE_TABLE,
    'weeklyremove.sqlite3': WEEKLYREMOVE_TABLE,
    'weeklyupdate.sqlite3': WEEKLYUPDATE_TABLE,
    'monthlyremove.sqlite3': MONTHLYREMOVE_TABLE,
    'monthlyupdate.sqlite3': MONTHLYUPDATE_TABLE,
}
ALL_SEARCH_TARGET_TABLES = [
    SQLITE_TARGET_TABLE_BY_KEY.get(s3_key, OSINT_TABLE)
    for s3_key in SQLITE_FILES_ORDERED
]

# Legacy single-file constants kept for backward-compat with env override.
TARGET_SQLITE_KEY = os.environ.get('TARGET_SQLITE_KEY', 'osint.sqlite3')


def _get_table(name):
    table = TABLE_CACHE.get(name)
    if table is None:
        table = DYNAMODB.Table(name)
        TABLE_CACHE[name] = table
    return table


def _ttl_epoch_7_days():
    return int(time.time()) + TTL_SECONDS


def _get_watchlist_item(email, domain):
    """Fetch watchlist record: pk=OSINT# sk=OSINT#<email>#<domain>#"""
    table = _get_table(WATCHLIST_TABLE)
    try:
        response = table.get_item(
            Key={
                'pk': 'OSINT#',
                'sk': f'OSINT#{email}#{domain}#',
            }
        )
        return response.get('Item')
    except (BotoCoreError, ClientError) as exc:
        LOGGER.exception('get_watchlist_item failed for email=%s domain=%s error=%s', email, domain, exc)
        return None

def _get_user_threshold(email):
    """Retrieve threshold from users table: pk=OSINT# sk=OSINT#<email>#"""
    table = _get_table(USERS_TABLE)
    try:
        response = table.get_item(
            Key={
                'pk': 'OSINT#',
                'sk': f'OSINT#{email}#',
            },
            ProjectionExpression='#th',
            ExpressionAttributeNames={'#th': 'threshold'},
        )
        item = response.get('Item', {})
        raw = item.get('threshold', 0)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0
    except (BotoCoreError, ClientError) as exc:
        LOGGER.exception('get_user_threshold failed for email=%s error=%s', email, exc)
        return 0


def _update_watchlist_permutations(email, domain, permutations):
    """Write updated permutations list back to the watchlist item."""
    table = _get_table(WATCHLIST_TABLE)
    try:
        table.update_item(
            Key={
                'pk': 'OSINT#',
                'sk': f'OSINT#{email}#{domain}#',
            },
            UpdateExpression='SET permutations = :p',
            ExpressionAttributeValues={':p': permutations},
        )
    except (BotoCoreError, ClientError) as exc:
        LOGGER.exception('update_watchlist_permutations failed for email=%s domain=%s error=%s', email, domain, exc)


def _sqlite_local_path(s3_key):
    safe = s3_key.replace('/', '_')
    return f'/tmp/{safe}'


def _sqlite_local_metadata_path(s3_key):
    return _sqlite_local_path(s3_key) + '.meta.json'


def _sqlite_local_metadata(s3_key):
    meta_path = _sqlite_local_metadata_path(s3_key)
    if not os.path.exists(meta_path):
        return None

    try:
        with open(meta_path, 'r', encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _sqlite_store_local_metadata(s3_key, etag, size):
    meta_path = _sqlite_local_metadata_path(s3_key)
    with open(meta_path, 'w', encoding='utf-8') as handle:
        json.dump({'etag': etag, 'size': size}, handle)


def _sqlite_download_local_copy(s3_key):
    if not SQLITE_BUCKET_NAME:
        raise FileNotFoundError('S3_SQLITE_BUCKET_NAME is not configured')

    local_path = _sqlite_local_path(s3_key)
    metadata = S3_CLIENT.head_object(Bucket=SQLITE_BUCKET_NAME, Key=s3_key)
    etag = metadata.get('ETag', '')
    size = int(metadata.get('ContentLength', 0) or 0)
    local_metadata = _sqlite_local_metadata(s3_key)

    if (
        os.path.exists(local_path)
        and local_metadata is not None
        and local_metadata.get('etag') == etag
        and int(local_metadata.get('size', -1)) == size
    ):
        return local_path

    temp_path = local_path + '.download'
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)

        LOGGER.info(
            'sqlite_download_start bucket=%s key=%s local_path=%s size=%d',
            SQLITE_BUCKET_NAME,
            s3_key,
            local_path,
            size,
        )
        S3_CLIENT.download_file(SQLITE_BUCKET_NAME, s3_key, temp_path)

        downloaded_size = os.path.getsize(temp_path)
        if downloaded_size <= 0:
            raise FileNotFoundError(
                f'Downloaded SQLite file is empty for s3://{SQLITE_BUCKET_NAME}/{s3_key}'
            )

        os.replace(temp_path, local_path)
        _sqlite_store_local_metadata(s3_key, etag, downloaded_size)
        LOGGER.info(
            'sqlite_download_done bucket=%s key=%s local_path=%s size=%d',
            SQLITE_BUCKET_NAME,
            s3_key,
            local_path,
            downloaded_size,
        )
        return local_path
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def _sqlite_connect(s3_key):
    sqlite_path = _sqlite_download_local_copy(s3_key)

    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f'SQLite not found at {sqlite_path}')

    conn = sqlite3.connect(f'file:{sqlite_path}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA query_only = ON')
    conn.execute('PRAGMA temp_store = MEMORY')
    conn.execute('PRAGMA cache_size = -200000')
    return conn


def _sqlite_cleanup_local_copy():
    all_keys = set(SQLITE_FILES_ORDERED) | {TARGET_SQLITE_KEY}
    for s3_key in all_keys:
        _sqlite_delete_one(s3_key)


def _sqlite_delete_one(s3_key):
    """Remove a single SQLite file and its metadata from /tmp to free disk space."""
    for path in (_sqlite_local_path(s3_key), _sqlite_local_metadata_path(s3_key)):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError as exc:
            LOGGER.warning('sqlite_cleanup_failed path=%s error=%s', path, exc)


def _sqlite_has_fts(conn):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='domains_fts'"
    ).fetchone()
    return row is not None


def _sqlite_all_terms(sld, enabled_permutations):
    terms = [sld]
    for term in sorted(enabled_permutations):
        if term and term not in terms:
            terms.append(term)
    return terms


def _sqlite_can_use_fts_for_terms(terms, use_fts):
    return use_fts and all(len(term) >= 3 for term in terms)


def _sqlite_build_exact_where(terms):
    placeholders = ', '.join('?' for _ in terms)
    return f'd.sld IN ({placeholders})', tuple(terms)


def _sqlite_build_contains_where(terms, use_fts):
    if _sqlite_can_use_fts_for_terms(terms, use_fts):
        match_expression = ' OR '.join(f'"{term.replace(chr(34), chr(34) + chr(34))}"' for term in terms)
        return 'f.sld MATCH ?', (match_expression,), True

    or_clause = ' OR '.join('d.sld LIKE ?' for _ in terms)
    params = tuple(f'%{term}%' for term in terms)
    return or_clause, params, False


def _sqlite_count_rows_by_term(rows, terms, exact_match):
    counts = {term: 0 for term in terms}
    for row in rows:
        row_sld = str(row['sld']).lower()
        for term in terms:
            if exact_match:
                if row_sld == term:
                    counts[term] += 1
            elif term in row_sld:
                counts[term] += 1
    return counts


def _sqlite_group_rows_by_term(rows, terms, exact_match):
    rows_by_term = {term: [] for term in terms}
    for row in rows:
        item = (row['sld'], row['tld'], row['url'] or '')
        row_sld = str(row['sld']).lower()
        for term in terms:
            if exact_match:
                if row_sld == term:
                    rows_by_term[term].append(item)
            elif term in row_sld:
                rows_by_term[term].append(item)
    return rows_by_term


def _normalize_source_url(value):
    normalized = str(value or '').strip()
    if not normalized:
        return ''

    return normalized


def _is_debug_metrics_enabled():
    return str(os.environ.get('SEARCH_DEBUG_METRICS', '')).strip().lower() in {'1', 'true', 'yes', 'on'}


def _debug_metrics_snapshot(email, domain, s3_key, sqlite_results, permutations):
    if not _is_debug_metrics_enabled():
        return

    domains_with_multi_sources = sum(
        1
        for _fqdn, result_entry in sqlite_results.items()
        if len(_coerce_source_urls(result_entry.get('sources', []))) > 1
    )
    permutation_snapshot = [
        {
            'term': str(p.get('permutation', '')),
            'enabled': str(p.get('enabled', 'ON')),
            'unique_domains': int(p.get('unique_domains', 0) or 0),
            'unique_sources': int(p.get('unique_sources', 0) or 0),
        }
        for p in permutations
    ]
    LOGGER.info(
        'metrics_snapshot email=%s domain=%s s3_key=%s result_domains=%d domains_with_multi_sources=%d permutations=%s',
        email,
        domain,
        s3_key,
        len(sqlite_results),
        domains_with_multi_sources,
        json.dumps(permutation_snapshot, separators=(',', ':')),
    )


def _coerce_source_urls(value):
    if isinstance(value, list):
        return [_normalize_source_url(item) for item in value if _normalize_source_url(item)]

    if isinstance(value, tuple):
        return [_normalize_source_url(item) for item in value if _normalize_source_url(item)]

    normalized = _normalize_source_url(value)
    return [normalized] if normalized else []


def _merge_source_urls(*values):
    merged = []
    for value in values:
        for source_url in _coerce_source_urls(value):
            if source_url not in merged:
                merged.append(source_url)
    return merged


def _coerce_permutations(value):
    if isinstance(value, list):
        normalized = []
        for item in value:
            term = str(item or '').strip().lower()
            if term and term not in normalized:
                normalized.append(term)
        return normalized

    if isinstance(value, tuple):
        return _coerce_permutations(list(value))

    term = str(value or '').strip().lower()
    return [term] if term else []


def _merge_permutations(*values):
    merged = []
    for value in values:
        for term in _coerce_permutations(value):
            if term not in merged:
                merged.append(term)
    return merged


def _result_contains_sld(result_sld, search_sld):
    normalized_result = str(result_sld or '').strip().lower().rstrip('.')
    normalized_search = str(search_sld or '').strip().lower().rstrip('.')
    if not normalized_result or not normalized_search:
        return False
    return normalized_search in normalized_result


def _normalize_result_domain_parts(rsld, rtld):
    normalized_sld = str(rsld or '').strip().lower().rstrip('.')
    normalized_tld = str(rtld or '').strip().lower().strip('.')

    # Some feeds store the full domain in sld and leave tld empty.
    if normalized_sld and not normalized_tld and '.' in normalized_sld:
        fqdn = normalized_sld
        parsed_sld, parsed_tld = fqdn.split('.', 1)
        if parsed_sld and parsed_tld:
            return parsed_sld, parsed_tld, fqdn

    if not normalized_sld or not normalized_tld:
        return '', '', ''

    fqdn = f'{normalized_sld}.{normalized_tld}'
    return normalized_sld, normalized_tld, fqdn


def _sld_matches_permutation(sld_value, permutation_value):
    normalized_sld = str(sld_value or '').strip().lower().rstrip('.')
    normalized_permutation = str(permutation_value or '').strip().lower().rstrip('.')
    if not normalized_sld or not normalized_permutation:
        return False

    if normalized_sld == normalized_permutation:
        return True

    sld_tokens = [token for token in re.split(r'[^a-z0-9]+', normalized_sld) if token]
    return normalized_permutation in sld_tokens


def _add_sqlite_result(sqlite_results, rsld, rtld, source_url, matched_term='', search_sld=''):
    normalized_sld, normalized_tld, fqdn = _normalize_result_domain_parts(rsld, rtld)
    if not fqdn:
        return

    existing_entry = sqlite_results.get(fqdn)
    # Record the query term that caused SQLite to return this row.  SQLite's
    # query is the authority; we do not re-filter here so that permutation
    # attribution is always faithful to what was actually searched.
    matched_permutations = _coerce_permutations(matched_term) if matched_term else []
    sld_found = 'YES' if _result_contains_sld(normalized_sld, search_sld) else 'NO'

    if existing_entry is None:
        sqlite_results[fqdn] = {
            'sld': normalized_sld,
            'tld': normalized_tld,
            'sources': _merge_source_urls(source_url),
            'matched_permutations': matched_permutations,
            'sld_found': sld_found,
        }
        return

    sqlite_results[fqdn] = {
        'sld': normalized_sld,
        'tld': normalized_tld,
        'sources': _merge_source_urls(existing_entry.get('sources', []), source_url),
        'matched_permutations': _merge_permutations(
            existing_entry.get('matched_permutations', []),
            matched_permutations,
        ),
        'sld_found': 'YES' if (
            str(existing_entry.get('sld_found', 'NO')).strip().upper() == 'YES'
            or sld_found == 'YES'
        ) else 'NO',
    }


def _update_permutation_metrics(aggregate_metrics, term, rows):
    metrics = aggregate_metrics.setdefault(term, {'domains': set(), 'sources': set()})
    for rsld, rtld, url in rows:
        _, _, fqdn = _normalize_result_domain_parts(rsld, rtld)
        if not fqdn:
            continue

        metrics['domains'].add(fqdn)
        normalized_url = _normalize_source_url(url)
        if normalized_url:
            metrics['sources'].add(normalized_url)

    return metrics


def _update_permutation_metrics_from_results(aggregate_metrics, term, sqlite_results):
    metrics = aggregate_metrics.setdefault(term, {'domains': set(), 'sources': set()})
    normalized_term = str(term or '').strip().lower()
    if not normalized_term:
        return metrics

    for fqdn, result_entry in sqlite_results.items():
        if normalized_term not in _coerce_permutations(result_entry.get('matched_permutations', [])):
            continue

        metrics['domains'].add(fqdn)
        for normalized_url in _coerce_source_urls(result_entry.get('sources', [])):
            metrics['sources'].add(normalized_url)

    return metrics


def _build_post_sync_table_results(sqlite_results, stored_items):
    """
    Build expected post-sync table state for results retained in this run.

    Output shape:
    {
      fqdn: {
        'sld': sld,
        'tld': tld,
        'sources': [source_urls...],
        'matched_permutations': [permutation_terms...],
        'sld_found': 'YES'|'NO',
      }
    }
    """
    post_sync_results = {}
    for fqdn, result_entry in sqlite_results.items():
        existing_sources = []
        existing_permutations = []
        existing_sld_found = 'NO'
        existing_item = stored_items.get(fqdn)
        if isinstance(existing_item, dict):
            existing_sources = _coerce_source_urls(existing_item.get('sources'))
            existing_permutations = _coerce_permutations(existing_item.get('matched_permutations'))
            existing_sld_found = str(existing_item.get('sld_found', 'NO')).strip().upper()

        post_sync_results[fqdn] = {
            'sld': str(result_entry.get('sld', '')).strip().lower(),
            'tld': str(result_entry.get('tld', '')).strip().lower(),
            'sources': _merge_source_urls(existing_sources, result_entry.get('sources', [])),
            'matched_permutations': _merge_permutations(
                existing_permutations,
                result_entry.get('matched_permutations', []),
            ),
            'sld_found': 'YES' if (
                existing_sld_found == 'YES'
                or str(result_entry.get('sld_found', 'NO')).strip().upper() == 'YES'
            ) else 'NO',
        }

    return post_sync_results


def _collect_term_match_domains(rows_by_term, terms):
    matched = {}
    for term in terms:
        term_matches = set()
        for rsld, rtld, _url in rows_by_term.get(term, []):
            _, _, fqdn = _normalize_result_domain_parts(rsld, rtld)
            if fqdn:
                term_matches.add(fqdn)
        matched[term] = term_matches
    return matched


def _update_permutation_metrics_from_table_results(
    aggregate_metrics,
    permutations,
    table_results,
):
    """
    Update cumulative permutation metrics from post-sync table results.

    Uses persisted per-domain permutation matches as the source of truth.
    """
    for permutation_entry in permutations:
        term = str(permutation_entry.get('permutation', '')).strip().lower()
        metrics = aggregate_metrics.setdefault(term, {'domains': set(), 'sources': set()})
        if term:
            for fqdn, result_entry in table_results.items():
                matched_permutations = _coerce_permutations(result_entry.get('matched_permutations', []))
                if term not in matched_permutations:
                    continue

                metrics['domains'].add(fqdn)
                for normalized_url in _coerce_source_urls(result_entry.get('sources', [])):
                    metrics['sources'].add(normalized_url)

        permutation_entry['unique_domains'] = int(len(metrics['domains']))
        permutation_entry['unique_sources'] = int(len(metrics['sources']))


def _refresh_permutation_counts_from_tables(email, domain, permutations, table_names):
    aggregate_table_metrics = {}
    ordered_tables = []
    for table_name in table_names:
        if table_name and table_name not in ordered_tables:
            ordered_tables.append(table_name)

    for table_name in ordered_tables:
        stored_items = _list_table_domains(table_name, email, domain)
        table_results = {}
        for fqdn, stored_item in stored_items.items():
            result_sld, result_tld, _normalized_fqdn = _normalize_result_domain_parts(fqdn, '')
            if not result_sld or not result_tld:
                continue

            table_results[fqdn] = {
                'sld': result_sld,
                'tld': result_tld,
                'sources': _coerce_source_urls(stored_item.get('sources', [])),
                'matched_permutations': _coerce_permutations(stored_item.get('matched_permutations', [])),
                'sld_found': 'YES' if str(stored_item.get('sld_found', 'NO')).strip().upper() == 'YES' else 'NO',
            }

        _update_permutation_metrics_from_table_results(
            aggregate_table_metrics,
            permutations,
            table_results,
        )


def _extract_dynamodb_source_urls(item):
    source_attr = item.get('source')
    if not isinstance(source_attr, dict):
        return []

    if 'S' in source_attr:
        return _coerce_source_urls(source_attr.get('S'))

    if 'SS' in source_attr and isinstance(source_attr.get('SS'), list):
        return _coerce_source_urls(source_attr.get('SS'))

    if 'L' in source_attr and isinstance(source_attr.get('L'), list):
        values = []
        for element in source_attr.get('L', []):
            if isinstance(element, dict) and 'S' in element:
                values.append(element.get('S'))
        return _coerce_source_urls(values)

    return []


def _extract_dynamodb_permutations(item):
    permutation_attr = item.get('permutations')
    if not isinstance(permutation_attr, dict):
        return []

    if 'S' in permutation_attr:
        return _coerce_permutations(permutation_attr.get('S'))

    if 'SS' in permutation_attr and isinstance(permutation_attr.get('SS'), list):
        return _coerce_permutations(permutation_attr.get('SS'))

    if 'L' in permutation_attr and isinstance(permutation_attr.get('L'), list):
        values = []
        for element in permutation_attr.get('L', []):
            if isinstance(element, dict) and 'S' in element:
                values.append(element.get('S'))
        return _coerce_permutations(values)

    return []


def _extract_dynamodb_sld_found(item):
    sld_found_attr = item.get('sldfound')
    if isinstance(sld_found_attr, dict) and 'S' in sld_found_attr:
        value = str(sld_found_attr.get('S', '')).strip().upper()
        return 'YES' if value == 'YES' else 'NO'
    return 'NO'


def _sqlite_count_terms(s3_key, sld, enabled_permutations):
    match_mode = 'exact' if len(sld) < 5 else 'contains'
    started = time.perf_counter()
    conn = _sqlite_connect(s3_key)
    try:
        use_fts = _sqlite_has_fts(conn)
        all_terms = _sqlite_all_terms(sld, enabled_permutations)
        LOGGER.info(
            'sqlite_count_start s3_key=%s sld=%s mode=%s enabled_permutations=%d use_fts=%s',
            s3_key,
            sld,
            match_mode,
            len(enabled_permutations),
            use_fts,
        )
        if len(sld) < 5:
            where_clause, params = _sqlite_build_exact_where(all_terms)
            rows = conn.execute(
                f'SELECT d.sld FROM domains d WHERE {where_clause}',
                params,
            ).fetchall()
            counts = _sqlite_count_rows_by_term(rows, all_terms, True)
        else:
            where_clause, params, using_fts_query = _sqlite_build_contains_where(all_terms, use_fts)
            if using_fts_query:
                rows = conn.execute(
                    'SELECT d.sld FROM domains_fts f '
                    'JOIN domains d ON d.pk = f.rowid '
                    f'WHERE {where_clause}',
                    params,
                ).fetchall()
            else:
                rows = conn.execute(
                    f'SELECT d.sld FROM domains d WHERE {where_clause}',
                    params,
                ).fetchall()
            counts = _sqlite_count_rows_by_term(rows, all_terms, False)
        LOGGER.info(
            'sqlite_count_done s3_key=%s sld=%s terms=%d elapsed_ms=%d',
            s3_key,
            sld,
            len(all_terms),
            int((time.perf_counter() - started) * 1000),
        )
        return counts
    finally:
        conn.close()


def _sqlite_fetch_rows(s3_key, sld, enabled_permutations):
    match_mode = 'exact' if len(sld) < 5 else 'contains'
    started = time.perf_counter()
    conn = _sqlite_connect(s3_key)
    try:
        use_fts = _sqlite_has_fts(conn)
        all_terms = _sqlite_all_terms(sld, enabled_permutations)
        LOGGER.info(
            'sqlite_fetch_start s3_key=%s sld=%s mode=%s enabled_permutations=%d use_fts=%s',
            s3_key,
            sld,
            match_mode,
            len(enabled_permutations),
            use_fts,
        )
        if len(sld) < 5:
            where_clause, params = _sqlite_build_exact_where(all_terms)
            rows = conn.execute(
                'SELECT d.sld, d.tld, desc.url '
                'FROM domains d '
                'INNER JOIN descriptions desc ON desc.id = d.letter '
                f'WHERE {where_clause}',
                params,
            ).fetchall()
            rows_by_term = _sqlite_group_rows_by_term(rows, all_terms, True)
        else:
            where_clause, params, using_fts_query = _sqlite_build_contains_where(all_terms, use_fts)
            if using_fts_query:
                rows = conn.execute(
                    'SELECT d.sld, d.tld, desc.url '
                    'FROM domains_fts f '
                    'JOIN domains d ON d.pk = f.rowid '
                    'INNER JOIN descriptions desc ON desc.id = d.letter '
                    f'WHERE {where_clause}',
                    params,
                ).fetchall()
            else:
                rows = conn.execute(
                    'SELECT d.sld, d.tld, desc.url '
                    'FROM domains d '
                    'INNER JOIN descriptions desc ON desc.id = d.letter '
                    f'WHERE {where_clause}',
                    params,
                ).fetchall()
            rows_by_term = _sqlite_group_rows_by_term(rows, all_terms, False)
        LOGGER.info(
            'sqlite_fetch_done s3_key=%s sld=%s terms=%d elapsed_ms=%d',
            s3_key,
            sld,
            len(all_terms),
            int((time.perf_counter() - started) * 1000),
        )
        return rows_by_term
    finally:
        conn.close()


def _list_table_domains(table_name, email, domain):
    """
    Return items already stored in osint table:
      pk=OSINT# sk begins_with OSINT#<email>#<domain>#

        Returns dict:
        {
            result_fqdn: {
                'sk': sk,
                'sources': [url, ...],
                'matched_permutations': [term, ...],
                'sld_found': 'YES'|'NO',
            }
        }
    """
    stored = {}
    try:
        paginator = DYNAMODB_CLIENT.get_paginator('query')
        pages = paginator.paginate(
            TableName=table_name,
            KeyConditionExpression='pk = :pk AND begins_with(sk, :prefix)',
            ExpressionAttributeValues={
                ':pk': {'S': 'OSINT#'},
                ':prefix': {'S': f'OSINT#{email}#{domain}#'},
            },
            ProjectionExpression='sk, #source, #permutations, #sldfound',
            ExpressionAttributeNames={
                '#source': 'source',
                '#permutations': 'permutations',
                '#sldfound': 'sldfound',
            },
        )
        for page in pages:
            for item in page.get('Items', []):
                sk = item['sk']['S']
                # sk format: OSINT#<email>#<domain>#<result_fqdn>#
                parts = sk.rstrip('#').split('#')
                if len(parts) >= 4:
                    result_value = parts[-1]
                    source_urls = _extract_dynamodb_source_urls(item)
                    matched_permutations = _extract_dynamodb_permutations(item)
                    sld_found = _extract_dynamodb_sld_found(item)
                    existing = stored.get(result_value)
                    if existing is None:
                        stored[result_value] = {
                            'sk': sk,
                            'sources': source_urls,
                            'matched_permutations': matched_permutations,
                            'sld_found': sld_found,
                        }
                    else:
                        existing['sources'] = _merge_source_urls(existing.get('sources', []), source_urls)
                        existing['matched_permutations'] = _merge_permutations(
                            existing.get('matched_permutations', []),
                            matched_permutations,
                        )
                        existing['sld_found'] = 'YES' if (
                            str(existing.get('sld_found', 'NO')).strip().upper() == 'YES'
                            or sld_found == 'YES'
                        ) else 'NO'
    except (BotoCoreError, ClientError) as exc:
        LOGGER.exception(
            'list_table_domains failed table=%s email=%s domain=%s error=%s',
            table_name,
            email,
            domain,
            exc,
        )
    return stored


def _sync_table(email, domain, sqlite_results, stored_items, table_name):
    """
    Batch-sync the osint table to reduce request count over the VPC gateway.

        sqlite_results:
        {
            fqdn: {
                'sld': sld,
                'tld': tld,
                'sources': [url, ...],
                'matched_permutations': [term, ...],
                'sld_found': 'YES'|'NO',
            }
        }
        stored_items: {fqdn: {'sk': sk, 'sources': [url, ...], ...}}
    """
    table = _get_table(table_name)
    added = 0
    removed = 0

    LOGGER.info(
        'sync_table_start table=%s email=%s domain=%s sqlite_results=%d existing=%d',
        table_name,
        email,
        domain,
        len(sqlite_results),
        len(stored_items),
    )

    try:
        with table.batch_writer() as batch:
            for fqdn, result_entry in sqlite_results.items():
                result_sld = str(result_entry.get('sld', '')).strip().lower()
                result_tld = str(result_entry.get('tld', '')).strip().lower()
                source_urls = _coerce_source_urls(result_entry.get('sources', []))
                matched_permutations = _coerce_permutations(result_entry.get('matched_permutations', []))
                sld_found = 'YES' if str(result_entry.get('sld_found', 'NO')).strip().upper() == 'YES' else 'NO'

                existing_item = stored_items.get(fqdn)
                merged_source_urls = _merge_source_urls(source_urls)
                merged_permutations = _merge_permutations(matched_permutations)
                merged_sld_found = sld_found

                if existing_item is not None:
                    existing_sources = []
                    existing_permutations = []
                    existing_sld_found = 'NO'
                    if isinstance(existing_item, dict):
                        existing_sources = _coerce_source_urls(existing_item.get('sources'))
                        existing_permutations = _coerce_permutations(existing_item.get('matched_permutations'))
                        existing_sld_found = str(existing_item.get('sld_found', 'NO')).strip().upper()

                    merged_source_urls = _merge_source_urls(existing_sources, merged_source_urls)
                    merged_permutations = _merge_permutations(existing_permutations, merged_permutations)
                    merged_sld_found = 'YES' if (existing_sld_found == 'YES' or merged_sld_found == 'YES') else 'NO'

                    if (
                        merged_source_urls == existing_sources
                        and merged_permutations == existing_permutations
                        and merged_sld_found == existing_sld_found
                    ):
                        continue

                batch.put_item(
                    Item={
                        'pk': 'OSINT#',
                        'sk': f'OSINT#{email}#{domain}#{fqdn}#',
                        'email': email,
                        'domain': domain,
                        'result': f'{result_sld}.{result_tld}',
                        'source': merged_source_urls,
                        'permutations': merged_permutations,
                        'sldfound': merged_sld_found,
                        'ttl': _ttl_epoch_7_days(),
                    }
                )
                if existing_item is None:
                    added += 1

            for fqdn in stored_items:
                if fqdn in sqlite_results:
                    continue
                batch.delete_item(
                    Key={
                        'pk': 'OSINT#',
                        'sk': f'OSINT#{email}#{domain}#{fqdn}#',
                    }
                )
                removed += 1
    except (BotoCoreError, ClientError) as exc:
        LOGGER.exception(
            'sync_table failed table=%s email=%s domain=%s error=%s',
            table_name,
            email,
            domain,
            exc,
        )

    LOGGER.info(
        'sync_table_done table=%s email=%s domain=%s added=%d removed=%d',
        table_name,
        email,
        domain,
        added,
        removed,
    )
    return added, removed


def _collect_sqlite_results(s3_key, sld, permutations):
    """
    Search one SQLite file and return accumulated domain results.
    Does NOT modify permutation state and does NOT apply threshold logic.
    Returns dict keyed by FQDN with result metadata used for table sync.
    """
    enabled_terms = {
        p['permutation'] for p in permutations
        if p['enabled'] == 'ON' and p['permutation']
    }
    rows_by_term = _sqlite_fetch_rows(s3_key, sld, enabled_terms)
    sqlite_results = {}
    for (rsld, rtld, url) in rows_by_term.get(sld, []):
        _add_sqlite_result(sqlite_results, rsld, rtld, url, search_sld=sld)
    for p in permutations:
        if p['enabled'] != 'ON':
            continue
        term = p['permutation']
        for (rsld, rtld, url) in rows_by_term.get(term, []):
            _add_sqlite_result(sqlite_results, rsld, rtld, url, matched_term=term, search_sld=sld)
    return sqlite_results


def _apply_threshold_and_fetch(
    s3_key,
    sld,
    permutations,
    threshold,
    email,
    domain,
    aggregate_metrics,
):
    """
        Fetch rows in one SQLite file, apply threshold logic, and compute metrics.

        - Adds per-file unique domain/source metrics into aggregate_metrics.
        - Updates permutations[*]['unique_domains'] and ['unique_sources'] from aggregate_metrics.
        - Disables any enabled permutation whose cumulative unique_domains exceeds threshold.
        - Re-runs the SQLite query after any auto-disable so persisted results
          include only currently enabled permutations.
        - Returns {fqdn: (sld, tld, [source_urls...])} for the file.
    """
    while True:
        enabled_terms = {
            p['permutation'] for p in permutations
            if p['enabled'] == 'ON' and p['permutation']
        }

        queried_terms = set(enabled_terms)
        rows_by_term = _sqlite_fetch_rows(s3_key, sld, enabled_terms)

        sqlite_results = {}
        for (rsld, rtld, url) in rows_by_term.get(sld, []):
            _add_sqlite_result(sqlite_results, rsld, rtld, url, search_sld=sld)
        for term in queried_terms:
            for (rsld, rtld, url) in rows_by_term.get(term, []):
                _add_sqlite_result(
                    sqlite_results,
                    rsld,
                    rtld,
                    url,
                    matched_term=term,
                    search_sld=sld,
                )

        preview_metrics = {}
        for p in permutations:
            term = p['permutation']
            existing_metrics = aggregate_metrics.setdefault(term, {'domains': set(), 'sources': set()})
            next_metrics = {
                'domains': set(existing_metrics['domains']),
                'sources': set(existing_metrics['sources']),
            }

            if term in queried_terms:
                for fqdn, result_entry in sqlite_results.items():
                    if term not in _coerce_permutations(result_entry.get('matched_permutations', [])):
                        continue
                    next_metrics['domains'].add(fqdn)
                    for normalized_url in _coerce_source_urls(result_entry.get('sources', [])):
                        next_metrics['sources'].add(normalized_url)

            preview_metrics[term] = next_metrics
            p['unique_domains'] = int(len(next_metrics['domains']))
            p['unique_sources'] = int(len(next_metrics['sources']))

        if threshold > 0:
            exceeded_terms = [
                p['permutation']
                for p in permutations
                if p['enabled'] == 'ON' and p['unique_domains'] > threshold
            ]
            if exceeded_terms:
                LOGGER.info(
                    'threshold_exceeded s3_key=%s email=%s domain=%s threshold=%d terms=%s',
                    s3_key,
                    email,
                    domain,
                    threshold,
                    exceeded_terms,
                )
                for p in permutations:
                    if p['enabled'] == 'ON' and p['permutation'] in exceeded_terms:
                        p['enabled'] = 'OFF'
                continue

        for term, term_metrics in preview_metrics.items():
            aggregate_metrics[term] = term_metrics

        _debug_metrics_snapshot(email, domain, s3_key, sqlite_results, permutations)
        return sqlite_results


def _process_message(domain, email, subscription, osintsearch):
    """Core search logic for one SQS message.

    Behaviour matrix
    ----------------
    osintsearch=YES  subscription=NO  → single-file path (osint.sqlite3).
                                        Threshold applied.
                                        Watchlist counts refreshed from all tables.
    osintsearch=YES  subscription=YES → all 8 SQLite files searched in order.
                                        Threshold + auto-disable logic applied using
                                        cumulative counts across files;
                                        permutation state (enabled/disabled) carries
                                        forward across files.  Watchlist counts written
                                        only after the final file (monthlyupdate.sqlite3).
    osintsearch=NO   subscription=YES → files 1-7 searched (osint.sqlite3 skipped).
                                        No threshold checking. Watchlist counts refreshed
                                        from all tables after file sync completes.
    anything else                     → skipped.
    """

    subscription_upper = str(subscription or '').strip().upper()
    osintsearch_upper = str(osintsearch or '').strip().upper()

    LOGGER.info(
        'process_message_start email=%s domain=%s subscription=%s osintsearch=%s',
        email,
        domain,
        subscription_upper,
        osintsearch_upper,
    )

    # ---------------------------------------------------------------
    # Case A: subscription=NO, osintsearch=YES  (original behaviour)
    # ---------------------------------------------------------------
    if subscription_upper == 'NO' and osintsearch_upper == 'YES':
        watchlist_item = _get_watchlist_item(email, domain)
        if not watchlist_item:
            LOGGER.warning('process_message_skip email=%s domain=%s reason=watchlist_item_missing', email, domain)
            return

        sld = str(watchlist_item.get('sld', '')).strip().lower() or domain.split('.')[0].lower()
        raw_permutations = watchlist_item.get('permutations', [])
        permutations = [
            {
                'permutation': str(p.get('permutation', '')).strip().lower(),
                'enabled': str(p.get('enabled', 'ON')).strip().upper(),
                'unique_domains': 0,
                'unique_sources': 0,
            }
            for p in raw_permutations if isinstance(p, dict)
        ]

        LOGGER.info(
            'watchlist_loaded email=%s domain=%s sld=%s permutations_total=%d permutations_enabled=%d',
            email, domain, sld, len(permutations),
            sum(1 for p in permutations if p['enabled'] == 'ON'),
        )

        threshold = _get_user_threshold(email)
        LOGGER.info('threshold_loaded email=%s domain=%s threshold=%d', email, domain, threshold)

        aggregate_metrics = {}

        sqlite_results = _apply_threshold_and_fetch(
            TARGET_SQLITE_KEY, sld, permutations, threshold, email, domain,
            aggregate_metrics,
        )

        stored_items = _list_table_domains(OSINT_TABLE, email, domain)
        added_count, removed_count = _sync_table(
            email,
            domain,
            sqlite_results,
            stored_items,
            OSINT_TABLE,
        )

        # Persist counts from DynamoDB query source of truth across all
        # searched output tables, not just osint.
        _refresh_permutation_counts_from_tables(
            email,
            domain,
            permutations,
            ALL_SEARCH_TARGET_TABLES,
        )
        _update_watchlist_permutations(email, domain, permutations)

        LOGGER.info(
            'process_message_done email=%s domain=%s sqlite_results=%d previous=%d added=%d removed=%d',
            email, domain, len(sqlite_results), len(stored_items), added_count, removed_count,
        )
        return

    # ---------------------------------------------------------------
    # Cases B & C: subscription=YES
    # ---------------------------------------------------------------
    if subscription_upper == 'YES':
        watchlist_item = _get_watchlist_item(email, domain)
        if not watchlist_item:
            LOGGER.warning('process_message_skip email=%s domain=%s reason=watchlist_item_missing', email, domain)
            return

        sld = str(watchlist_item.get('sld', '')).strip().lower() or domain.split('.')[0].lower()
        raw_permutations = watchlist_item.get('permutations', [])
        permutations = [
            {
                'permutation': str(p.get('permutation', '')).strip().lower(),
                'enabled': str(p.get('enabled', 'ON')).strip().upper(),
                'unique_domains': 0,
                'unique_sources': 0,
            }
            for p in raw_permutations if isinstance(p, dict)
        ]

        LOGGER.info(
            'watchlist_loaded email=%s domain=%s sld=%s permutations_total=%d permutations_enabled=%d',
            email, domain, sld, len(permutations),
            sum(1 for p in permutations if p['enabled'] == 'ON'),
        )

        total_added = 0
        total_removed = 0
        files_synced = 0

        if osintsearch_upper == 'YES':
            # Case B: threshold + auto-disable across all files; watchlist counts
            # written only after the final file.
            threshold = _get_user_threshold(email)
            LOGGER.info('threshold_loaded email=%s domain=%s threshold=%d', email, domain, threshold)

            aggregate_metrics = {}
            for s3_key in SQLITE_FILES_ORDERED:
                is_final = (s3_key == SQLITE_FINAL_KEY)
                LOGGER.info(
                    'subscription_search_file email=%s domain=%s s3_key=%s is_final=%s',
                    email, domain, s3_key, is_final,
                )
                file_results = _apply_threshold_and_fetch(
                    s3_key,
                    sld,
                    permutations,
                    threshold,
                    email,
                    domain,
                    aggregate_metrics,
                )

                target_table = SQLITE_TARGET_TABLE_BY_KEY.get(s3_key, OSINT_TABLE)
                stored_items = _list_table_domains(target_table, email, domain)
                added_count, removed_count = _sync_table(
                    email,
                    domain,
                    file_results,
                    stored_items,
                    target_table,
                )
                total_added += added_count
                total_removed += removed_count
                files_synced += 1

                if is_final:
                    # Final file: write complete permutation state + counts
                    # derived from DynamoDB queries across all target tables.
                    _refresh_permutation_counts_from_tables(
                        email,
                        domain,
                        permutations,
                        ALL_SEARCH_TARGET_TABLES,
                    )
                    _update_watchlist_permutations(email, domain, permutations)

                # Free disk space before downloading the next file.
                _sqlite_delete_one(s3_key)

        else:
            # Case C: subscription=YES, osintsearch=NO — skip osint.sqlite3,
            # no threshold. Refresh watchlist permutation counts from all tables
            # after subscription table sync completes.
            for s3_key in SQLITE_FILES_ORDERED[1:]:
                LOGGER.info(
                    'subscription_search_file email=%s domain=%s s3_key=%s',
                    email, domain, s3_key,
                )
                file_results = _collect_sqlite_results(s3_key, sld, permutations)

                target_table = SQLITE_TARGET_TABLE_BY_KEY.get(s3_key, OSINT_TABLE)
                stored_items = _list_table_domains(target_table, email, domain)
                added_count, removed_count = _sync_table(
                    email,
                    domain,
                    file_results,
                    stored_items,
                    target_table,
                )
                total_added += added_count
                total_removed += removed_count
                files_synced += 1

                # Free disk space before downloading the next file.
                _sqlite_delete_one(s3_key)

            _refresh_permutation_counts_from_tables(
                email,
                domain,
                permutations,
                ALL_SEARCH_TARGET_TABLES,
            )
            _update_watchlist_permutations(email, domain, permutations)

        LOGGER.info(
            'process_message_done email=%s domain=%s files_synced=%d added=%d removed=%d',
            email,
            domain,
            files_synced,
            total_added,
            total_removed,
        )
        return

    # ---------------------------------------------------------------
    # All other flag combinations → skip.
    # ---------------------------------------------------------------
    LOGGER.info(
        'process_message_skip email=%s domain=%s reason=flag_combination subscription=%s osintsearch=%s',
        email, domain, subscription_upper, osintsearch_upper,
    )


def handler(event, context):
    del context

    LOGGER.info('handler_start records=%d', len(event.get('Records', [])))

    failures = []

    try:
        for record in event.get('Records', []):
            message_id = record.get('messageId', '')
            try:
                body = json.loads(record.get('body', '{}'))
                domain = str(body.get('domain', '')).strip().lower()
                email = str(body.get('email', '')).strip().lower()
                subscription = str(body.get('subscription', '')).strip()
                osintsearch = str(body.get('osintsearch', '')).strip()

                if not domain or not email:
                    LOGGER.warning('record_skip message_id=%s reason=missing_domain_or_email body=%s', message_id, body)
                    continue

                _process_message(domain, email, subscription, osintsearch)

            except (ValueError, KeyError, FileNotFoundError, sqlite3.Error, BotoCoreError, ClientError) as exc:
                LOGGER.exception('record_error message_id=%s error=%s', message_id, exc)
                failures.append({'itemIdentifier': message_id})
    finally:
        _sqlite_cleanup_local_copy()

    LOGGER.info('handler_done records=%d failures=%d', len(event.get('Records', [])), len(failures))
    return {'batchItemFailures': failures}
