import base64
import binascii
import html
import json
import os
import re
import time
from decimal import Decimal
from urllib.parse import urlsplit, urlunsplit

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError

try:
    import requests
    from requests.exceptions import ConnectionError as RequestsConnectionError
    from requests.exceptions import Timeout as RequestsTimeout
    from requests.exceptions import TooManyRedirects as RequestsTooManyRedirects
except ImportError:  # pragma: no cover
    requests = None

    class RequestsConnectionError(Exception):
        pass

    class RequestsTimeout(Exception):
        pass

    class RequestsTooManyRedirects(Exception):
        pass


API_ENDPOINT = os.getenv('API_ENDPOINT', '')
LOGOUT_ENDPOINT = os.getenv('LOGOUT_ENDPOINT', '')
USER_INFO_ENDPOINT = os.getenv('USER_INFO_ENDPOINT', '')

HTTP_SESSION = requests.Session() if requests else None
DYNAMODB = boto3.resource('dynamodb')
DYNAMODB_CLIENT = boto3.client('dynamodb')

TABLE_CACHE = {}
IDENTITY_CACHE = {}
IDENTITY_CACHE_TTL_SECONDS = 300
IDENTITY_CACHE_MAX_ENTRIES = 256
MATCHED_SLD_CACHE = {}
MATCHED_SLD_CACHE_TTL_SECONDS = 60
MATCHED_SLD_CACHE_MAX_ENTRIES = 256
SEARCH_FIELDS_CACHE = {}
SEARCH_FIELDS_CACHE_TTL_SECONDS = 60
SEARCH_FIELDS_CACHE_MAX_ENTRIES = 32
VISIBLE_PROFILE_FIELDS = ('sponsor', 'threshold', 'monitors')
PROFILE_VISIBLE_FIELDS = {'sponsor', 'threshold', 'monitors'}

# Simple keyboard neighborhood map for replacement/insertion strategies.
_QWERTY_NEIGHBORS = {
    'a': 'qwsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'erfcxs', 'e': 'rdsw',
    'f': 'rtgvcd', 'g': 'tyhbvf', 'h': 'yujnbg', 'i': 'uojk', 'j': 'uikmnh',
    'k': 'iolmj', 'l': 'opk', 'm': 'njk', 'n': 'bhjm', 'o': 'pikl',
    'p': 'ol', 'q': 'wa', 'r': 'tfde', 's': 'wedxza', 't': 'ygfr',
    'u': 'yihj', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'uhgt',
    'z': 'asx',
    '0': '9', '1': '2', '2': '13', '3': '24', '4': '35',
    '5': '46', '6': '57', '7': '68', '8': '79', '9': '80'
}


def _get_table(table_name):
    if table_name not in TABLE_CACHE:
        TABLE_CACHE[table_name] = DYNAMODB.Table(table_name)
    return TABLE_CACHE[table_name]


def _get_env_table(env_key, default_name):
    return _get_table(os.getenv(env_key, default_name))


def _table_name_from_env(value):
    if not isinstance(value, str):
        return ''

    normalized = value.strip()
    if not normalized:
        return ''

    marker = ':table/'
    if marker in normalized:
        return normalized.split(marker, 1)[1]

    return normalized


def _resolve_table_identifiers(*env_keys):
    identifiers = []
    for key in env_keys:
        raw_value = os.getenv(key, '').strip()
        if not raw_value:
            continue

        parsed_name = _table_name_from_env(raw_value)
        if raw_value not in identifiers:
            identifiers.append(raw_value)
        if parsed_name and parsed_name not in identifiers:
            identifiers.append(parsed_name)

    return identifiers


def _resolve_home_api_endpoint(api_endpoint):
    normalized = (api_endpoint or '').strip()
    if not normalized:
        return '/home'

    parsed = urlsplit(normalized)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or ''
        if not path or path == '/':
            path = '/home'
        return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))

    if normalized in ('', '/'):
        return '/home'

    return normalized


def _resolve_logout_endpoint(logout_endpoint):
    normalized = (logout_endpoint or '').strip()
    if not normalized:
        return '/auth?action=logout'

    parsed = urlsplit(normalized)

    # Prefer API /auth logout flow because it adds required Cognito query params.
    if parsed.path == '/logout':
        if parsed.scheme and parsed.netloc:
            return urlunsplit((parsed.scheme, parsed.netloc, '/auth', 'action=logout', ''))
        return '/auth?action=logout'

    if parsed.path == '/auth' and parsed.scheme and parsed.netloc:
        if parsed.query:
            return normalized
        return urlunsplit((parsed.scheme, parsed.netloc, '/auth', 'action=logout', ''))

    if normalized == '/auth':
        return '/auth?action=logout'

    return normalized


def _get_method(event):
    request_context = event.get('requestContext') or {}
    http_context = request_context.get('http') or {}
    return (http_context.get('method') or event.get('httpMethod') or 'GET').upper()


def _get_body(event):
    body = event.get('body') or ''
    if event.get('isBase64Encoded') and body:
        try:
            body = base64.b64decode(body, validate=True).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return ''
    return body


def _get_authorization(event):
    authorization = event.get('authorization')
    if isinstance(authorization, str) and authorization:
        return authorization

    headers = event.get('headers') or {}
    return headers.get('authorization') or headers.get('Authorization') or ''


def _get_header_value(event, header_name):
    headers = event.get('headers') or {}
    if not isinstance(headers, dict):
        return ''

    normalized_name = str(header_name or '').strip().lower()
    if not normalized_name:
        return ''

    for key, value in headers.items():
        if str(key).strip().lower() == normalized_name:
            return str(value or '')

    return ''


def _is_force_refresh(event):
    value = _get_header_value(event, 'x-osint-refresh')
    return str(value).strip().lower() in ('1', 'true', 'yes', 'force')


def _clear_runtime_caches():
    MATCHED_SLD_CACHE.clear()
    SEARCH_FIELDS_CACHE.clear()


def _sanitize_event_for_logging(event):
    if not isinstance(event, dict):
        return event

    sanitized = dict(event)
    if isinstance(sanitized.get('authorization'), str):
        sanitized['authorization'] = '***'

    headers = sanitized.get('headers')
    if isinstance(headers, dict):
        sanitized_headers = dict(headers)
        if 'Authorization' in sanitized_headers:
            sanitized_headers['Authorization'] = '***'
        if 'authorization' in sanitized_headers:
            sanitized_headers['authorization'] = '***'
        sanitized['headers'] = sanitized_headers

    return sanitized


def _normalize_authorization(authorization_header):
    if not isinstance(authorization_header, str):
        return ''

    normalized = authorization_header.strip()
    if not normalized:
        return ''

    if normalized.lower().startswith('bearer '):
        return normalized

    return f'Bearer {normalized}'


def _decode_jwt_payload(authorization_header):
    normalized = _normalize_authorization(authorization_header)
    if not normalized or ' ' not in normalized:
        return {}

    token = normalized.split(' ', 1)[1].strip()
    parts = token.split('.')
    if len(parts) != 3:
        return {}

    payload = parts[1]
    pad = '=' * (-len(payload) % 4)

    try:
        raw_payload = base64.urlsafe_b64decode(payload + pad)
        parsed = json.loads(raw_payload.decode('utf-8'))
    except (binascii.Error, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return {}

    if not isinstance(parsed, dict):
        return {}

    return parsed


def _build_identity(payload, default_region):
    email = (
        payload.get('email')
        or payload.get('username')
        or payload.get('cognito:username')
        or 'unknown'
    )
    region = (
        payload.get('region')
        or payload.get('custom:region')
        or payload.get('zoneinfo')
        or payload.get('locale')
        or default_region
        or 'unknown'
    )

    return {
        'email': str(email),
        'region': str(region),
    }


def _get_cached_identity(normalized_authorization):
    cached_entry = IDENTITY_CACHE.get(normalized_authorization)
    if not cached_entry:
        return None

    cached_at, identity = cached_entry
    if (time.time() - cached_at) > IDENTITY_CACHE_TTL_SECONDS:
        IDENTITY_CACHE.pop(normalized_authorization, None)
        return None

    return dict(identity)


def _cache_identity(normalized_authorization, identity):
    if not normalized_authorization or not identity or identity.get('email') == 'unknown':
        return

    if len(IDENTITY_CACHE) >= IDENTITY_CACHE_MAX_ENTRIES:
        oldest_key = min(IDENTITY_CACHE, key=lambda key: IDENTITY_CACHE[key][0])
        IDENTITY_CACHE.pop(oldest_key, None)

    IDENTITY_CACHE[normalized_authorization] = (time.time(), dict(identity))


def _fetch_user_identity(authorization_header):
    default_region = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION') or 'us-east-1'
    normalized_authorization = _normalize_authorization(authorization_header)
    if not normalized_authorization:
        return {'email': 'unknown', 'region': default_region}

    cached_identity = _get_cached_identity(normalized_authorization)
    if cached_identity is not None:
        return cached_identity

    if USER_INFO_ENDPOINT and HTTP_SESSION is not None:
        try:
            response = HTTP_SESSION.get(
                USER_INFO_ENDPOINT,
                headers={'Authorization': normalized_authorization},
                timeout=3,
            )
            if response.ok:
                identity = _build_identity(response.json(), default_region)
                _cache_identity(normalized_authorization, identity)
                return identity
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            pass
        except requests.RequestException:  # type: ignore[union-attr]
            pass

    identity = _build_identity(_decode_jwt_payload(normalized_authorization), default_region)
    _cache_identity(normalized_authorization, identity)
    return identity


def _identity_from_authorizer_context(event):
    request_context = event.get('requestContext') or {}
    authorizer = request_context.get('authorizer') or {}
    default_region = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION') or 'us-east-1'

    candidates = []
    if isinstance(authorizer, dict):
        lambda_context = authorizer.get('lambda')
        if isinstance(lambda_context, dict):
            candidates.append(lambda_context)
        candidates.append(authorizer)

    for context in candidates:
        email = str(context.get('email') or '').strip().lower()
        if not email:
            continue

        region = str(
            context.get('region')
            or context.get('custom:region')
            or context.get('zoneinfo')
            or context.get('locale')
            or default_region
            or 'unknown'
        )
        return {'email': email, 'region': region}

    return {}


def _resolve_identity(event, authorization_header):
    authorizer_identity = _identity_from_authorizer_context(event)
    if authorizer_identity.get('email'):
        return authorizer_identity
    return _fetch_user_identity(authorization_header)


def _normalize_domain(entry):
    if not isinstance(entry, str):
        return ''
    return entry.strip().lower().rstrip('.')


def _normalize_permutation_value(value):
    normalized = _normalize_domain(value)
    if not normalized:
        return ''

    # Permutation list should display only SLD-like values (without TLD).
    if '.' in normalized:
        return normalized.split('.', 1)[0]

    return normalized


def _normalize_permutation_enabled(value):
    normalized = str(value or '').strip().upper()
    return 'OFF' if normalized == 'OFF' else 'ON'


def _normalize_permutation_metric(value):
    if isinstance(value, int):
        return max(0, value)

    if isinstance(value, Decimal):
        if value.is_nan() or value.is_infinite():
            return 0
        return max(0, int(value))

    if isinstance(value, str):
        try:
            return max(0, int(value.strip()))
        except ValueError:
            return 0

    return 0


def _validate_domain(domain):
    if not domain:
        return False, 'Domain is required.'

    labels = domain.split('.')
    if len(labels) < 2 or (len(labels) == 2 and labels[1] == ''):
        return False, 'Domain must include a single dot (e.g. example.com).'
    if len(labels) != 2:
        return False, 'Domain must contain exactly one dot (no subdomains allowed).'

    return True, ''


def _split_domain(domain):
    sld, tld = domain.split('.')
    return sld, tld


def _tld_exists(table, tld):
    response = table.get_item(
        Key={'pk': 'TLD#', 'sk': tld},
        ProjectionExpression='sk',
    )
    return 'Item' in response


def _watchlist_pk(email):
    _ = email
    return 'OSINT#'


def _watchlist_sk(domain):
    return f'OSINT#{domain}#'


def _watchlist_item_sk(email, domain):
    return f'OSINT#{email}#{domain}#'


def _user_pk():
    return 'OSINT#'


def _user_sk(email):
    return f'OSINT#{email}#'


def _query_user_record(table, email):
    if not email or email == 'unknown':
        return {}

    for sk in (f'OSTIN#{email}#', _user_sk(email)):
        try:
            response = table.query(
                KeyConditionExpression=Key('pk').eq(_user_pk()) & Key('sk').eq(sk),
                Limit=1,
            )
            items = response.get('Items', [])
            if items:
                return items[0]
        except (AttributeError, BotoCoreError, ClientError, KeyError, TypeError, ValueError):
            return {}

    return {}


def _get_user_extra_fields(table, email):
    item = _query_user_record(table, email)
    if not item:
        return {}

    extra_fields = {}
    for key, value in item.items():
        if key in ('pk', 'sk', 'email', 'region'):
            continue

        normalized_key = str(key).strip().lower()
        if normalized_key not in VISIBLE_PROFILE_FIELDS:
            continue

        normalized_value = _stringify_user_extra_field_value(value)
        if normalized_value is not None:
            extra_fields[normalized_key] = normalized_value

    return dict(sorted(extra_fields.items(), key=lambda item: item[0]))


def _stringify_user_extra_field_value(value):
    if value is None:
        return None

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, (str, int, float, bool)):
        return str(value)

    if isinstance(value, (list, dict, set, tuple)):
        try:
            return json.dumps(value, sort_keys=True)
        except (TypeError, ValueError):
            return str(value)

    return str(value)


def _json_safe_value(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f'Object of type {value.__class__.__name__} is not JSON serializable')


def _format_user_extra_field_label(key):
    normalized_key = str(key or '').strip().lower()
    if not normalized_key:
        return 'Profile Field'

    label_overrides = {
        'threshold': 'Threshold',
        'sponsor': 'Sponsor',
        'monitors': 'Monitors',
    }
    if normalized_key in label_overrides:
        return label_overrides[normalized_key]

    humanized = normalized_key.replace('_', ' ').replace('-', ' ')
    return ' '.join(token.capitalize() for token in humanized.split())


def _normalize_domains_monitor_token(api_token):
    if not isinstance(api_token, str):
        return ''
    return api_token.strip()


def _build_domains_monitor_account_url(api_token):
    return f'https://domains-monitor.com/api/v1/{api_token}/account/json/'


def _verify_domains_monitor_account(api_token):
    normalized_token = _normalize_domains_monitor_token(api_token)
    if not normalized_token:
        return {}, 'API token is required.'

    if HTTP_SESSION is None:
        return {}, 'Requests dependency is not available in this runtime.'

    try:
        response = HTTP_SESSION.get(_build_domains_monitor_account_url(normalized_token), timeout=30)
    except (RequestsConnectionError, RequestsTimeout, RequestsTooManyRedirects) as exc:  # pragma: no cover - requests-specific runtime/network errors
        return {}, f'Could not verify token: {exc}'

    if response.status_code != 200:
        return {}, f'Could not verify token (HTTP {response.status_code}).'

    try:
        payload = response.json()
    except ValueError:
        return {}, 'Could not verify token: response body was not valid JSON.'

    account = payload.get('account') if isinstance(payload, dict) else None
    if not isinstance(account, dict):
        return {}, 'Could not verify token: account payload is missing.'

    email = str(account.get('email') or '').strip().lower()
    status = str(account.get('status') or '').strip()
    license_name = str(account.get('license_name') or '').strip()
    license_until = str(account.get('license_until') or '').strip()

    if not email:
        return {}, 'Could not verify token: account email is missing.'
    if not status:
        return {}, 'Could not verify token: account status is missing.'
    if not license_name:
        return {}, 'Could not verify token: license name is missing.'
    if not license_until:
        return {}, 'Could not verify token: license expiration is missing.'

    try:
        ttl = int(license_until)
    except (TypeError, ValueError):
        return {}, 'Could not verify token: license expiration must be numeric.'

    return {
        'email': email,
        'status': status,
        'license': license_name,
        'ttl': ttl,
    }, ''


def _put_domains_monitor_subscription(table, account, cognito_email=''):
    domains_monitor_email = str(account.get('email', '')).strip().lower()
    normalized_cognito_email = str(cognito_email or '').strip().lower()
    if not domains_monitor_email:
        raise ValueError('Domains Monitor email is required to store a subscription record.')
    if not normalized_cognito_email:
        raise ValueError('Cognito email is required to store a subscription record.')

    table.put_item(
        Item={
            'pk': 'OSINT#',
            'sk': f'OSINT#DM#{domains_monitor_email}#',
            'domains_monitor_email': domains_monitor_email,
            'cognito_email': normalized_cognito_email,
            'status': account.get('status', ''),
            'license': account.get('license', ''),
            'ttl': account.get('ttl', 0),
        }
    )


def _get_domains_monitor_subscription(table, email):
    if not email or email == 'unknown':
        return {}

    normalized_email = str(email).strip().lower()

    def _normalize_subscription_item(item):
        if not isinstance(item, dict):
            return {}

        normalized_item = dict(item)
        normalized_item['email'] = str(
            normalized_item.get('email')
            or normalized_item.get('domains_monitor_email')
            or normalized_item.get('cognito_email')
            or ''
        ).strip().lower()
        return normalized_item

    try:
        response = table.get_item(Key={'pk': 'OSINT#', 'sk': f'OSINT#DM#{normalized_email}#'})
    except (AttributeError, BotoCoreError, ClientError, KeyError, TypeError, ValueError):
        return {}

    normalized_item = _normalize_subscription_item(response.get('Item'))
    if not normalized_item:
        return {}

    return normalized_item


def _homoglyph_permutations(sld):
    swaps = {
        'o': ['0'], '0': ['o'],
        'i': ['1', 'l'], '1': ['i', 'l'], 'l': ['1', 'i'],
        's': ['5'], '5': ['s'],
        'a': ['4'], '4': ['a'],
        'e': ['3'], '3': ['e'],
        'g': ['9'], '9': ['g']
    }
    out = set()
    chars = list(sld)
    for idx, char in enumerate(chars):
        for rep in swaps.get(char, []):
            candidate = chars.copy()
            candidate[idx] = rep
            out.add(''.join(candidate))
    return out


def _omission_permutations(sld):
    return {sld[:idx] + sld[idx + 1:] for idx in range(len(sld)) if len(sld) > 1}


def _repetition_permutations(sld):
    out = set()
    for idx, char in enumerate(sld):
        out.add(sld[:idx] + char + sld[idx:])
    return out


def _transposition_permutations(sld):
    out = set()
    for idx in range(len(sld) - 1):
        if sld[idx] != sld[idx + 1]:
            out.add(sld[:idx] + sld[idx + 1] + sld[idx] + sld[idx + 2:])
    return out


def _hyphenation_permutations(sld):
    out = set()
    for idx in range(1, len(sld)):
        out.add(sld[:idx] + '-' + sld[idx:])
    return out


def _replacement_permutations(sld):
    out = set()
    for idx, char in enumerate(sld):
        for neighbor in _QWERTY_NEIGHBORS.get(char, ''):
            out.add(sld[:idx] + neighbor + sld[idx + 1:])
    return out


def _insertion_permutations(sld):
    out = set()
    for idx, char in enumerate(sld):
        for neighbor in _QWERTY_NEIGHBORS.get(char, ''):
            out.add(sld[:idx] + neighbor + sld[idx:])
            out.add(sld[:idx + 1] + neighbor + sld[idx + 1:])
    return out


def _addition_permutations(sld):
    out = set()
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
    for ch in charset:
        out.add(ch + sld)
        out.add(sld + ch)
    return out


def _bitsquatting_permutations(sld):
    out = set()
    bit_masks = (1, 2, 4, 8, 16, 32, 64)
    for idx, ch in enumerate(sld):
        code = ord(ch)
        for mask in bit_masks:
            flipped = chr(code ^ mask)
            if flipped.isalnum() or flipped == '-':
                out.add(sld[:idx] + flipped + sld[idx + 1:])
    return out


def _vowel_swap_permutations(sld):
    out = set()
    vowels = 'aeiou'
    for idx, ch in enumerate(sld):
        if ch in vowels:
            for rep in vowels:
                if rep != ch:
                    out.add(sld[:idx] + rep + sld[idx + 1:])
    return out


def _strategy_candidates(sld):
    if len(sld) < 5:
        return [
            ('homoglyph', _homoglyph_permutations(sld)),
            ('transposition', _transposition_permutations(sld))
        ]

    if len(sld) == 5:
        return [
            ('homoglyph', _homoglyph_permutations(sld)),
            ('transposition', _transposition_permutations(sld)),
            ('replacement', _replacement_permutations(sld))
        ]

    return [
        ('homoglyph', _homoglyph_permutations(sld)),
        ('omission', _omission_permutations(sld)),
        ('repetition', _repetition_permutations(sld)),
        ('transposition', _transposition_permutations(sld)),
        ('hyphenation', _hyphenation_permutations(sld)),
        ('replacement', _replacement_permutations(sld)),
        ('insertion', _insertion_permutations(sld)),
        ('addition', _addition_permutations(sld)),
        ('bitsquatting', _bitsquatting_permutations(sld)),
        ('vowel_swap', _vowel_swap_permutations(sld))
    ]


def _recommended_permutations(sld):
    sld = sld.lower()
    strategy_sets = _strategy_candidates(sld)
    candidates = set()
    for _, values in strategy_sets:
        candidates.update(values)

    normalized = set()
    for candidate in candidates:
        if not candidate or len(candidate) < 2:
            continue

        lowered = candidate.lower()
        if sld in lowered:
            continue

        if all(ch.isalnum() or ch == '-' for ch in lowered):
            normalized.add(lowered)

    return sorted(normalized)


def _build_watchlist_permutations(sld):
    values = _recommended_permutations(sld)
    return [
        {
            'permutation': value,
            'enabled': 'ON',
            'unique_domains': 0,
            'unique_sources': 0,
        }
        for value in values
    ]


def _put_watchlist_domain(table, email, domain):
    sld, tld = _split_domain(domain)
    permutations = _build_watchlist_permutations(sld)
    table.put_item(
        Item={
            'pk': _watchlist_pk(email),
            'sk': _watchlist_item_sk(email, domain),
            'email': email,
            'domain': domain,
            'sld': sld,
            'tld': tld,
            'count': len(permutations),
            'permutations': permutations,
            'updated': int(time.time())
        }
    )


def _delete_watchlist_domain(table, email, domain):
    table.delete_item(Key={'pk': _watchlist_pk(email), 'sk': _watchlist_item_sk(email, domain)})


def _watchlist_domain_exists(table, email, domain):
    response = table.get_item(
        Key={'pk': _watchlist_pk(email), 'sk': _watchlist_item_sk(email, domain)},
        ProjectionExpression='sk',
    )
    return bool(response.get('Item'))


def _ensure_user_record(table, email):
    query_kwargs = {
        'KeyConditionExpression': Key('pk').eq(_user_pk()) & Key('sk').eq(_user_sk(email)),
        'Limit': 1,
    }
    response = table.query(**query_kwargs)
    if response.get('Items'):
        return

    table.put_item(
        Item={
            'pk': _user_pk(),
            'sk': _user_sk(email),
            'email': email,
            'sponsor': 'Basic',
            'monitors': 1,
            'threshold': 100,
        }
    )


def _list_watchlist_domains(table, email):
    if not email or email == 'unknown':
        return []

    domains = []

    def _collect(query_kwargs):
        while True:
            response = table.query(**query_kwargs)
            for item in response.get('Items', []):
                normalized_domain = _normalize_domain(item.get('domain'))
                if normalized_domain:
                    domains.append(normalized_domain)

            last_evaluated_key = response.get('LastEvaluatedKey')
            if not last_evaluated_key:
                break
            query_kwargs['ExclusiveStartKey'] = last_evaluated_key

    for query_kwargs in [
        {
            'KeyConditionExpression': Key('pk').eq(_watchlist_pk(email)) & Key('sk').begins_with(f'OSINT#{email}#'),
            'ProjectionExpression': '#domain',
            'ExpressionAttributeNames': {'#domain': 'domain'},
        },
        {
            'IndexName': 'email-domain-index',
            'KeyConditionExpression': Key('email').eq(email),
            'ProjectionExpression': '#domain',
            'ExpressionAttributeNames': {'#domain': 'domain'},
        },
    ]:
        try:
            _collect(query_kwargs)
        except ClientError as exc:
            error_code = exc.response.get('Error', {}).get('Code', '')
            if error_code not in ('ValidationException', 'ResourceNotFoundException'):
                return []
        except (BotoCoreError, KeyError, TypeError):
            return []

    return sorted(set(domains))


def _get_user_monitors_count(users_table, email):
    if not email or email == 'unknown':
        return 0

    record = _query_user_record(users_table, email)
    monitors = record.get('monitors', 0)

    if isinstance(monitors, int):
        return max(0, monitors)

    if isinstance(monitors, Decimal):
        if monitors.is_nan() or monitors.is_infinite():
            return 0
        return max(0, int(monitors))

    if isinstance(monitors, str):
        try:
            return max(0, int(monitors.strip()))
        except ValueError:
            return 0

    return 0


def _get_watchlist_domain_count(watchlist_table, email):
    if not email or email == 'unknown':
        return 0

    # Count via listing to include both primary-key and legacy index paths.
    # This prevents undercounting when a user's watchlist contains mixed schemas.
    try:
        domains = _list_watchlist_domains(watchlist_table, email)
        if isinstance(domains, list):
            return len(domains)
    except (BotoCoreError, ClientError, KeyError, TypeError, ValueError, AttributeError):
        pass

    try:
        response = watchlist_table.query(
            KeyConditionExpression=Key('pk').eq(_watchlist_pk(email)) & Key('sk').begins_with(f'OSINT#{email}#'),
            Select='COUNT',
        )
    except ClientError as exc:
        error_code = exc.response.get('Error', {}).get('Code', '')
        if error_code in ('ValidationException', 'ResourceNotFoundException'):
            return 0
        return 0
    except (BotoCoreError, KeyError, TypeError, AttributeError):
        return 0

    count = response.get('Count', 0)
    if isinstance(count, int):
        return max(0, count)

    if isinstance(count, str):
        try:
            return max(0, int(count.strip()))
        except ValueError:
            return 0

    return 0


def _process_submission(raw_domain, email, action):
    domain = _normalize_domain(raw_domain)
    is_valid, msg = _validate_domain(domain)
    if not is_valid:
        return domain, False, msg

    if not email or email == 'unknown':
        return domain, False, 'Could not determine user identity email.'

    _sld, tld = _split_domain(domain)
    tld_table = _get_env_table('TLD_TABLE', 'tld')
    watchlist_table = _get_env_table('WATCHLIST_TABLE', 'watchlist')
    users_table = _get_env_table('USERS_TABLE', 'users')

    if not _tld_exists(tld_table, tld):
        return domain, False, f'Unknown top-level domain: {tld}'

    normalized_action = (action or '').strip().lower()

    if normalized_action == 'deleteitem':
        try:
            if not _watchlist_domain_exists(watchlist_table, email, domain):
                return domain, False, 'That domain is not in your watchlist, so there is nothing to delete.'
            _delete_watchlist_domain(watchlist_table, email, domain)
            return domain, True, 'Deleted'
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
            return domain, False, 'An error occurred while removing the domain.'

    _ensure_user_record(users_table, email)

    try:
        if _watchlist_domain_exists(watchlist_table, email, domain):
            return domain, False, 'Domain already exists in your watchlist.'

        # Enforce the monitors limit only for new domains.
        monitors = _get_user_monitors_count(users_table, email)
        domain_count = _get_watchlist_domain_count(watchlist_table, email)
        if monitors > 0 and domain_count >= monitors:
            return domain, False, f'You have reached your monitors limit ({monitors}). Remove a domain before adding another.'

        _put_watchlist_domain(watchlist_table, email, domain)

        monitors = _get_user_monitors_count(users_table, email)
        if monitors > 0:
            domain_count = _get_watchlist_domain_count(watchlist_table, email)
            if domain_count > monitors:
                _delete_watchlist_domain(watchlist_table, email, domain)
                return domain, False, f'You have reached your monitors limit ({monitors}). Remove a domain before adding another.'

        return domain, True, 'Saved'
    except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as exc:
        return domain, False, str(exc)


def _extract_values(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if isinstance(value, set):
        return [str(item) for item in value if item is not None]
    if isinstance(value, dict):
        if 'S' in value:
            return [str(value['S'])]
        if 'SS' in value and isinstance(value['SS'], list):
            return [str(item) for item in value['SS']]
        if 'L' in value and isinstance(value['L'], list):
            out = []
            for row in value['L']:
                out.extend(_extract_values(row))
            return out
    return []


def _normalize_source_url(value):
    if not isinstance(value, str):
        return ''

    normalized = value.strip()
    if not normalized:
        return ''

    parsed = urlsplit(normalized)
    if parsed.scheme in ('http', 'https') and parsed.netloc:
        return normalized

    return ''


def _extract_osint_source_urls(value):
    extracted_urls = []

    def _append_if_new(url_value):
        normalized_url = _normalize_source_url(url_value)
        if normalized_url and normalized_url not in extracted_urls:
            extracted_urls.append(normalized_url)

    for raw_value in _extract_values(value):
        candidate_value = str(raw_value or '').strip()
        if not candidate_value:
            continue

        for token in re.findall(r'https?://[^\s,;|]+', candidate_value):
            _append_if_new(token)

        for token in re.split(r'[\s,;|]+', candidate_value):
            _append_if_new(token)

    return extracted_urls


def _derive_osint_source_name(source_url):
    parsed = urlsplit(source_url)
    host = parsed.netloc.lower().lstrip('www.')
    path_segments = [segment for segment in parsed.path.split('/') if segment]

    if host in ('github.com', 'raw.githubusercontent.com') and len(path_segments) >= 2:
        return f'{path_segments[0]}/{path_segments[1]}'

    if host:
        return host

    return source_url


def _normalize_osint_attribution_entries(raw_entries):
    if not isinstance(raw_entries, list):
        return []

    normalized_entries = []
    seen_by_url = set()
    seen_name_only = set()

    def _append_entry(name_value, url_value=''):
        normalized_name = str(name_value or '').strip()
        normalized_url = _normalize_source_url(url_value)

        if not normalized_name and not normalized_url:
            return

        if not normalized_name and normalized_url:
            normalized_name = _derive_osint_source_name(normalized_url)

        if normalized_url:
            if normalized_url in seen_by_url:
                return
            seen_by_url.add(normalized_url)
        else:
            name_key = normalized_name.lower()
            if name_key in seen_name_only:
                return
            seen_name_only.add(name_key)

        entry = {'name': normalized_name}
        if normalized_url:
            entry['url'] = normalized_url
        normalized_entries.append(entry)

    for raw_entry in raw_entries:
        if isinstance(raw_entry, str):
            normalized_url = _normalize_source_url(raw_entry)
            _append_entry(_derive_osint_source_name(normalized_url) if normalized_url else raw_entry, normalized_url)
            continue

        if isinstance(raw_entry, dict):
            raw_url = (
                raw_entry.get('url')
                or raw_entry.get('href')
                or raw_entry.get('link')
                or ''
            )
            raw_name = (
                raw_entry.get('name')
                or raw_entry.get('label')
                or raw_entry.get('source')
                or raw_url
                or ''
            )
            _append_entry(raw_name, raw_url)

    return normalized_entries


def _merge_osint_attribution(existing_entries, incoming_entries):
    merged_entries = []
    seen_urls = set()
    seen_names = set()

    for entry in (existing_entries or []) + (incoming_entries or []):
        if not isinstance(entry, dict):
            continue

        name = str(entry.get('name') or '').strip()
        url = _normalize_source_url(entry.get('url', ''))

        if not name and not url:
            continue
        if not name and url:
            name = _derive_osint_source_name(url)

        if url:
            if url in seen_urls:
                continue
            seen_urls.add(url)
        else:
            name_key = name.lower()
            if name_key in seen_names:
                continue
            seen_names.add(name_key)

        merged_entry = {'name': name}
        if url:
            merged_entry['url'] = url
        merged_entries.append(merged_entry)

    return merged_entries


def _normalize_osint_domain_entry(item):
    if isinstance(item, str):
        normalized_domain = _normalize_domain(item)
        if not normalized_domain or '.' not in normalized_domain:
            return {}
        return {'domain': normalized_domain, 'attribution': []}

    if not isinstance(item, dict):
        return {}

    normalized_domain = _normalize_domain(
        item.get('domain')
        or item.get('result')
        or item.get('value')
        or ''
    )
    if not normalized_domain or '.' not in normalized_domain:
        return {}

    return {
        'domain': normalized_domain,
        'attribution': _normalize_osint_attribution_entries(item.get('attribution') or item.get('attributions') or []),
    }


def _query_osint_domains(email, domain):
    normalized_email = str(email or '').strip().lower()
    normalized_domain = _normalize_domain(domain)
    if not normalized_email or normalized_email == 'unknown' or not normalized_domain:
        return []

    table_identifiers = _resolve_table_identifiers('OSINT_TABLE')
    if not table_identifiers:
        table_identifiers = ['osint']

    domains_by_name = {}
    prefix = f'OSINT#{normalized_email}#{normalized_domain}#'
    for table_identifier in table_identifiers:
        query_kwargs = {
            'TableName': table_identifier,
            'ConsistentRead': True,
            'KeyConditionExpression': 'pk = :pk AND begins_with(sk, :sk)',
            'ExpressionAttributeValues': {
                ':pk': {'S': 'OSINT#'},
                ':sk': {'S': prefix},
            },
            'ProjectionExpression': '#result, #domain, #source, #url, #sk',
            'ExpressionAttributeNames': {
                '#result': 'result',
                '#domain': 'domain',
                '#source': 'source',
                '#url': 'url',
                '#sk': 'sk',
            },
        }

        while True:
            response = DYNAMODB_CLIENT.query(**query_kwargs)
            for item in response.get('Items', []):
                result_value = _normalize_domain(item.get('result', {}).get('S', ''))
                if result_value:
                    source_urls = _extract_osint_source_urls(item.get('source'))
                    if not source_urls:
                        source_urls = _extract_osint_source_urls(item.get('url'))

                    source_entries = [
                        {'name': _derive_osint_source_name(source_url), 'url': source_url}
                        for source_url in source_urls
                    ]

                    existing = domains_by_name.get(result_value)
                    if existing is None:
                        domains_by_name[result_value] = {
                            'domain': result_value,
                            'attribution': source_entries,
                        }
                    else:
                        existing['attribution'] = _merge_osint_attribution(existing.get('attribution', []), source_entries)
                    continue

                fallback_domain = _normalize_domain(item.get('domain', {}).get('S', ''))
                if fallback_domain:
                    if fallback_domain not in domains_by_name:
                        domains_by_name[fallback_domain] = {
                            'domain': fallback_domain,
                            'attribution': [],
                        }

            last_evaluated_key = response.get('LastEvaluatedKey')
            if not last_evaluated_key:
                break
            query_kwargs['ExclusiveStartKey'] = last_evaluated_key

        if domains_by_name:
            break

    return [
        domains_by_name[domain_name]
        for domain_name in sorted(domains_by_name)
    ]


def _query_scoped_domains(table_identifier, email, domain):
    normalized_email = str(email or '').strip().lower()
    normalized_domain = _normalize_domain(domain)
    if not normalized_email or normalized_email == 'unknown' or not normalized_domain:
        return []

    all_domains = []
    prefix = f'OSINT#{normalized_email}#{normalized_domain}#'
    query_kwargs = {
        'TableName': table_identifier,
        'ConsistentRead': True,
        'KeyConditionExpression': 'pk = :pk AND begins_with(sk, :sk)',
        'ExpressionAttributeValues': {
            ':pk': {'S': 'OSINT#'},
            ':sk': {'S': prefix},
        },
        'ProjectionExpression': '#result, #domain, #sk',
        'ExpressionAttributeNames': {
            '#result': 'result',
            '#domain': 'domain',
            '#sk': 'sk',
        },
    }

    while True:
        response = DYNAMODB_CLIENT.query(**query_kwargs)
        for item in response.get('Items', []):
            result_value = _normalize_domain(item.get('result', {}).get('S', ''))
            if result_value:
                all_domains.append(result_value)
                continue

            fallback_domain = _normalize_domain(item.get('domain', {}).get('S', ''))
            if fallback_domain:
                all_domains.append(fallback_domain)
                continue

            sk_value = str(item.get('sk', {}).get('S', '')).strip()
            if sk_value.startswith(prefix):
                trailing = sk_value[len(prefix):].strip('#')
                parsed_domain = _normalize_domain(trailing)
                if parsed_domain:
                    all_domains.append(parsed_domain)

        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break
        query_kwargs['ExclusiveStartKey'] = last_evaluated_key

    return sorted(set(all_domains))


def _load_section_domains(email, domain, *env_keys):
    table_identifiers = _resolve_table_identifiers(*env_keys)
    if not table_identifiers:
        return []

    for table_identifier in table_identifiers:
        scoped_domains = _query_scoped_domains(table_identifier, email, domain)
        if scoped_domains:
            return scoped_domains

    return []


def _partition_suspect_domains(osint_domains, malware_domains):
    def _normalize_and_dedupe_osint(domains):
        domains_by_name = {}

        for raw_domain in domains or []:
            normalized_entry = _normalize_osint_domain_entry(raw_domain)
            normalized_domain = normalized_entry.get('domain')
            if not normalized_domain:
                continue

            existing_entry = domains_by_name.get(normalized_domain)
            if existing_entry is None:
                domains_by_name[normalized_domain] = {
                    'domain': normalized_domain,
                    'attribution': normalized_entry.get('attribution', []),
                }
                continue

            existing_entry['attribution'] = _merge_osint_attribution(
                existing_entry.get('attribution', []),
                normalized_entry.get('attribution', []),
            )

        return [
            domains_by_name[domain_name]
            for domain_name in sorted(domains_by_name)
        ]

    def _normalize_and_dedupe(domains):
        normalized = []
        seen = set()

        for domain in domains or []:
            normalized_domain = _normalize_domain(domain)
            if not normalized_domain or '.' not in normalized_domain or normalized_domain in seen:
                continue

            seen.add(normalized_domain)
            normalized.append(normalized_domain)

        return normalized

    normalized_osint = _normalize_and_dedupe_osint(osint_domains)
    normalized_malware = _normalize_and_dedupe(malware_domains)

    return {
        'openSourceIntelligence': normalized_osint,
        'domainsMonitorSubscription': normalized_malware,
    }


def _normalize_search_field(value):
    normalized_value = _normalize_domain(value)
    if not normalized_value:
        return ''

    if '.' in normalized_value:
        return normalized_value.split('.', 1)[0]

    return normalized_value


def _extract_search_field_value(item):
    if not isinstance(item, dict):
        return ''

    for key in ('search', 'searchField', 'searchfield', 'sld'):
        normalized_value = _normalize_search_field(item.get(key))
        if normalized_value:
            return normalized_value

    return ''


def _query_search_fields(table_identifier):
    search_fields = []
    expression_values = {
        ':pk': {'S': 'OSINT#'},
        ':sk': {'S': 'OSINT#'},
    }
    query_kwargs = {
        'TableName': table_identifier,
        'KeyConditionExpression': 'pk = :pk AND begins_with(sk, :sk)',
        'ExpressionAttributeValues': expression_values,
        'ProjectionExpression': '#sk, #search, #searchField, #searchfield, #sld',
        'ExpressionAttributeNames': {
            '#sk': 'sk',
            '#search': 'search',
            '#searchField': 'searchField',
            '#searchfield': 'searchfield',
            '#sld': 'sld',
        },
    }

    while True:
        response = DYNAMODB_CLIENT.query(**query_kwargs)
        for item in response.get('Items', []):
            normalized_item = {
                key: next(iter(value.values())) if isinstance(value, dict) and value else value
                for key, value in item.items()
            }
            search_field = _extract_search_field_value(normalized_item)
            if search_field:
                search_fields.append(search_field)

        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break
        query_kwargs['ExclusiveStartKey'] = last_evaluated_key

    return sorted(set(search_fields))


def _get_cached_matched_slds(cache_key):
    cached_entry = MATCHED_SLD_CACHE.get(cache_key)
    if not cached_entry:
        return None

    cached_at, matched_slds = cached_entry
    if (time.time() - cached_at) > MATCHED_SLD_CACHE_TTL_SECONDS:
        MATCHED_SLD_CACHE.pop(cache_key, None)
        return None

    return set(matched_slds)


def _cache_matched_slds(cache_key, matched_slds):
    if len(MATCHED_SLD_CACHE) >= MATCHED_SLD_CACHE_MAX_ENTRIES:
        oldest_key = min(MATCHED_SLD_CACHE, key=lambda key: MATCHED_SLD_CACHE[key][0])
        MATCHED_SLD_CACHE.pop(oldest_key, None)

    MATCHED_SLD_CACHE[cache_key] = (time.time(), sorted(set(matched_slds)))


def _get_cached_search_fields_entry(table_identifier):
    cached_entry = SEARCH_FIELDS_CACHE.get(table_identifier)
    if not cached_entry:
        return None

    cached_at, search_fields = cached_entry
    if (time.time() - cached_at) > SEARCH_FIELDS_CACHE_TTL_SECONDS:
        SEARCH_FIELDS_CACHE.pop(table_identifier, None)
        return None

    return set(search_fields)


def _cache_search_fields(table_identifier, search_fields):
    if len(SEARCH_FIELDS_CACHE) >= SEARCH_FIELDS_CACHE_MAX_ENTRIES:
        oldest_key = min(SEARCH_FIELDS_CACHE, key=lambda key: SEARCH_FIELDS_CACHE[key][0])
        SEARCH_FIELDS_CACHE.pop(oldest_key, None)

    SEARCH_FIELDS_CACHE[table_identifier] = (time.time(), sorted(set(search_fields)))


def _get_cached_search_fields(table_identifier):
    cached_search_fields = _get_cached_search_fields_entry(table_identifier)
    if cached_search_fields is not None:
        return cached_search_fields

    search_fields = set(_query_search_fields(table_identifier))
    _cache_search_fields(table_identifier, search_fields)
    return search_fields


def _get_search_field_matches(domains):
    normalized_slds = set()
    for domain in domains or []:
        normalized_domain = _normalize_domain(domain)
        is_valid, _ = _validate_domain(normalized_domain)
        if not is_valid:
            continue

        sld, _ = _split_domain(normalized_domain)
        normalized_slds.add(sld)

    if not normalized_slds:
        return set()

    search_fields = set()
    for env_key in ('WM_DAILYUPDATE', 'WM_DAILYREMOVE', 'WM_MALWARE', 'WM_OSINT'):
        for table_identifier in _resolve_table_identifiers(env_key):
            try:
                search_fields.update(_get_cached_search_fields(table_identifier))
            except (BotoCoreError, ClientError, KeyError, TypeError) as exc:
                print(f'Search-field query failed on table {table_identifier}: {exc}')

    return normalized_slds.intersection(search_fields)


def _get_domain_sections(domain, email=''):
    normalized_domain = _normalize_domain(domain)
    is_valid, _ = _validate_domain(normalized_domain)
    if not is_valid:
        return {}

    osint = _query_osint_domains(email, normalized_domain)
    malware = _load_section_domains(email, normalized_domain, 'WM_MALWARE')
    suspect_domains = _partition_suspect_domains(osint, malware)

    return {
        'suspect': suspect_domains,
        'newRegistrations': {
            'daily': _load_section_domains(email, normalized_domain, 'WM_DAILYUPDATE'),
            'weekly': _load_section_domains(email, normalized_domain, 'WM_WEEKLYUPDATE'),
            'monthly': _load_section_domains(email, normalized_domain, 'WM_MONTHLY', 'WM_MONTHLYUPDATE'),
        },
        'expiredRegistrations': {
            'daily': _load_section_domains(email, normalized_domain, 'WM_DAILYREMOVE'),
            'weekly': _load_section_domains(email, normalized_domain, 'WM_WEEKLYREMOVE'),
            'monthly': _load_section_domains(email, normalized_domain, 'WM_MONTHLYREMOVE'),
        },
        '_noDomainsMonitor': False,
    }


def _get_domain_permutations(domain, email=''):
    normalized_domain = _normalize_domain(domain)
    is_valid, _ = _validate_domain(normalized_domain)
    if not is_valid:
        return []

    watchlist_table = _get_env_table('WATCHLIST_TABLE', 'watchlist')
    if not email or email == 'unknown':
        return []

    try:
        response = watchlist_table.get_item(
            Key={'pk': _watchlist_pk(email), 'sk': _watchlist_item_sk(email, normalized_domain)}
        )
    except (BotoCoreError, ClientError, KeyError, TypeError):
        return []

    item = response.get('Item') or {}
    entries = _extract_permutation_entries(item)
    return [entry['permutation'] for entry in entries]


def _extract_permutation_entries(item):
    if not isinstance(item, dict):
        return []

    entries_by_value = {}
    ordered_entries = []

    def _upsert_entry(permutation_value, enabled_value='ON', unique_domains_value=0, unique_sources_value=0):
        normalized_permutation = _normalize_permutation_value(permutation_value)
        if not normalized_permutation:
            return

        normalized_enabled = _normalize_permutation_enabled(enabled_value)
        normalized_unique_domains = _normalize_permutation_metric(unique_domains_value)
        normalized_unique_sources = _normalize_permutation_metric(unique_sources_value)
        existing_entry = entries_by_value.get(normalized_permutation)
        if existing_entry is None:
            entry = {
                'permutation': normalized_permutation,
                'enabled': normalized_enabled,
                'unique_domains': normalized_unique_domains,
                'unique_sources': normalized_unique_sources,
            }
            entries_by_value[normalized_permutation] = entry
            ordered_entries.append(entry)
            return

        existing_entry['enabled'] = normalized_enabled
        existing_entry['unique_domains'] = max(
            _normalize_permutation_metric(existing_entry.get('unique_domains', 0)),
            normalized_unique_domains,
        )
        existing_entry['unique_sources'] = max(
            _normalize_permutation_metric(existing_entry.get('unique_sources', 0)),
            normalized_unique_sources,
        )

    for value in item.get('permutations', []):
        if isinstance(value, dict):
            _upsert_entry(
                value.get('permutation', ''),
                value.get('enabled', 'ON'),
                value.get('unique_domains', 0),
                value.get('unique_sources', 0),
            )
        elif isinstance(value, str):
            _upsert_entry(value, 'ON', 0, 0)

    for legacy_value in _extract_values(item.get('perm')):
        _upsert_entry(legacy_value, 'ON', 0, 0)

    ordered_entries.sort(key=lambda row: (
        0 if str(row.get('enabled', 'ON')).strip().upper() == 'OFF' else 1,
        row['permutation'],
    ))
    return ordered_entries


def _get_domain_permutation_entries(domain, email=''):
    normalized_domain = _normalize_domain(domain)
    is_valid, _ = _validate_domain(normalized_domain)
    if not is_valid or not email or email == 'unknown':
        return []

    watchlist_table = _get_env_table('WATCHLIST_TABLE', 'watchlist')
    try:
        response = watchlist_table.get_item(
            Key={'pk': _watchlist_pk(email), 'sk': _watchlist_item_sk(email, normalized_domain)}
        )
    except (BotoCoreError, ClientError, KeyError, TypeError):
        return []

    return _extract_permutation_entries(response.get('Item') or {})


def _set_domain_permutation_enabled(domain, email, permutation, enabled):
    normalized_domain = _normalize_domain(domain)
    is_valid, _ = _validate_domain(normalized_domain)
    if not is_valid:
        return False, 'Domain is invalid.'

    if not email or email == 'unknown':
        return False, 'Could not determine user identity email.'

    normalized_permutation = _normalize_permutation_value(permutation)
    if not normalized_permutation:
        return False, 'Permutation is invalid.'

    enabled_state = _normalize_permutation_enabled(enabled)
    watchlist_table = _get_env_table('WATCHLIST_TABLE', 'watchlist')
    try:
        response = watchlist_table.get_item(
            Key={'pk': _watchlist_pk(email), 'sk': _watchlist_item_sk(email, normalized_domain)}
        )
    except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
        return False, 'An error occurred while loading the domain permutations.'

    item = response.get('Item')
    if not isinstance(item, dict):
        return False, 'Domain is not in your watchlist.'

    entries = _extract_permutation_entries(item)
    if not entries:
        return False, 'No permutations are available for this domain.'

    updated = False
    for entry in entries:
        if entry['permutation'] == normalized_permutation:
            entry['enabled'] = enabled_state
            updated = True
            break

    if not updated:
        return False, 'Permutation was not found for this domain.'

    item['permutations'] = [
        {
            'permutation': entry['permutation'],
            'enabled': entry['enabled'],
            'unique_domains': _normalize_permutation_metric(entry.get('unique_domains', 0)),
            'unique_sources': _normalize_permutation_metric(entry.get('unique_sources', 0)),
        }
        for entry in entries
    ]
    item['count'] = len(item['permutations'])
    item['updated'] = int(time.time())

    try:
        watchlist_table.put_item(Item=item)
    except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
        return False, 'An error occurred while updating the permutation.'

    return True, 'Permutation updated.'


def _get_permutation_count(domain, email=''):
    normalized_domain = _normalize_domain(domain)
    is_valid, _ = _validate_domain(normalized_domain)
    if not is_valid or not email or email == 'unknown':
        return 0

    watchlist_table = _get_env_table('WATCHLIST_TABLE', 'watchlist')
    try:
        response = watchlist_table.get_item(
            Key={'pk': _watchlist_pk(email), 'sk': _watchlist_item_sk(email, normalized_domain)},
            ProjectionExpression='#count',
            ExpressionAttributeNames={'#count': 'count'},
        )
        item = response.get('Item') or {}
        count = item.get('count')
        if isinstance(count, int):
            return count
        if isinstance(count, str) and count.isdigit():
            return int(count)
    except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
        pass

    return len(_get_domain_permutations(normalized_domain, email=email))


def _domain_has_priority_entries(sections):
    if not isinstance(sections, dict):
        return False

    suspect = sections.get('suspect') if isinstance(sections.get('suspect'), dict) else {}
    new_regs = sections.get('newRegistrations') if isinstance(sections.get('newRegistrations'), dict) else {}
    expired_regs = sections.get('expiredRegistrations') if isinstance(sections.get('expiredRegistrations'), dict) else {}

    return any(
        [
            bool(suspect.get('openSourceIntelligence')),
            bool(suspect.get('domainsMonitorSubscription')),
            bool(new_regs.get('daily')),
            bool(expired_regs.get('daily')),
        ]
    )


def _normalize_domain_list(domains):
    normalized_domains = []
    for domain in domains or []:
        normalized_domain = _normalize_domain(domain)
        if normalized_domain:
            normalized_domains.append(normalized_domain)
    return sorted(set(normalized_domains))


def _get_matched_slds(domains):
    normalized_domains = _normalize_domain_list(domains)
    if not normalized_domains:
        return set()

    cache_key = tuple(normalized_domains)
    cached_match = _get_cached_matched_slds(cache_key)
    if cached_match is not None:
        return cached_match

    matched_slds = _get_search_field_matches(normalized_domains)
    _cache_matched_slds(cache_key, matched_slds)
    return matched_slds


def _render_form(authorization_header, identity, domains=None, matched_slds=None, user_extra_fields=None, domains_monitor_subscription=None, highlighted_domains=None):
    auth_header_json = json.dumps(authorization_header)
    api_endpoint_json = json.dumps(_resolve_home_api_endpoint(API_ENDPOINT))
    logout_endpoint_json = json.dumps(_resolve_logout_endpoint(LOGOUT_ENDPOINT))
    safe_email = html.escape(identity.get('email', 'unknown'))
    normalized_domains = _normalize_domain_list(domains)
    highlighted_domain_set = {
        _normalize_domain(value)
        for value in (highlighted_domains or set())
        if _normalize_domain(value)
    }
    normalized_matched_slds = {
        str(value).strip().lower()
        for value in (matched_slds or set())
        if str(value).strip()
    }
    user_extra_fields = {
        str(key).strip().lower(): value
        for key, value in dict(user_extra_fields or {}).items()
        if str(key).strip().lower() in VISIBLE_PROFILE_FIELDS
    }
    domains_monitor_subscription = domains_monitor_subscription or {}
    domains_monitor_subscription_json = json.dumps(domains_monitor_subscription, default=_json_safe_value)
    subscription_email = html.escape(str(domains_monitor_subscription.get('email', '')).strip())
    subscription_preview = f'<div hidden><strong>Email:</strong> {subscription_email}</div>' if subscription_email else ''
    sponsor_value = user_extra_fields.get('sponsor', '').strip().lower() if user_extra_fields else ''
    if sponsor_value == 'data':
        configuration_row = '<br><strong>Configuration:</strong> <a class="inline-link" href="#" onclick="showSettings(); return false;">Settings</a>'
    else:
        configuration_row = ''

    ordered_user_fields = []
    preferred_order = list(VISIBLE_PROFILE_FIELDS)
    for field_name in preferred_order:
        raw_value = user_extra_fields.get(field_name)
        safe_value = html.escape(str(raw_value).strip()) if raw_value is not None else ''
        if not safe_value:
            continue
        ordered_user_fields.append(f'<br><strong>{field_name.title()}:</strong> {safe_value}')

    extra_identity_rows = ''.join(ordered_user_fields)
    domains_json = json.dumps(normalized_domains)

    if normalized_domains:
        rendered_domain_rows = []
        for domain in normalized_domains:
            safe_domain = html.escape(domain)
            sld, _ = _split_domain(domain)
            matched_class = ' matched-domain' if sld in normalized_matched_slds else ''
            bold_class = ' priority-domain' if domain in highlighted_domain_set else ''
            domain_literal = html.escape(json.dumps(domain), quote=True)
            rendered_domain_rows.append(
                f'<li><a class="inline-link{matched_class}{bold_class}" data-domain="{safe_domain}" href="#" onclick="showDomain({domain_literal}); return false;">{safe_domain}</a></li>'
            )
        domains_markup = ''.join(rendered_domain_rows)
        domains_list_tag = 'ol'
    else:
        domains_markup = '<li>Empty!</li>'
        domains_list_tag = 'ul'

    domains_section = (
        '<section class="watchlist-list">'
        '<h2>Watchlist</h2>'
        f'<{domains_list_tag}>{domains_markup}</{domains_list_tag}>'
        '</section>'
    )

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gone Fishing!</title>
    <style>
        body {{
            font-family: sans-serif;
            margin: 0;
            background: #f4f7fb;
            color: #10233c;
        }}

        body.modal-open {{
            overflow: hidden;
        }}

        body.modal-open {{
            overflow: hidden;
        }}

        main {{
            position: relative;
            max-width: 540px;
            margin: 48px auto;
            padding: 32px;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 18px 40px rgba(16, 35, 60, 0.12);
            text-align: center;
        }}

        img {{
            display: block;
            margin: 0 auto 16px;
            max-width: 220px;
        }}

        .card-actions {{
            position: absolute;
            top: 16px;
            right: 16px;
            display: flex;
            gap: 8px;
        }}

        .help-button,
        .help-button,
        .refresh-button,
        .logoff-button {{
            width: 34px;
            height: 34px;
            border: 1px solid #cbd5e1;
            border-radius: 50%;
            background: #ffffff;
            color: #10233c;
            font-weight: 700;
            line-height: 1;
            cursor: pointer;
            transition: background 0.15s ease, border-color 0.15s ease;
        }}

        .help-button:hover,
        .refresh-button:hover,
        .logoff-button:hover {{
            background: #f8fafc;
            border-color: #b9c6da;
        }}

        .identity {{
            text-align: left;
            margin: 16px 0;
            padding: 16px;
            border: 1px solid #e4e7ec;
            border-radius: 16px;
            background: #f8fafc;
        }}

        .watchlist-list {{
            margin-top: 18px;
            text-align: left;
            padding-top: 18px;
            border-top: 1px solid #d8e2f0;
        }}

        .watchlist-list h2 {{
            margin: 0 0 10px;
            font-size: 1.05rem;
        }}

        .inline-link {{
            color: #0e7490;
            text-decoration: none;
        }}

        .matched-domain {{
            font-weight: 700;
            color: #b42318;
        }}

        .priority-domain {{
            font-weight: 700;
        }}

        .watchlist-list ol {{
            margin: 12px 0 0;
            padding-left: 20px;
        }}

        .watchlist-list li + li {{
            margin-top: 6px;
        }}

        form {{
            text-align: left;
            margin-top: 18px;
            padding-top: 18px;
            border-top: 1px solid #d8e2f0;
        }}

        label {{
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
        }}

        input[type="text"] {{
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
        }}

        .options {{
            display: flex;
            gap: 16px;
            margin: 16px 0;
        }}

        .actions {{
            margin-top: 18px;
            text-align: center;
        }}

        .actions button,
        .btn-primary {{
            display: inline-block;
            border: 0;
            border-radius: 999px;
            background: #0e7490;
            color: #ffffff;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            padding: 12px 28px;
            text-decoration: none;
            line-height: 1;
            transition: background 0.15s ease;
        }}

        .actions button:hover,
        .btn-primary:hover {{
            background: #0c637b;
        }}

        .help-close {{
            display: inline-block;
            border: 0;
            border-radius: 999px;
            background: #0e7490;
            color: #ffffff;
            cursor: pointer;
            font-size: 1rem;
            padding: 12px 28px;
            font-weight: 600;
            line-height: 1;
            transition: background 0.15s ease;
        }}

        .help-close:hover {{
            background: #0c637b;
        }}

        a:focus-visible,
        button:focus-visible,
        input:focus-visible,
        summary:focus-visible {{
            outline: 3px solid #1d4ed8;
            outline-offset: 2px;
            border-radius: 8px;
        }}

        .domain-sections {{
            text-align: left;
            margin-top: 18px;
        }}

        .view-header {{
            margin: 8px 0 14px;
            padding-bottom: 14px;
            border-bottom: 1px solid #d8e2f0;
            text-align: center;
            line-height: 1.4;
        }}

        .view-header p {{
            margin: 0;
        }}

        .view-header p + p {{
            margin-top: 4px;
        }}

        .view-nav {{
            margin: 0 0 14px;
            text-align: center;
        }}

        .domain-sections h3 {{
            margin: 18px 0 10px;
            color: #10233c;
        }}

        .section-toggle {{
            margin-bottom: 12px;
            border: 1px solid #d8e2f0;
            border-radius: 14px;
            background: #f8fafc;
            overflow: hidden;
        }}

        .section-toggle summary {{
            padding: 12px 14px;
            cursor: pointer;
            font-weight: 600;
            color: #10233c;
            list-style: none;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .section-toggle summary::-webkit-details-marker {{
            display: none;
        }}

        .section-toggle summary::before {{
            content: '+';
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 20px;
            height: 20px;
            border-radius: 999px;
            background: #dbeafe;
            color: #1d4ed8;
            font-weight: 700;
            line-height: 1;
            flex-shrink: 0;
        }}

        .section-toggle[open] summary::before {{
            content: '-';
            background: #dbeafe;
            color: #1d4ed8;
        }}

        .section-toggle[open] summary {{
            border-bottom: 1px solid #d8e2f0;
            background: #eef4fb;
        }}

        .section-toggle ol,
        .section-toggle ul {{
            margin: 0;
            padding: 14px 18px 14px 38px;
        }}

        .section-toggle ul {{
            list-style: disc;
        }}

        .section-toggle li + li {{
            margin-top: 8px;
        }}

        .osint-attribution {{
            margin-top: 6px;
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}

        .attribution-chip {{
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 999px;
            border: 1px solid #bfdbfe;
            background: #eff6ff;
            color: #1e3a8a;
            font-size: 0.72rem;
            line-height: 1.4;
            text-decoration: none;
        }}

        .attribution-chip:hover {{
            background: #dbeafe;
            border-color: #93c5fd;
        }}

        .section-header-alert {{
            color: #ff0000;
        }}

        .section-header-warning {{
            color: #ff8c00;
        }}

        .exact-sld-text {{
            font-weight: 700;
            color: #ff0000;
        }}

        .attention-text {{
            font-weight: 600;
            color: #ff8c00;
        }}

        .permutation-list {{
            list-style: none;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}

        .permutation-row {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 14px 16px;
            border: 1px solid #d8e2f0;
            border-radius: 14px;
            background: #f8fafc;
        }}

        .permutation-main {{
            display: flex;
            flex-direction: column;
            gap: 6px;
            min-width: 0;
        }}

        .permutation-value {{
            font-weight: 700;
            word-break: break-word;
        }}

        .permutation-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            font-size: 0.92rem;
            color: #475467;
        }}

        .permutation-state {{
            display: inline-flex;
            align-items: center;
            padding: 2px 10px;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 700;
        }}

        .permutation-state.on {{
            background: #dcfce7;
            color: #166534;
        }}

        .permutation-state.off {{
            background: #fee2e2;
            color: #b42318;
        }}

        .permutation-count {{
            display: inline-flex;
            align-items: center;
            padding: 2px 10px;
            border-radius: 999px;
            background: #dbeafe;
            color: #1d4ed8;
            font-weight: 700;
        }}

        .permutation-action {{
            border: 0;
            border-radius: 999px;
            padding: 10px 18px;
            color: #ffffff;
            cursor: pointer;
            font-weight: 700;
            white-space: nowrap;
        }}

        .permutation-action.enable {{
            background: #166534;
        }}

        .permutation-action.disable {{
            background: #b42318;
        }}

        .permutation-action:disabled,
        .refresh-button:disabled {{
            opacity: 0.6;
            cursor: default;
        }}

        #refresh-error-banner {{
            margin: 0 0 12px;
            padding: 10px 12px;
            border: 1px solid #f5c2c7;
            border-radius: 10px;
            background: #fff5f5;
            color: #b42318;
            font-size: 0.92rem;
            text-align: left;
        }}

        .help-modal-overlay {{
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            background: rgba(16, 35, 60, 0.45);
            padding: 16px;
            z-index: 1000;
        }}

        .help-modal-overlay.open {{
            display: flex;
        }}

        .help-modal {{
            width: min(420px, 100%);
            padding: 18px 18px 14px;
            border: 1px solid #dbe4ee;
            border-radius: 14px;
            background: #ffffff;
            box-shadow: 0 18px 36px rgba(16, 35, 60, 0.2);
            text-align: left;
            max-height: 80vh;
            overflow-y: auto;
        }}

        .help-modal h2 {{
            margin: 0 0 12px;
            font-size: 1rem;
        }}

        .help-steps {{
            margin: 0;
            padding-left: 20px;
            color: #486581;
            font-size: 0.92rem;
        }}

        .help-steps li {{
            margin-bottom: 12px;
        }}

        .help-steps span {{
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            color: #10233c;
        }}

        @media (max-width: 640px) {{
            main {{
                margin: 20px 12px;
                padding: 24px 18px;
            }}

            .card-actions {{
                position: static;
                justify-content: center;
                margin-bottom: 16px;
            }}

            .options {{
                flex-direction: column;
                gap: 10px;
            }}

            .permutation-row {{
                flex-direction: column;
                align-items: stretch;
            }}

            .permutation-action {{
                width: 100%;
            }}
        }}
    </style>
</head>
<body>
    <section id="osint-help" class="help-modal-overlay" aria-hidden="true" aria-live="polite">
        <div class="help-modal" role="dialog" aria-modal="true" aria-label="OSINT Help">
            <h2 style="text-align:center">OSINT Help</h2>
            <ol class="help-steps">
                <li>
                    <span>Home View</span>
                    This is your main dashboard. Enter a domain in the Domain box, choose an action, and select <b>Submit</b> to continue.
                </li>
                <li>
                    <span>Remove</span>
                    Select <b>Remove</b> when you want to delete a domain from your watchlist. The domain must already exist in your list.
                </li>
                <li>
                    <span>Add</span>
                    Select <b>Add</b> to track a new domain. Domains must be entered as a single base domain, for example example.com.
                </li>
                <li>
                    <span>Domain format rules</span>
                    Enter one base domain only, such as <b>example.com</b>. Do not include subdomains like <b>mail.example.com</b>.
                </li>
                <li>
                    <span>Settings</span>
                    Open <b>Configuration</b> to verify and save your Domains Monitor API token. Saved subscription details appear on that screen.
                </li>
                <li>
                    <span>Domain View</span>
                    Select any domain from your list to open detailed sections for suspect domains, new domains, and expired domains.
                </li>
                <li>
                    <span>Permutations View</span>
                    In Domain View, select the permutations count to review detected variations. Use <b>Enable</b> or <b>Disable</b> to control each permutation.
                </li>
                <li>
                    <span>How to read results</span>
                    Matched domains are signals for review, not automatic proof of malicious activity.
                </li>
                <li>
                    <span>Data freshness</span>
                    Feeds refresh throughout the day, so very recent changes may take time to appear.
                </li>
                <li>
                    <span>Quick controls</span>
                    Use <b>?</b> for help, <b>↺</b> to refresh data, and <b>X</b> to log off.
                </li>
                <li>
                    <span>Session and support</span>
                    Inactive sessions may require sign-in again. If data or access looks wrong, contact your sponsor or administrator.
                </li>
            </ol>
            <div style="text-align:center">
                <button class="help-close" type="button" onclick="closeHelp()">Close</button>
            </div>
        </div>
    </section>
    <main>
        <div class="card-actions">
            <button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>
            <button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>
            <button class="logoff-button" type="button" title="Cognito Log Off" onclick="logOff()">X</button>
        </div>

        <img src="https://cdn.4n6ir.com/lunker.png" alt="OSINT Logo">

        <h1>Gone Fishing!</h1>
        <div class="identity">
            <strong>Email:</strong> {safe_email}
            {configuration_row}
            {extra_identity_rows}
        </div>
        {subscription_preview}

        <form id="home-form">
            <label for="entry">Domain</label>
            <input id="entry" name="entry" type="text" required>

            <div class="options">
                <label><input type="radio" name="action" value="PutItem" checked> Add</label>
                <label><input type="radio" name="action" value="DeleteItem"> Remove</label>
            </div>

            <p id="entry-print"></p>
            <div class="actions"><button type="button" onclick="submitHomeForm()">Submit</button></div>
            {domains_section}
        </form>

        <section id="dynamic-view"></section>
    </main>

    <script>
        var initialDomains = {domains_json};
        var activeView = {{
            name: 'home',
            domain: ''
        }};
        var refreshInFlight = false;
        var domainSectionsAbortController = null;
        var domainPermutationsAbortController = null;
        var domainDetailsCache = new Map();
        var domainPermutationsCache = new Map();

        function buildAuthHeaders(authHeader, forceRefresh = false) {{
            const headers = authHeader ? {{ 'Authorization': authHeader }} : {{}};
            if (forceRefresh) {{
                headers['X-OSINT-Refresh'] = '1';
            }}
            return headers;
        }}

        function clearDomainViewCaches() {{
            domainDetailsCache.clear();
            domainPermutationsCache.clear();
        }}

        function containsSldMatch(item, matchSld) {{
            const normalizedItem = normalizeDomainKey(item);
            const normalizedMatch = normalizeDomainKey(matchSld);
            if (!normalizedItem || !normalizedMatch) {{
                return false;
            }}

            const itemSld = extractSld(normalizedItem);
            return itemSld.includes(normalizedMatch);
        }}

        function setRefreshButtonsDisabled(disabled) {{
            document.querySelectorAll('.refresh-button').forEach((button) => {{
                button.disabled = Boolean(disabled);
            }});
        }}

        function showRefreshError(message) {{
            const existing = document.getElementById('refresh-error-banner');
            if (existing) {{
                existing.remove();
            }}

            const banner = document.createElement('div');
            banner.id = 'refresh-error-banner';
            banner.textContent = message || 'Refresh failed. Please try again.';
            const main = document.querySelector('main');
            if (main) {{
                main.prepend(banner);
            }}
        }}

        function validateDomain(domain) {{
            const issues = [];
            if (!domain) {{
                issues.push('Domain is required.');
            }}

            const labels = String(domain || '').split('.');
            if (labels.length < 2 || (labels.length === 2 && labels[1] === '')) {{
                issues.push('Domain must include a single dot (e.g. example.com).');
            }}
            if (labels.length !== 2) {{
                issues.push('Domain must contain exactly one dot (no subdomains allowed).');
            }}

            const sld = labels[0] || '';
            const tld = labels[1] || '';
            if (sld && !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(sld)) {{
                issues.push('Second-level label must start/end with an alphanumeric character.');
            }}
            if (tld && !/^[a-z0-9-]{{2,63}}$/.test(tld)) {{
                issues.push('Top-level label must be 2-63 chars using alphanumeric or dash.');
            }}

            return issues;
        }}

        async function submitHomeForm() {{
            const form = document.getElementById('home-form');
            const formData = new FormData(form);
            const action = formData.get('action');
            const entry = formData.get('entry');
            const authHeader = {auth_header_json};
            const normalizedEntry = (entry || '').trim().toLowerCase();
            const entryPrint = document.getElementById('entry-print');

            document.getElementById('entry').value = normalizedEntry;
            const issues = validateDomain(normalizedEntry);
            if (issues.length > 0) {{
                entryPrint.style.color = '#b42318';
                entryPrint.innerHTML = issues.join('<br>');
                return;
            }}

            entryPrint.style.color = '#166534';
            entryPrint.textContent = 'Submitting…';

            try {{
                const response = await fetch({api_endpoint_json}, {{
                    method: 'POST',
                    credentials: 'include',
                    cache: 'no-store',
                    headers: {{
                        'Content-Type': 'application/json',
                        ...(authHeader ? {{ 'Authorization': authHeader }} : {{}})
                    }},
                    body: JSON.stringify({{ action, entry: normalizedEntry }})
                }});
                if (!response.ok) {{
                    entryPrint.style.color = '#b42318';
                    entryPrint.textContent = 'Submission failed: HTTP ' + response.status;
                    return;
                }}
                const htmlBody = await response.text();
                document.open();
                document.write(htmlBody);
                document.close();
            }} catch (err) {{
            entryPrint.style.color = '#b42318';
            entryPrint.textContent = 'Submission failed: ' + err.message;
            }}
        }}

        async function goHome(forceRefresh = false) {{
            activeView = {{
                name: 'home',
                domain: ''
            }};
            const authHeader = {auth_header_json} || '';
            try {{
                const r = await fetch({api_endpoint_json}, {{
                    method: 'GET',
                    credentials: 'include',
                    cache: 'no-store',
                    headers: buildAuthHeaders(authHeader, forceRefresh)
                }});
                if (!r.ok || r.redirected) {{
                    throw new Error('Home reload was redirected or failed: ' + r.status);
                }}
                const h = await r.text();
                document.open();
                document.write(h);
                document.close();
            }} catch (err) {{
                console.error('Failed to load home view.', err);
                showRefreshError('Failed to load home view. Please try again.');
            }}
        }}

        async function refreshCurrentView(event) {{
            if (event) {{
                event.preventDefault();
                event.stopPropagation();
            }}

            if (refreshInFlight) {{
                return;
            }}

            refreshInFlight = true;
            setRefreshButtonsDisabled(true);

            try {{
                if (activeView.name === 'domain' && activeView.domain) {{
                    domainDetailsCache.delete(activeView.domain);
                    domainPermutationsCache.delete(activeView.domain);
                    await showDomain(activeView.domain);
                    return;
                }}

                if (activeView.name === 'permutations' && activeView.domain) {{
                    domainDetailsCache.delete(activeView.domain);
                    domainPermutationsCache.delete(activeView.domain);
                    await showPermutations(activeView.domain);
                    return;
                }}

                if (activeView.name === 'settings') {{
                    clearDomainViewCaches();
                    await goHome();
                    return;
                }}

                clearDomainViewCaches();
                await goHome();
            }} catch (err) {{
                showRefreshError('Refresh failed. Please try again.');
            }} finally {{
                refreshInFlight = false;
                setRefreshButtonsDisabled(false);
            }}
        }}

        async function fetchDomainSections(domain, forceRefresh = false) {{
            if (domainSectionsAbortController) {{
                domainSectionsAbortController.abort();
            }}
            domainSectionsAbortController = new AbortController();
            const requestController = domainSectionsAbortController;

            const authHeader = {auth_header_json} || '';
            try {{
                const response = await fetch({api_endpoint_json}, {{
                    method: 'POST',
                    credentials: 'include',
                    cache: 'no-store',
                    signal: requestController.signal,
                    headers: {{
                        'Content-Type': 'application/json',
                        ...buildAuthHeaders(authHeader, forceRefresh)
                    }},
                    body: JSON.stringify({{ action: 'GetDomainSections', entry: domain }})
                }});
                if (domainSectionsAbortController !== requestController) {{
                    return null;
                }}
                return await response.json();
            }} catch (err) {{
                if (err && err.name === 'AbortError') {{
                    return null;
                }}
                throw err;
            }}
        }}

        async function fetchDomainPermutations(domain, forceRefresh = false) {{
            if (domainPermutationsAbortController) {{
                domainPermutationsAbortController.abort();
            }}
            domainPermutationsAbortController = new AbortController();
            const requestController = domainPermutationsAbortController;

            const authHeader = {auth_header_json} || '';
            try {{
                const response = await fetch({api_endpoint_json}, {{
                    method: 'POST',
                    credentials: 'include',
                    cache: 'no-store',
                    signal: requestController.signal,
                    headers: {{
                        'Content-Type': 'application/json',
                        ...buildAuthHeaders(authHeader, forceRefresh)
                    }},
                    body: JSON.stringify({{ action: 'GetDomainPermutations', entry: domain }})
                }});
                if (domainPermutationsAbortController !== requestController) {{
                    return {{ terms: [], items: [] }};
                }}
                const payload = await response.json();
                let items = Array.isArray(payload.permutationStates) ? payload.permutationStates : [];
                const terms = items.length > 0
                    ? items
                        .filter(item => _normalizePermutationEnabled(item?.enabled) === 'ON')
                        .map(item => normalizeDomainKey(item?.permutation))
                        .filter(term => term)
                    : (Array.isArray(payload.permutations) ? payload.permutations : []);

                if (items.length === 0 && Array.isArray(terms) && terms.length > 0) {{
                    items = terms
                        .map(term => extractSld(term))
                        .filter(term => term)
                        .map(term => ({{ permutation: term, enabled: 'ON', unique_domains: 0, unique_sources: 0 }}));
                }}
                return {{ terms, items }};
            }} catch (err) {{
                if (err && err.name === 'AbortError') {{
                    return {{ terms: [], items: [] }};
                }}
                throw err;
            }}
        }}

        async function togglePermutation(domain, permutation, enabled, event) {{
            if (event) {{
                event.preventDefault();
                event.stopPropagation();
            }}

            const authHeader = {auth_header_json} || '';
            const normalizedDomain = normalizeDomainKey(domain);
            const normalizedPermutation = normalizeDomainKey(permutation);
            const nextEnabled = Boolean(enabled);

            const allButtons = Array.from(document.querySelectorAll('button[data-permutation-toggle="true"]'));
            allButtons.forEach((button) => {{
                button.disabled = true;
            }});

            try {{
                const response = await fetch({api_endpoint_json}, {{
                    method: 'POST',
                    credentials: 'include',
                    cache: 'no-store',
                    headers: {{
                        'Content-Type': 'application/json',
                        ...(authHeader ? {{ 'Authorization': authHeader }} : {{}})
                    }},
                    body: JSON.stringify({{
                        action: 'ToggleDomainPermutation',
                        entry: normalizedDomain,
                        permutation: normalizedPermutation,
                        enabled: nextEnabled ? 'ON' : 'OFF',
                    }})
                }});

                const payload = await response.json().catch(() => ({{}}));
                if (!response.ok || !payload || !payload.ok) {{
                    throw new Error(payload?.message || ('HTTP ' + response.status));
                }}

                const cached = domainPermutationsCache.get(normalizedDomain) || {{ terms: [], items: [] }};
                const currentItems = Array.isArray(cached.items) ? cached.items : [];
                const updatedItems = currentItems.map((item) => {{
                    const itemPermutation = normalizeDomainKey(item?.permutation);
                    if (itemPermutation !== normalizedPermutation) {{
                        return item;
                    }}
                    return {{
                        ...item,
                        enabled: nextEnabled ? 'ON' : 'OFF',
                    }};
                }});

                const updatedTerms = updatedItems
                    .filter((item) => _normalizePermutationEnabled(item?.enabled) === 'ON')
                    .map((item) => normalizeDomainKey(item?.permutation))
                    .filter((term) => term);

                domainPermutationsCache.set(normalizedDomain, {{
                    terms: updatedTerms,
                    items: updatedItems,
                }});
                renderPermutationsView(normalizedDomain, updatedItems);
            }} catch (err) {{
                showRefreshError('Failed to update permutation state: ' + (err?.message || 'Unexpected error.'));
                await showPermutations(normalizedDomain);
            }} finally {{
                allButtons.forEach((button) => {{
                    button.disabled = false;
                }});
            }}
        }}

        function escapeHtml(value) {{
            return String(value || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
        }}

        function normalizeDomainKey(value) {{
            if (value && typeof value === 'object') {{
                const objectValue =
                    value.domain ??
                    value.result ??
                    value.value ??
                    value.permutation ??
                    '';
                return String(objectValue || '').trim().toLowerCase();
            }}

            return String(value || '').trim().toLowerCase();
        }}

        function _normalizeAttributionUrl(value) {{
            const normalizedValue = String(value || '').trim();
            if (!normalizedValue) {{
                return '';
            }}

            if (!/^https?:\\/\\//i.test(normalizedValue)) {{
                return '';
            }}

            return normalizedValue;
        }}

        function _deriveAttributionLabel(url) {{
            const normalizedUrl = _normalizeAttributionUrl(url);
            if (!normalizedUrl) {{
                return '';
            }}

            try {{
                const parsed = new URL(normalizedUrl);
                const hostname = String(parsed.hostname || '').replace(/^www\\./i, '').toLowerCase();
                const pathParts = String(parsed.pathname || '')
                    .split('/')
                    .filter(Boolean);

                if ((hostname === 'github.com' || hostname === 'raw.githubusercontent.com') && pathParts.length >= 2) {{
                    return pathParts[0] + '/' + pathParts[1];
                }}

                return hostname || normalizedUrl;
            }} catch (_err) {{
                return normalizedUrl;
            }}
        }}

        function _getAttributionEntries(item) {{
            if (!item || typeof item !== 'object') {{
                return [];
            }}

            const rawEntries = Array.isArray(item.attribution)
                ? item.attribution
                : (Array.isArray(item.attributions) ? item.attributions : []);
            const normalizedEntries = [];
            const seenByUrl = new Set();
            const seenByName = new Set();

            rawEntries.forEach((entry) => {{
                let rawName = '';
                let rawUrl = '';

                if (typeof entry === 'string') {{
                    rawUrl = entry;
                    rawName = entry;
                }} else if (entry && typeof entry === 'object') {{
                    rawUrl = entry.url || entry.href || entry.link || '';
                    rawName = entry.name || entry.label || entry.source || rawUrl || '';
                }} else {{
                    return;
                }}

                const normalizedUrl = _normalizeAttributionUrl(rawUrl);
                const normalizedName = String(rawName || '').trim() || _deriveAttributionLabel(normalizedUrl);
                if (!normalizedName && !normalizedUrl) {{
                    return;
                }}

                if (normalizedUrl) {{
                    const urlKey = normalizedUrl.toLowerCase();
                    if (seenByUrl.has(urlKey)) {{
                        return;
                    }}
                    seenByUrl.add(urlKey);
                }} else {{
                    const nameKey = normalizedName.toLowerCase();
                    if (seenByName.has(nameKey)) {{
                        return;
                    }}
                    seenByName.add(nameKey);
                }}

                normalizedEntries.push({{
                    name: normalizedName,
                    url: normalizedUrl,
                }});
            }});

            return normalizedEntries;
        }}

        function _renderAttribution(item) {{
            const entries = _getAttributionEntries(item);
            if (entries.length === 0) {{
                return '';
            }}

            const chips = entries.map((entry) => {{
                const safeName = escapeHtml(entry.name || 'source');
                if (entry.url) {{
                    const safeUrl = escapeHtml(entry.url);
                    return '<a class="attribution-chip" href="' + safeUrl + '" target="_blank" rel="noopener noreferrer nofollow">' + safeName + '</a>';
                }}

                return '<span class="attribution-chip">' + safeName + '</span>';
            }}).join('');

            return '<div class="osint-attribution">' + chips + '</div>';
        }}

        function extractSld(value) {{
            const normalized = normalizeDomainKey(value);
            if (!normalized) {{
                return '';
            }}

            return normalized.includes('.') ? normalized.split('.', 1)[0] : normalized;
        }}

        function containsPermutationMatch(item, permutationTerms) {{
            const normalizedItem = normalizeDomainKey(item);
            if (!normalizedItem) {{
                return false;
            }}

            return (Array.isArray(permutationTerms) ? permutationTerms : []).some(term => {{
                const normalizedTerm = normalizeDomainKey(term);
                return normalizedTerm && normalizedItem.includes(normalizedTerm);
            }});
        }}

        function markSubstringMatches(styleMap, normalizedText, term, styleCode) {{
            const normalizedTerm = normalizeDomainKey(term);
            if (!normalizedTerm) {{
                return;
            }}

            let startIndex = 0;
            while (startIndex < normalizedText.length) {{
                const matchIndex = normalizedText.indexOf(normalizedTerm, startIndex);
                if (matchIndex === -1) {{
                    break;
                }}

                const endIndex = matchIndex + normalizedTerm.length;
                for (let idx = matchIndex; idx < endIndex; idx += 1) {{
                    styleMap[idx] = Math.max(styleMap[idx], styleCode);
                }}

                startIndex = endIndex;
            }}
        }}

        function highlightDomainSubstrings(item, exactTerms, permutationTerms) {{
            const rawText = String(item || '');
            const normalizedText = rawText.toLowerCase();
            if (!rawText) {{
                return '';
            }}

            const styleMap = new Array(rawText.length).fill(0);
            const safePermutationTerms = Array.isArray(permutationTerms) ? permutationTerms : [];

            safePermutationTerms
                .map(term => normalizeDomainKey(term))
                .filter(term => term)
                .sort((a, b) => b.length - a.length)
                .forEach(term => markSubstringMatches(styleMap, normalizedText, term, 1));

            const safeExactTerms = (Array.isArray(exactTerms) ? exactTerms : [exactTerms])
                .map(term => normalizeDomainKey(term))
                .filter(term => term);
            
            // Exact/high-priority style applies to matched SLD substrings in the left label.
            if (safeExactTerms.length > 0) {{
                const dotIndex = normalizedText.indexOf('.');
                const domainSld = dotIndex > 0 ? normalizedText.substring(0, dotIndex) : normalizedText;
                const sldEndIndex = dotIndex > 0 ? dotIndex : rawText.length;

                safeExactTerms.forEach((term) => {{
                    if (!term) {{
                        return;
                    }}

                    let startIndex = 0;
                    while (startIndex < domainSld.length) {{
                        const matchIndex = domainSld.indexOf(term, startIndex);
                        if (matchIndex === -1) {{
                            break;
                        }}

                        const endIndex = matchIndex + term.length;
                        for (let idx = matchIndex; idx < endIndex && idx < sldEndIndex; idx += 1) {{
                            styleMap[idx] = 2;
                        }}

                        startIndex = endIndex;
                    }}
                }});
            }}

            if (!styleMap.some(value => value > 0)) {{
                return escapeHtml(rawText);
            }}

            let output = '';
            let segmentStart = 0;
            while (segmentStart < rawText.length) {{
                const styleCode = styleMap[segmentStart];
                let segmentEnd = segmentStart + 1;
                while (segmentEnd < rawText.length && styleMap[segmentEnd] === styleCode) {{
                    segmentEnd += 1;
                }}

                const segmentText = escapeHtml(rawText.slice(segmentStart, segmentEnd));
                if (styleCode === 2) {{
                    output += '<span class="exact-sld-text">' + segmentText + '</span>';
                }} else if (styleCode === 1) {{
                    output += '<span class="attention-text">' + segmentText + '</span>';
                }} else {{
                    output += segmentText;
                }}

                segmentStart = segmentEnd;
            }}

            return output;
        }}

        function containsSldMatch(item, matchSld) {{
            const normalizedMatch = normalizeDomainKey(matchSld);
            if (!normalizedMatch) {{
                return false;
            }}

            const normalizedItem = normalizeDomainKey(item);
            if (!normalizedItem) {{
                return false;
            }}

            const itemSld = extractSld(normalizedItem);
            return itemSld.includes(normalizedMatch);
        }}

        function getHeaderHighlightLevel(items, matchSld, permutationTerms) {{
            const safeItems = Array.isArray(items) ? items : [];
            const hasExactSldMatch = safeItems.some(item => containsSldMatch(item, matchSld));
            if (hasExactSldMatch) {{
                return 'alert';
            }}

            const hasPermutationMatch = safeItems.some(item => containsPermutationMatch(item, permutationTerms));
            if (hasPermutationMatch) {{
                return 'warning';
            }}

            return 'none';
        }}

        function formatSectionHeader(label, count, alertIfPositive = false) {{
            const safeLabel = escapeHtml(label);
            const safeCount = escapeHtml(String(count));
            const text = safeLabel + ' - ' + safeCount;

            if (alertIfPositive && count > 0) {{
                return '<span class="section-header-alert"><strong>' + text + '</strong></span>';
            }}

            return text;
        }}

        function renderNumberedList(items, emphasize = false, matchSld = '', permutationTerms = [], options = {{}}) {{
            if (!Array.isArray(items) || items.length === 0) {{
                return '<ul><li>Empty!</li></ul>';
            }}

            const showAttribution = Boolean(options.showAttribution);

            const rows = items
                .map(item => {{
                    const normalizedItem = normalizeDomainKey(item);
                    const hasExactMatch = containsSldMatch(normalizedItem, matchSld);
                    const hasPermutationMatch = containsPermutationMatch(normalizedItem, permutationTerms);
                    const highlightItem = emphasize && (hasExactMatch || hasPermutationMatch);
                    const attributionMarkup = showAttribution ? _renderAttribution(item) : '';

                    if (!highlightItem) {{
                        return '<li>' + escapeHtml(normalizedItem) + attributionMarkup + '</li>';
                    }}

                    if (hasExactMatch) {{
                        // Priority findings: highlight only the matched SLD substring in red.
                        return '<li>' + highlightDomainSubstrings(normalizedItem, [matchSld], []) + attributionMarkup + '</li>';
                    }}

                    return '<li>' + highlightDomainSubstrings(normalizedItem, [], permutationTerms) + attributionMarkup + '</li>';
                }})
                .join('');
            return '<ol>' + rows + '</ol>';
        }}

        function dedupeByPriority(section) {{
            const safeSection = section || {{}};
            const seen = new Set();
            const filterBySeen = (items) => (Array.isArray(items) ? items : []).filter(item => {{
                const key = normalizeDomainKey(item);
                if (!key || seen.has(key)) {{
                    return false;
                }}
                seen.add(key);
                return true;
            }});

            return {{
                daily: filterBySeen(safeSection.daily),
                weekly: filterBySeen(safeSection.weekly),
                monthly: filterBySeen(safeSection.monthly),
            }};
        }}

        function getEmptySections() {{
            return {{
                suspect: {{
                    openSourceIntelligence: [],
                    domainsMonitorSubscription: []
                }},
                newRegistrations: {{
                    daily: [],
                    weekly: [],
                    monthly: []
                }},
                expiredRegistrations: {{
                    daily: [],
                    weekly: [],
                    monthly: []
                }}
            }};
        }}

        function renderCollapsibleList(label, items, options = {{}}) {{
            const safeItems = Array.isArray(items) ? items : [];
            const count = safeItems.length;
            const emphasizeRows = Boolean(options.emphasizeRows);
            const alertIfPositive = Boolean(options.alertIfPositive);
            const matchSld = extractSld(options.matchSld);
            const permutationTerms = Array.isArray(options.permutationTerms) ? options.permutationTerms : [];
            const headerHighlightLevel = getHeaderHighlightLevel(safeItems, matchSld, permutationTerms);
            const shouldAlertHeader = alertIfPositive && count > 0 && headerHighlightLevel === 'alert';
            const shouldWarnHeader = alertIfPositive && count > 0 && headerHighlightLevel === 'warning';
            const baseHeader = formatSectionHeader(label, count, shouldAlertHeader);
            const styledHeader = shouldWarnHeader
                ? '<span class="section-header-warning"><strong>' + baseHeader + '</strong></span>'
                : baseHeader;

            return '<details class="section-toggle">' +
                '<summary>' + styledHeader + '</summary>' +
                renderNumberedList(safeItems, emphasizeRows, matchSld, permutationTerms, options) +
                '</details>';
        }}

        async function getDomainPermutationTerms(domain) {{
            const permutations = await fetchDomainPermutations(domain, true);
            domainPermutationsCache.set(domain, permutations);

            const terms = Array.isArray(permutations?.terms) ? permutations.terms : [];
            return terms.map(term => normalizeDomainKey(term)).filter(term => term);
        }}

        function renderDomainView(domain, domainDetails) {{
            const safeDomain = escapeHtml(domain);
            const domainLiteral = JSON.stringify(String(domain || '')).replace(/"/g, '&quot;');
            const selectedSld = extractSld(domain);
            const rawSections = domainDetails?.sections || getEmptySections();
            const safeSections = {{
                suspect: {{
                    openSourceIntelligence: Array.isArray(rawSections.suspect?.openSourceIntelligence)
                        ? rawSections.suspect.openSourceIntelligence
                        : [],
                    domainsMonitorSubscription: Array.isArray(rawSections.suspect?.domainsMonitorSubscription)
                        ? rawSections.suspect.domainsMonitorSubscription
                        : [],
                }},
                newRegistrations: dedupeByPriority(rawSections.newRegistrations),
                expiredRegistrations: dedupeByPriority(rawSections.expiredRegistrations),
                _noDomainsMonitor: Boolean(rawSections._noDomainsMonitor),
            }};
            const hasDomainsMonitor = !Boolean(safeSections?._noDomainsMonitor);
            const hasMonitorRows = Boolean(
                (safeSections.suspect?.domainsMonitorSubscription || []).length ||
                (safeSections.newRegistrations?.daily || []).length ||
                (safeSections.newRegistrations?.weekly || []).length ||
                (safeSections.newRegistrations?.monthly || []).length ||
                (safeSections.expiredRegistrations?.daily || []).length ||
                (safeSections.expiredRegistrations?.weekly || []).length ||
                (safeSections.expiredRegistrations?.monthly || []).length
            );
            const safePermutations = Number.isFinite(domainDetails?.permutations)
                ? domainDetails.permutations
                : 0;
            const permutationTerms = Array.isArray(domainDetails?.permutationTerms)
                ? domainDetails.permutationTerms
                : [];

            domainDetailsCache.set(domain, {{
                sections: safeSections,
                permutations: safePermutations,
                permutationTerms,
            }});

            document.querySelector('main').innerHTML =
                '<div class="card-actions">' +
                '<button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>' +
                '<button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>' +
                '<button class="logoff-button" type="button" title="Cognito Log Off" onclick="logOff()">X</button>' +
                '</div>' +
                '<img src="https://cdn.4n6ir.com/lunker.png" alt="OSINT Logo">' +
                '<div class="view-header">' +
                '<p style="margin:0;"><strong>Domain:</strong> ' + safeDomain + '</p>' +
                '<p style="margin:4px 0 0;"><strong>Permutations:</strong> <a class="inline-link" href="#" onclick="showPermutations(' + domainLiteral + '); return false;">' + String(safePermutations) + '</a></p>' +
                '</div>' +
                '<div class="view-nav">' +
                '<a class="btn-primary" href="#" onclick="goHome(); return false;">Back</a>' +
                '</div>' +
                '<div class="domain-sections">' +
                '<h3>Suspect Domains</h3>' +
                renderCollapsibleList('Open Source Intelligence', safeSections.suspect?.openSourceIntelligence || [], {{ emphasizeRows: true, alertIfPositive: true, matchSld: selectedSld, permutationTerms, showAttribution: true }}) +
                ((hasDomainsMonitor || hasMonitorRows)
                    ? renderCollapsibleList('Domains Monitor Subscription', safeSections.suspect?.domainsMonitorSubscription || [], {{ emphasizeRows: true, alertIfPositive: true, matchSld: selectedSld, permutationTerms }})
                    : '') +
                ((hasDomainsMonitor || hasMonitorRows)
                    ? '<h3>New Domains</h3>' +
                        renderCollapsibleList('Daily', safeSections.newRegistrations?.daily || [], {{ emphasizeRows: true, alertIfPositive: true, matchSld: selectedSld, permutationTerms }}) +
                        renderCollapsibleList('Weekly', safeSections.newRegistrations?.weekly || [], {{ emphasizeRows: true, alertIfPositive: true, matchSld: selectedSld, permutationTerms }}) +
                        renderCollapsibleList('Monthly', safeSections.newRegistrations?.monthly || [], {{ emphasizeRows: true, alertIfPositive: true, matchSld: selectedSld, permutationTerms }}) +
                        '<h3>Expired Domains</h3>' +
                        renderCollapsibleList('Daily', safeSections.expiredRegistrations?.daily || [], {{ emphasizeRows: true, alertIfPositive: true, matchSld: selectedSld, permutationTerms }}) +
                        renderCollapsibleList('Weekly', safeSections.expiredRegistrations?.weekly || [], {{ emphasizeRows: true, alertIfPositive: true, matchSld: selectedSld, permutationTerms }}) +
                        renderCollapsibleList('Monthly', safeSections.expiredRegistrations?.monthly || [], {{ emphasizeRows: true, alertIfPositive: true, matchSld: selectedSld, permutationTerms }})
                    : '') +
                '</div>';
        }}

        function renderPermutationsView(domain, permutations) {{
            const safeDomain = escapeHtml(domain);
            const domainLiteral = JSON.stringify(String(domain || '')).replace(/"/g, '&quot;');
            const selectedSld = extractSld(domain);
            const rows = Array.isArray(permutations) ? permutations : [];
            const sortedRows = [...rows].sort((left, right) => {{
                const leftOff = _normalizePermutationEnabled(left?.enabled) === 'OFF' ? 0 : 1;
                const rightOff = _normalizePermutationEnabled(right?.enabled) === 'OFF' ? 0 : 1;
                if (leftOff !== rightOff) {{
                    return leftOff - rightOff;
                }}

                const leftDomains = _normalizePermutationMetric(left?.unique_domains);
                const rightDomains = _normalizePermutationMetric(right?.unique_domains);
                if (leftDomains !== rightDomains) {{
                    return rightDomains - leftDomains;
                }}

                const leftSources = _normalizePermutationMetric(left?.unique_sources);
                const rightSources = _normalizePermutationMetric(right?.unique_sources);
                if (leftSources !== rightSources) {{
                    return rightSources - leftSources;
                }}

                const leftPermutation = normalizeDomainKey(left?.permutation);
                const rightPermutation = normalizeDomainKey(right?.permutation);
                return leftPermutation.localeCompare(rightPermutation);
            }});

            const renderedRows = sortedRows.length > 0
                ? '<ul class="permutation-list">' + sortedRows.map((row) => {{
                    const rawPermutation = normalizeDomainKey(row?.permutation);
                    const isEnabled = _normalizePermutationEnabled(row?.enabled);
                    const uniqueDomains = _normalizePermutationMetric(row?.unique_domains);
                    const uniqueSources = _normalizePermutationMetric(row?.unique_sources);
                    const statusClass = isEnabled === 'ON' ? 'on' : 'off';
                    const statusLabel = isEnabled === 'ON' ? 'ON' : 'OFF';
                    const actionLabel = isEnabled === 'ON' ? 'Disable' : 'Enable';
                    const actionClass = isEnabled === 'ON' ? 'disable' : 'enable';
                    const targetEnabled = isEnabled === 'ON' ? 'false' : 'true';
                    const clickHandler = 'togglePermutation(' +
                        domainLiteral + ', ' +
                        JSON.stringify(rawPermutation).replace(/"/g, '&quot;') + ', ' +
                        targetEnabled +
                        ', event); return false;';

                    return '<li class="permutation-row">' +
                        '<div class="permutation-main">' +
                        '<span class="permutation-value">' + highlightDomainSubstrings(rawPermutation, [selectedSld], []) + '</span>' +
                        '<div class="permutation-meta">' +
                        '<span class="permutation-state ' + statusClass + '">' + statusLabel + '</span>' +
                        '<span class="permutation-count">Domains: ' + String(uniqueDomains) + '</span>' +
                        '<span class="permutation-count">Sources: ' + String(uniqueSources) + '</span>' +
                        '</div>' +
                        '</div>' +
                        '<button data-permutation-toggle="true" class="permutation-action ' + actionClass + '" type="button" onclick="' + clickHandler + '">' + actionLabel + '</button>' +
                        '</li>';
                }}).join('') + '</ul>'
                : '<ol><li>Empty!</li></ol>';

            document.querySelector('main').innerHTML =
                '<div class="card-actions">' +
                '<button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>' +
                '<button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>' +
                '<button class="logoff-button" type="button" title="Cognito Log Off" onclick="logOff()">X</button>' +
                '</div>' +
                '<img src="https://cdn.4n6ir.com/lunker.png" alt="OSINT Logo">' +
                '<div class="view-header">' +
                '<p><strong>Domain:</strong> ' + safeDomain + '</p>' +
                '<p><strong>Permutations:</strong> ' + String(sortedRows.length) + '</p>' +
                '</div>' +
                '<div class="view-nav">' +
                '<a class="btn-primary" href="#" onclick="showDomain(' + domainLiteral + '); return false;">Back</a>' +
                '</div>' +
                '<div class="domain-sections">' +
                '<h3>Permutations</h3>' +
                renderedRows +
                '</div>';
        }}

            function _normalizePermutationEnabled(value) {{
                return String(value || '').trim().toUpperCase() === 'OFF' ? 'OFF' : 'ON';
            }}

            function _normalizePermutationMetric(value) {{
                const parsed = Number.parseInt(String(value ?? '').trim(), 10);
                if (!Number.isFinite(parsed) || parsed < 0) {{
                    return 0;
                }}
                return parsed;
            }}

        async function showDomain(domain, forceRefresh = false) {{
            activeView = {{
                name: 'domain',
                domain,
            }};
            domainDetailsCache.delete(domain);
            const domainDetails = await fetchDomainSections(domain, true);
            const safeDomainDetails = (domainDetails && typeof domainDetails === 'object') ? domainDetails : {{}};
            const [resolvedDomainDetails, permutationTerms] = await Promise.all([
                Promise.resolve(safeDomainDetails),
                getDomainPermutationTerms(domain),
            ]);
            renderDomainView(domain, {{
                ...resolvedDomainDetails,
                permutationTerms,
            }});
        }}

        async function showPermutations(domain, forceRefresh = false) {{
            activeView = {{
                name: 'permutations',
                domain,
            }};
            domainPermutationsCache.delete(domain);
            const permutations = await fetchDomainPermutations(domain, true);
            domainPermutationsCache.set(domain, permutations);

            const items = Array.isArray(permutations?.items) ? permutations.items : [];
            const terms = Array.isArray(permutations?.terms) ? permutations.terms : [];
            const renderItems = items.length > 0
                ? items
                : terms
                    .map(term => extractSld(term))
                    .filter(term => term)
                    .map(term => ({{ permutation: term, enabled: 'ON', unique_domains: 0, unique_sources: 0 }}));

            renderPermutationsView(domain, renderItems);
        }}

        function renderSettingsView(message = '', success = null, account = null) {{
            const initialDomainsMonitorSubscription = {domains_monitor_subscription_json};
            account = account || initialDomainsMonitorSubscription;
            const hasMessage = String(message || '').trim().length > 0;
            const safeMessage = escapeHtml(message || '');
            const messageColor = success === true ? '#166534' : '#b42318';
            const safeAccountEmail = escapeHtml(account?.email || '');
            const safeAccountStatus = escapeHtml(account?.status || '');
            const safeAccountLicense = escapeHtml(account?.license || '');
            const safeAccountExpiry = escapeHtml(formatSubscriptionExpiry(account?.ttl));

            function formatSubscriptionExpiry(ttlValue) {{
                const ttlNumber = Number(ttlValue);
                if (!Number.isFinite(ttlNumber) || ttlNumber <= 0) {{
                    return 'Unknown';
                }}

                const date = new Date(ttlNumber * 1000);
                if (Number.isNaN(date.getTime())) {{
                    return 'Unknown';
                }}

                return date.toLocaleString(undefined, {{
                    year: 'numeric',
                    month: 'short',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    timeZoneName: 'short',
                }});
            }}

            document.querySelector('main').innerHTML =
                '<div class="card-actions">' +
                '<button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>' +
                '<button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>' +
                '<button class="logoff-button" type="button" title="Cognito Log Off" onclick="logOff()">X</button>' +
                '</div>' +
                '<img src="https://cdn.4n6ir.com/lunker.png" alt="OSINT Logo">' +
                '<h1>Configuration</h1>' +
                '<div style="text-align:left; margin: 0 0 16px; padding: 16px; border: 1px solid #e4e7ec; border-radius: 16px; background: #fff;">' +
                '<p style="margin:0 0 6px;"><strong>Domains Monitor Subscription</strong>' + (account && account.email ? ' <span style="color:#166534;">✓ ACTIVE</span>' : '') + '</p>' +
                '<p style="margin:0 0 14px; color:#475467;">Verify your API token to save the subscription record.</p>' +
                '<label for="domains-monitor-token">API Token</label>' +
                '<input id="domains-monitor-token" type="text" autocomplete="off" spellcheck="false">' +
                '<div class="actions" style="text-align:left;"><button type="button" onclick="verifyDomainsMonitorToken(event)">Verify</button></div>' +
                (hasMessage
                    ? '<p id="settings-status" style="margin-top:10px; color: ' + messageColor + ';">' + safeMessage + '</p>'
                    : '<p id="settings-status" style="margin-top:10px;"></p>') +
                (account && account.email
                    ? '<div style="margin:12px 0 0; padding:12px; border-radius:12px; background:#f9fafb; border:1px solid #eaecf0; line-height:1.5;">' +
                        '<strong>Saved Subscription</strong><br>' +
                        '<strong>Email:</strong> ' + safeAccountEmail + '<br>' +
                        '<strong>Status:</strong> ' + safeAccountStatus + '<br>' +
                        '<strong>License:</strong> ' + safeAccountLicense + '<br>' +
                                                '<strong>Expires:</strong> ' + safeAccountExpiry +
                      '</div>'
                    : '') +
                '</div>' +
                '<div class="actions"><a class="btn-primary" href="#" onclick="goHome(); return false;">Back</a></div>';
        }}

        function showSettings() {{
            activeView = {{
                name: 'settings',
                domain: ''
            }};
            renderSettingsView();
        }}

        async function verifyDomainsMonitorToken(event) {{
            if (event) {{
                event.preventDefault();
                event.stopPropagation();
            }}

            const tokenInput = document.getElementById('domains-monitor-token');
            const statusEl = document.getElementById('settings-status');
            const apiToken = String(tokenInput?.value || '').trim();
            const authHeader = {auth_header_json} || '';

            if (!apiToken) {{
                if (statusEl) {{
                    statusEl.style.color = '#b42318';
                    statusEl.textContent = 'API token is required.';
                }}
                return;
            }}

            if (statusEl) {{
                statusEl.style.color = '#166534';
                statusEl.textContent = 'Verifying...';
            }}

            try {{
                const response = await fetch({api_endpoint_json}, {{
                    method: 'POST',
                    credentials: 'include',
                    cache: 'no-store',
                    headers: {{
                        'Content-Type': 'application/json',
                        ...(authHeader ? {{ 'Authorization': authHeader }} : {{}})
                    }},
                    body: JSON.stringify({{ action: 'VerifyDomainsMonitorToken', apiToken }})
                }});

                const payload = await response.json().catch(() => ({{}}));
                const ok = Boolean(response.ok && payload && payload.ok);
                const message = String(payload?.message || (ok ? 'Verified and saved.' : 'Verification failed.'));
                const savedAccount = payload && payload.email
                    ? {{
                        email: payload?.email || '',
                        status: payload?.status || '',
                        license: payload?.license || '',
                        ttl: payload?.ttl || '',
                    }}
                    : null;

                renderSettingsView(
                    message,
                    ok,
                    savedAccount,
                );

                const newTokenInput = document.getElementById('domains-monitor-token');
                if (newTokenInput) {{
                    newTokenInput.value = apiToken;
                }}
            }} catch (err) {{
                renderSettingsView('Verification failed: ' + (err?.message || 'Unexpected error.'), false, null);
                const newTokenInput = document.getElementById('domains-monitor-token');
                if (newTokenInput) {{
                    newTokenInput.value = apiToken;
                }}
            }}
        }}

        function toggleHelp() {{
            const modal = document.getElementById('osint-help');
            modal.classList.toggle('open');
            document.body.classList.toggle('modal-open', modal.classList.contains('open'));
        }}

        function closeHelp() {{
            const modal = document.getElementById('osint-help');
            modal.classList.remove('open');
            document.body.classList.remove('modal-open');
        }}

        function logOff() {{
            window.location.assign({logout_endpoint_json});
        }}

        window.addEventListener('click', function(event) {{
            const modal = document.getElementById('osint-help');
            if (event.target === modal) {{
                closeHelp();
            }}
        }});

    </script>
</body>
</html>'''


def _html_response(body, status_code=200):
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        },
        'body': body,
    }


def _json_response(payload, status_code=200):
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        },
        'body': json.dumps(payload),
    }


def _render_result(message, success=False, authorization_header='', operation='submission'):
    auth_header_json = json.dumps(authorization_header)
    api_endpoint_json = json.dumps(_resolve_home_api_endpoint(API_ENDPOINT))
    logout_endpoint_json = json.dumps(_resolve_logout_endpoint(LOGOUT_ENDPOINT))
    safe_message = html.escape(str(message or ''))

    normalized_operation = str(operation or 'submission').strip().lower()
    is_deletion = normalized_operation == 'deletion'
    if success:
        heading = 'Deletion Successful' if is_deletion else 'Submission Successful'
        accent_color = '#166534'
    else:
        heading = 'Deletion Failed' if is_deletion else 'Submission Failed'
        accent_color = '#b42318'

    refresh_button = '' if success else '<button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gone Fishing!</title>
    <style>
        body {{
            font-family: sans-serif;
            margin: 0;
            background: #f4f7fb;
            color: #10233c;
        }}

        body.modal-open {{
            overflow: hidden;
        }}

        main {{
            position: relative;
            max-width: 540px;
            margin: 48px auto;
            padding: 32px;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 18px 40px rgba(16, 35, 60, 0.12);
            text-align: center;
        }}

        img {{
            display: block;
            margin: 0 auto 16px;
            max-width: 220px;
        }}

        h1 {{
            margin: 0 0 12px;
            color: {accent_color};
        }}

        p {{
            margin: 0;
            line-height: 1.5;
            white-space: pre-wrap;
        }}

        .toolbar {{
            position: absolute;
            top: 16px;
            right: 16px;
            display: flex;
            gap: 8px;
        }}

        .help-button,
        .refresh-button,
        .logoff-button {{
            width: 34px;
            height: 34px;
            border: 1px solid #cbd5e1;
            border-radius: 50%;
            background: #ffffff;
            color: #10233c;
            font-weight: 700;
            line-height: 1;
            cursor: pointer;
        }}

        .help-button:hover,
        .refresh-button:hover,
        .logoff-button:hover {{
            background: #f8fafc;
        }}

        .help-modal-overlay {{
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            background: rgba(16, 35, 60, 0.45);
            padding: 16px;
            z-index: 1000;
        }}

        .help-modal-overlay.open {{
            display: flex;
        }}

        .help-modal {{
            width: min(420px, 100%);
            padding: 18px 18px 14px;
            border: 1px solid #dbe4ee;
            border-radius: 14px;
            background: #ffffff;
            box-shadow: 0 18px 36px rgba(16, 35, 60, 0.2);
            text-align: left;
            max-height: 80vh;
            overflow-y: auto;
        }}

        .help-modal h2 {{
            margin: 0 0 12px;
            font-size: 1rem;
        }}

        .help-modal h3 {{
            margin: 14px 0 8px;
            font-size: 0.98rem;
            color: #10233c;
        }}

        .help-steps {{
            margin: 0;
            padding-left: 20px;
            color: #486581;
            font-size: 0.92rem;
        }}

        .help-steps li {{
            margin-bottom: 12px;
        }}

        .help-steps span {{
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            color: #10233c;
        }}

        .help-close {{
            display: inline-block;
            margin-top: 12px;
            border: 0;
            border-radius: 999px;
            background: #0e7490;
            color: #ffffff;
            font-size: 1rem;
            padding: 12px 28px;
            cursor: pointer;
        }}

        .actions {{
            margin-top: 18px;
        }}

        .actions a {{
            display: inline-block;
            border: 0;
            border-radius: 999px;
            background: #0e7490;
            color: #ffffff;
            cursor: pointer;
            font-size: 1rem;
            padding: 12px 28px;
            text-decoration: none;
        }}

        #refresh-error-banner {{
            margin: 0 0 12px;
            padding: 10px 12px;
            border: 1px solid #f5c2c7;
            border-radius: 10px;
            background: #fff5f5;
            color: #b42318;
            font-size: 0.92rem;
            text-align: left;
        }}
    </style>
</head>
<body>
    <section id="osint-help" class="help-modal-overlay" aria-hidden="true" aria-live="polite">
        <div class="help-modal" role="dialog" aria-modal="true" aria-label="OSINT Help">
            <h2 style="text-align:center">OSINT Help</h2>
            <ol class="help-steps">
                <li>
                    <span>Home View</span>
                    Use the Domain field to submit an add or remove request, then return to the dashboard to review your updated list.
                </li>
                <li>
                    <span>Remove</span>
                    Choose <b>Remove</b> to delete a tracked domain. Successful deletion returns an updated result.
                </li>
                <li>
                    <span>Add</span>
                    Choose <b>Add</b> to create a new watchlist entry for a base domain.
                </li>
                <li>
                    <span>Domain format rules</span>
                    Use one base domain only, such as <b>example.com</b>. Entries with extra dots are rejected.
                </li>
                <li>
                    <span>Settings</span>
                    Use <b>Configuration</b> to verify your Domains Monitor token and confirm the active subscription record.
                </li>
                <li>
                    <span>Domain View</span>
                    Open a domain to inspect OSINT findings and registration activity grouped by section.
                </li>
                <li>
                    <span>Permutations View</span>
                    From Domain View, open permutations to review variations and toggle each one on or off.
                </li>
                <li>
                    <span>How to read results</span>
                    Matched domains are indicators for investigation, not automatic confirmation of malicious activity.
                </li>
                <li>
                    <span>Data freshness</span>
                    Data updates during the day, so recent registrations and feed changes may appear with short delay.
                </li>
                <li>
                    <span>Quick controls</span>
                    Use <b>?</b> for help, <b>↺</b> to refresh data, and <b>X</b> to log off.
                </li>
                <li>
                    <span>Session and support</span>
                    Inactive sessions may time out and require sign-in again. Contact your sponsor or administrator if access or data appears incorrect.
                </li>
            </ol>
            <div style="text-align:center">
                <button class="help-close" type="button" onclick="closeHelp()">Close</button>
            </div>
        </div>
    </section>

    <main>
        <div class="toolbar">
            <button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>
            {refresh_button}
            <button class="logoff-button" type="button" title="Cognito Log Off" onclick="logOff()">X</button>
        </div>

        <img src="https://cdn.4n6ir.com/lunker.png" alt="OSINT Logo">
        <h1>{heading}</h1>
        <p>{safe_message}</p>
        <div class="actions">
            <a href="#" onclick="goHome(); return false;">Back</a>
        </div>
    </main>

    <script>
        function showRefreshError(message) {{
            const existing = document.getElementById('refresh-error-banner');
            if (existing) {{
                existing.remove();
            }}

            const banner = document.createElement('div');
            banner.id = 'refresh-error-banner';
            banner.textContent = message || 'Refresh failed. Please try again.';
            const main = document.querySelector('main');
            if (main) {{
                main.prepend(banner);
            }}
        }}

        async function goHome() {{
            const authHeader = {auth_header_json} || '';
            try {{
                const response = await fetch({api_endpoint_json}, {{
                    method: 'GET',
                    credentials: 'include',
                    cache: 'no-store',
                    headers: authHeader ? {{ 'Authorization': authHeader }} : {{}}
                }});
                if (!response.ok || response.redirected) {{
                    throw new Error('Home reload was redirected or failed: ' + response.status);
                }}

                const htmlBody = await response.text();
                document.open();
                document.write(htmlBody);
                document.close();
            }} catch (err) {{
                console.error('Failed to load home view.', err);
                showRefreshError('Failed to load home view. Please try again.');
            }}
        }}

        function refreshCurrentView(event) {{
            if (event) {{
                event.preventDefault();
                event.stopPropagation();
            }}
            goHome();
        }}

        function toggleHelp() {{
            const modal = document.getElementById('osint-help');
            modal.classList.toggle('open');
            document.body.classList.toggle('modal-open', modal.classList.contains('open'));
        }}

        function closeHelp() {{
            const modal = document.getElementById('osint-help');
            modal.classList.remove('open');
            document.body.classList.remove('modal-open');
        }}

        function logOff() {{
            window.location.assign({logout_endpoint_json});
        }}

        window.addEventListener('click', function(event) {{
            const modal = document.getElementById('osint-help');
            if (event.target === modal) {{
                closeHelp();
            }}
        }});

    </script>
</body>
</html>'''


def _normalize_action(action):
    normalized = str(action or '').strip().lower()
    mapping = {
        'getitem': 'GetItem',
        'putitem': 'PutItem',
        'deleteitem': 'DeleteItem',
        'getdomainsections': 'GetDomainSections',
        'getdomainpermutations': 'GetDomainPermutations',
        'toggledomainpermutation': 'ToggleDomainPermutation',
        'verifydomainsmonitortoken': 'VerifyDomainsMonitorToken',
    }
    return mapping.get(normalized, 'PutItem')


def _handle_request(event, _context):
    event = event or {}
    if _is_force_refresh(event):
        _clear_runtime_caches()

    method = _get_method(event)
    authorization_header = _get_authorization(event)

    if method == 'GET':
        identity = _resolve_identity(event, authorization_header)
        email = identity.get('email', 'unknown')
        watchlist_table = _get_env_table('WATCHLIST_TABLE', 'watchlist')
        users_table = _get_env_table('USERS_TABLE', 'users')
        subscription_table = _get_env_table('SUBSCRIPTION_TABLE', 'subscription')

        domains = _list_watchlist_domains(watchlist_table, email)
        matched_slds = _get_matched_slds(domains)
        highlighted_domains = set()
        for domain in domains:
            try:
                sections = _get_domain_sections(domain, email)
                if _domain_has_priority_entries(sections):
                    highlighted_domains.add(domain)
            except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
                continue
        user_extra_fields = _get_user_extra_fields(users_table, email)
        domains_monitor_subscription = _get_domains_monitor_subscription(subscription_table, email)

        html_body = _render_form(
            authorization_header,
            identity,
            domains,
            matched_slds,
            user_extra_fields,
            domains_monitor_subscription,
            highlighted_domains,
        )
        return _html_response(html_body)

    if method == 'POST':
        body = _get_body(event)
        payload = {}
        if body:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}

        if not isinstance(payload, dict):
            payload = {}

        action = _normalize_action(payload.get('action'))
        entry = _normalize_domain(payload.get('entry', ''))

        if action == 'GetDomainSections':
            identity = _resolve_identity(event, authorization_header)
            email = identity.get('email', 'unknown')
            try:
                subscription_table = _get_env_table('SUBSCRIPTION_TABLE', 'subscription')
                has_domains_monitor = bool(_get_domains_monitor_subscription(subscription_table, email))
                sections = _get_domain_sections(entry, email)
                permutations = _get_permutation_count(entry, email)

                if not isinstance(sections, dict):
                    sections = {}

                if not has_domains_monitor:
                    safe_suspect = sections.get('suspect') if isinstance(sections.get('suspect'), dict) else {}
                    sections = {
                        **sections,
                        'suspect': {
                            'openSourceIntelligence': list(safe_suspect.get('openSourceIntelligence') or []),
                            'domainsMonitorSubscription': [],
                        },
                        'newRegistrations': {'daily': [], 'weekly': [], 'monthly': []},
                        'expiredRegistrations': {'daily': [], 'weekly': [], 'monthly': []},
                        '_noDomainsMonitor': True,
                    }
                else:
                    sections['_noDomainsMonitor'] = False
            except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
                sections = {}
                permutations = 0

            return _json_response({
                'sections': sections,
                'permutations': permutations,
            })

        if action == 'GetDomainPermutations':
            identity = _resolve_identity(event, authorization_header)
            email = identity.get('email', 'unknown')
            try:
                permutation_states = _get_domain_permutation_entries(entry, email)
                permutations = [
                    entry['permutation']
                    for entry in permutation_states
                    if _normalize_permutation_enabled(entry.get('enabled', 'ON')) == 'ON'
                ]
            except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
                permutations = []
                permutation_states = []
            return _json_response({
                'permutations': permutations,
                'permutationStates': permutation_states,
            })

        if action == 'ToggleDomainPermutation':
            identity = _resolve_identity(event, authorization_header)
            email = identity.get('email', 'unknown')
            success, message = _set_domain_permutation_enabled(
                entry,
                email,
                payload.get('permutation', ''),
                payload.get('enabled', 'ON'),
            )
            status_code = 200 if success else 400
            return _json_response({'ok': success, 'message': message}, status_code=status_code)

        if action == 'VerifyDomainsMonitorToken':
            account, error = _verify_domains_monitor_account(payload.get('apiToken', ''))
            if error:
                return _json_response({'ok': False, 'message': error}, status_code=400)

            identity = _resolve_identity(event, authorization_header)
            cognito_email = identity.get('email', 'unknown')
            subscription_table = _get_env_table('SUBSCRIPTION_TABLE', 'subscription')
            try:
                _put_domains_monitor_subscription(subscription_table, account, cognito_email=cognito_email)
            except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
                return _json_response(
                    {
                        'ok': False,
                        'message': 'Token verified, but saving the subscription record failed.',
                    },
                    status_code=500,
                )

            domains_monitor_email = str(account.get('email', '')).strip().lower()
            normalized_cognito_email = str(cognito_email or '').strip().lower()
            email_match = bool(domains_monitor_email and normalized_cognito_email and domains_monitor_email == normalized_cognito_email)

            if not email_match:
                return _json_response(
                    {
                        'ok': False,
                        'message': 'Token verified and subscription saved, but Domains Monitor email does not match your Cognito login email.',
                        'email': account.get('email', ''),
                        'status': account.get('status', ''),
                        'license': account.get('license', ''),
                        'ttl': account.get('ttl', 0),
                    }
                )

            return _json_response(
                {
                    'ok': True,
                    'message': 'Token verified and subscription saved.',
                    'email': account.get('email', ''),
                    'status': account.get('status', ''),
                    'license': account.get('license', ''),
                    'ttl': account.get('ttl', 0),
                }
            )

        identity = _resolve_identity(event, authorization_header)
        email = identity.get('email', 'unknown')
        domain, success, message = _process_submission(entry, email, action)

        operation = 'deletion' if action == 'DeleteItem' else 'submission'
        result_message = domain
        if not success and message:
            result_message = f'{domain}\n\n{message}'

        html_body = _render_result(result_message, success, authorization_header, operation)
        return _html_response(html_body)

    return {
        'statusCode': 405,
        'headers': {'Content-Type': 'application/json; charset=utf-8'},
        'body': json.dumps({'message': 'Method not allowed'}),
    }


def create_handler(api_endpoint, logout_endpoint, user_info_endpoint):
    def configured_handler(event, context):
        old_api_endpoint = API_ENDPOINT
        old_logout_endpoint = LOGOUT_ENDPOINT
        old_user_info_endpoint = USER_INFO_ENDPOINT

        globals()['API_ENDPOINT'] = api_endpoint
        globals()['LOGOUT_ENDPOINT'] = logout_endpoint
        globals()['USER_INFO_ENDPOINT'] = user_info_endpoint

        try:
            return _handle_request(event, context)
        finally:
            globals()['API_ENDPOINT'] = old_api_endpoint
            globals()['LOGOUT_ENDPOINT'] = old_logout_endpoint
            globals()['USER_INFO_ENDPOINT'] = old_user_info_endpoint

    return configured_handler


# Public aliases for test and runtime compatibility.
get_user_extra_fields = _get_user_extra_fields
ensure_user_record = _ensure_user_record
list_watchlist_domains = _list_watchlist_domains
put_watchlist_domain = _put_watchlist_domain
process_submission = _process_submission
render_form = _render_form
render_result = _render_result
handle_request = _handle_request
handler = _handle_request


if __name__ == '__main__':
    raise SystemExit('This module is intended to be used as an AWS Lambda handler.')
