import boto3
import os
from urllib.parse import unquote
from botocore.exceptions import ClientError


COGNITO_IDP = boto3.client('cognito-idp')
ACCESS_TOKEN_COOKIE_NAME = str(os.getenv('ACCESS_TOKEN_COOKIE_NAME', 'osint_at')).strip() or 'osint_at'
COOKIE_NAME_CANDIDATES = tuple(
    dict.fromkeys([ACCESS_TOKEN_COOKIE_NAME, 'osint_at'])
)


def _header_value(headers, name):
    if not isinstance(headers, dict):
        return ''

    wanted = str(name or '').strip().lower()
    for key, value in headers.items():
        if str(key).strip().lower() == wanted:
            return str(value or '')
    return ''


def _extract_access_token(event):
    def _normalize_token(raw_value):
        token = unquote(str(raw_value or '').strip()).strip('"\'')
        if token.lower().startswith('bearer '):
            token = token.split(' ', 1)[1].strip()
        return token

    def _token_from_cookie_parts(parts):
        for part in parts:
            name, sep, value = part.strip().partition('=')
            if sep and name.strip() in COOKIE_NAME_CANDIDATES:
                token = _normalize_token(value)
                if token:
                    return token
        return ''

    headers = event.get('headers') or {}
    authorization = _header_value(headers, 'authorization').strip()
    if authorization:
        if authorization.lower().startswith('bearer '):
            return authorization.split(' ', 1)[1].strip()
        return _normalize_token(authorization)

    cookie_header = _header_value(headers, 'cookie').strip()
    if cookie_header:
        token = _token_from_cookie_parts(cookie_header.split(';'))
        if token:
            return token

    cookie_values = event.get('cookies') or []
    if isinstance(cookie_values, list):
        token = _token_from_cookie_parts(cookie_values)
        if token:
            return token

    multivalue_headers = event.get('multiValueHeaders') or {}
    if isinstance(multivalue_headers, dict):
        for key, values in multivalue_headers.items():
            if str(key).strip().lower() != 'cookie' or not isinstance(values, list):
                continue
            token = _token_from_cookie_parts(values)
            if token:
                return token

    return ''


def _to_bool(value):
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')


def handler(event, _context):
    access_token = _extract_access_token(event)
    if not access_token:
        return {'isAuthorized': False}

    try:
        response = COGNITO_IDP.get_user(AccessToken=access_token)
    except ClientError:
        return {'isAuthorized': False}

    attributes = {
        item.get('Name'): item.get('Value', '')
        for item in response.get('UserAttributes', [])
        if isinstance(item, dict)
    }
    email = attributes.get('email', '')

    if not email:
        return {'isAuthorized': False}

    return {
        'isAuthorized': True,
        'context': {
            'sub': attributes.get('sub', ''),
            'email_verified': _to_bool(attributes.get('email_verified', 'false')),
            'email': email,
            'username': response.get('Username', ''),
        },
    }
