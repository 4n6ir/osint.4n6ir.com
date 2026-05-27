import boto3
from botocore.exceptions import ClientError


COGNITO_IDP = boto3.client('cognito-idp')


def _header_value(headers, name):
    if not isinstance(headers, dict):
        return ''

    wanted = str(name or '').strip().lower()
    for key, value in headers.items():
        if str(key).strip().lower() == wanted:
            return str(value or '')
    return ''


def _extract_access_token(event):
    headers = event.get('headers') or {}
    authorization = _header_value(headers, 'authorization').strip()
    if not authorization:
        return ''

    if authorization.lower().startswith('bearer '):
        return authorization.split(' ', 1)[1].strip()
    return authorization


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
