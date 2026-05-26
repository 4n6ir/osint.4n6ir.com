import os
import requests


def handler(event, _context):
    """
    Lambda authorizer for token-based authorization.
    Validates Authorization header and returns user context.
    """
    url = os.getenv('USER_INFO_ENDPOINT', 'https://hello.dev.osint.4n6ir.com/oauth2/userInfo')
    headers = {
        'Authorization': str(event['headers']['authorization'])
    }
    response = requests.get(url, headers=headers, timeout=5)

    if response.status_code != 200 or 'email' not in response.json():
        authorized = {
            "isAuthorized": False
        }
    else:
        authorized = {
            "isAuthorized": True,
            "context": {
                "sub": response.json().get('sub'),
                "email_verified": response.json().get('email_verified'),
                "email": response.json().get('email'),
                "username": response.json().get('username')
            }
        }

    return authorized
