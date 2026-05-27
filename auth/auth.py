import base64
import binascii
import hashlib
import hmac
import html
import json
import logging
import os
from urllib.parse import parse_qs, urlencode

import boto3
import requests
from botocore.exceptions import ClientError

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

SECRETS_CLIENT = boto3.client('secretsmanager')
COGNITO_CLIENT = boto3.client('cognito-idp')

HTML_CONTENT_TYPE = 'text/html; charset=utf-8'
PAGE_TITLE = 'No Fishing!'
PAGE_SUBTITLE = 'Passwordless email sign-in and account creation'
AUTH_SELF_SIGN_UP_ENV = 'AUTH_SELF_SIGN_UP_ENABLED'


def _self_sign_up_enabled() -> bool:
    return str(os.environ.get(AUTH_SELF_SIGN_UP_ENV, 'true')).strip().lower() in (
        '1',
        'true',
        'yes',
        'on',
    )


def _html_response(status_code: int, body: str) -> dict:
    return {
        'statusCode': status_code,
        'body': body,
        'headers': {'Content-Type': HTML_CONTENT_TYPE},
    }


def _redirect_response(location: str) -> dict:
    return {
        'statusCode': 302,
        'body': '',
        'headers': {
            'Location': location,
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        },
    }


def _render_default_page(cdn_base_url: str, email: str = '', message: str = '', is_auth_issue: bool = False) -> str:
    return _page(
        cdn_base_url,
        PAGE_TITLE,
        PAGE_SUBTITLE,
        _default_form(email),
        message or 'Use your email to create an account or sign in. No password is required.',
        is_auth_issue=is_auth_issue,
    )


def _render_issue_page(cdn_base_url: str, message: str = '') -> str:
    return _render_default_page(
        cdn_base_url,
        email='',
        message=message,
        is_auth_issue=True,
    )


def _get_credentials() -> tuple[str, str]:
    secret_arn = os.environ['CREDENTIALS_SECRET_ARN']
    response = SECRETS_CLIENT.get_secret_value(SecretId=secret_arn)
    payload = json.loads(response['SecretString'])
    return payload['CLIENT_ID'], payload['CLIENT_SECRET']


def _get_runtime_config() -> tuple[str, str, str, str]:
    return (
        os.environ['COGNITO_DOMAIN'],
        os.environ['COGNITO_REDIRECT_URI'],
        os.environ['HOME_ENDPOINT'],
        os.environ['CDN_BASE_URL'],
    )


def _secret_hash(username: str, client_id: str, client_secret: str) -> str:
    digest = hmac.new(
        client_secret.encode('utf-8'),
        (username + client_id).encode('utf-8'),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode('utf-8')


def _event_method(event: dict) -> str:
    request_context = event.get('requestContext', {})
    http_context = request_context.get('http', {})
    return (http_context.get('method') or event.get('httpMethod') or 'GET').upper()


def _read_body(event: dict) -> str:
    body = event.get('body') or ''
    if event.get('isBase64Encoded'):
        try:
            return base64.b64decode(body, validate=True).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return ''
    return body


def _form(event: dict) -> dict[str, str]:
    parsed = parse_qs(_read_body(event), keep_blank_values=False)
    return {k: v[0] for k, v in parsed.items() if v}


def _page(
    cdn_base_url: str,
    title: str,
    subtitle: str,
    content_html: str,
    message: str = '',
    is_auth_issue: bool = False,
) -> str:
    del title
    safe_title = html.escape('Sign-In Issue' if is_auth_issue else 'Happy Fishing!')
    del subtitle
    safe_message = html.escape(message)
    message_block = ''
    if safe_message:
        message_block = f'<div class="message"><span class="message-kicker">Notice</span><span>{safe_message}</span></div>'

    image_url = 'https://cdn.4n6ir.com/nofishing.png' if is_auth_issue else 'https://cdn.4n6ir.com/lunker.png'
    card_class = 'issue-card' if is_auth_issue else 'happy-card'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{safe_title}</title>
    <style>
        :root {{
            --card-bg: #ffffff;
            --card-border: #e2e8f0;
            --text-main: #10233c;
            --text-muted: #486581;
            --brand: #0e7490;
            --brand-dark: #0b6077;
            --field-bg: #f8fafc;
            --info-bg: #eff6ff;
            --info-border: #93c5fd;
            --info-text: #1e3a5f;
        }}

        body {{
            font-family: sans-serif;
            margin: 0;
            background: radial-gradient(1200px 500px at 20% -10%, #dff3ff 0%, #f4f7fb 40%, #f4f7fb 100%);
            color: var(--text-main);
        }}

        main {{
            width: min(560px, calc(100% - 48px));
            margin: 48px auto;
            padding: 32px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 18px;
            box-shadow: 0 18px 40px rgba(16, 35, 60, 0.08);
            text-align: center;
        }}

        img {{
            display: block;
            margin: 0 auto 14px;
            max-width: 220px;
        }}

        h1 {{
            margin: 0 0 16px;
            font-size: 1.9rem;
            letter-spacing: 0.01em;
        }}

        .issue-card h1 {{
            margin-bottom: 26px;
        }}

        .message {{
            margin: 0 0 14px;
            padding: 10px 12px;
            border: 1px solid var(--info-border);
            border-left-width: 4px;
            border-radius: 12px;
            background: var(--info-bg);
            color: var(--info-text);
            text-align: left;
            font-size: 0.9rem;
            line-height: 1.45;
        }}

        .message-kicker {{
            display: inline-block;
            margin-right: 6px;
            font-weight: 700;
        }}

        form {{
            display: grid;
            gap: 10px;
            text-align: left;
            margin: 0 auto;
            max-width: 360px;
        }}

        label {{
            display: grid;
            gap: 6px;
            font-weight: 600;
            color: var(--text-main);
            font-size: 0.88rem;
            letter-spacing: 0.01em;
        }}

        input {{
            width: 100%;
            box-sizing: border-box;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            padding: 12px;
            font-size: 1rem;
            color: var(--text-main);
            background: var(--field-bg);
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }}

        input:hover {{
            border-color: #9fb0c8;
        }}

        input:focus-visible {{
            border-color: var(--brand);
            box-shadow: 0 0 0 3px rgba(14, 116, 144, 0.16);
            outline: none;
        }}

        input:focus-visible,
        button:focus-visible,
        a.button-link:focus-visible {{
            outline: 2px solid #0e7490;
            outline-offset: 2px;
        }}

        .button-row {{
            display: flex;
            gap: 8px;
            flex-wrap: nowrap;
            justify-content: center;
            margin-top: 12px;
        }}

        .button-row > button,
        .button-row > a {{
            flex: 1 1 0;
            text-align: center;
            white-space: nowrap;
        }}

        button, a.button-link {{
            display: inline-block;
            border: 0;
            border-radius: 999px;
            background: var(--brand);
            color: #ffffff;
            cursor: pointer;
            font-size: 0.88rem;
            font-weight: 600;
            padding: 10px 12px;
            text-decoration: none;
            transition: background 0.15s ease, transform 0.05s ease;
        }}

        button:hover,
        a.button-link:hover {{
            background: var(--brand-dark);
        }}

        button.secondary, a.button-link.secondary {{
            background: #ffffff;
            color: var(--brand);
            border: 1px solid var(--brand);
        }}

        button:active,
        a.button-link:active {{
            transform: translateY(1px);
        }}

        .footer-links {{
            margin-top: 12px;
            display: flex;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
        }}
    </style>
</head>
<body>
    <main class="{card_class}">
        <img src="{image_url}" alt="OSINT Logo">
        <h1>{safe_title}</h1>
        {message_block}
        {content_html}
    </main>
</body>
</html>'''.replace('https://cdn.4n6ir.com', cdn_base_url)


def _default_form(email: str = '') -> str:
    safe_email = html.escape(email)
    if _self_sign_up_enabled():
        return f'''
<form method="post" action="/auth">
    <label for="email">Email Address</label>
    <input id="email" type="email" name="email" value="{safe_email}" autocomplete="email" required>
    <div class="button-row">
        <button type="submit" name="action" value="signup_start">Create Account</button>
        <button type="submit" name="action" value="signin_start" class="secondary">Sign In</button>
        <a class="button-link secondary" href="/">Back</a>
    </div>
</form>
'''

    return f'''
<form method="post" action="/auth">
    <label for="email">Email Address</label>
    <input id="email" type="email" name="email" value="{safe_email}" autocomplete="email" required>
    <div class="button-row">
        <button type="submit" name="action" value="signin_start">Sign In</button>
        <a class="button-link secondary" href="/">Back</a>
    </div>
</form>
'''


def _signup_confirm_form(email: str) -> str:
    safe_email = html.escape(email)
    return f'''
<form method="post" action="/auth">
    <input type="hidden" name="action" value="signup_confirm">
    <input type="hidden" name="email" value="{safe_email}">
    <label>Verification Code
        <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required>
    </label>
    <div class="button-row">
        <button type="submit">Verify Account</button>
        <button type="submit" name="action" value="signup_start" class="secondary">Resend Code</button>
        <a class="button-link secondary" href="/auth">Start Over</a>
    </div>
</form>
'''


def _signin_confirm_form(email: str, session: str) -> str:
    safe_email = html.escape(email)
    safe_session = html.escape(session)
    return f'''
<form method="post" action="/auth">
    <input type="hidden" name="action" value="signin_confirm">
    <input type="hidden" name="email" value="{safe_email}">
    <input type="hidden" name="session" value="{safe_session}">
    <label>Sign-In Code
        <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required>
    </label>
    <div class="button-row">
        <button type="submit">Complete Sign In</button>
        <button type="submit" name="action" value="signin_start" class="secondary">Send New Code</button>
        <a class="button-link secondary" href="/auth">Start Over</a>
    </div>
</form>
'''


def _home_bridge(access_token: str, home_endpoint: str, cdn_base_url: str) -> str:
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Happy Fishing!</title>
    <style>
        body {
            font-family: sans-serif;
            margin: 0;
            background: #f4f7fb;
            color: #10233c;
            text-align: center;
            padding: 56px 20px;
        }

        img {
            max-width: 220px;
        }

        p {
            color: #486581;
        }
    </style>
    <script>
        const headers = { 'Authorization': 'Bearer ' + '{access_token}' };
        fetch('{home_endpoint_url}', { headers: headers })
            .then(response => {
                if (!response.ok) {
                    throw new Error('home fetch failed');
                }
                return response.text();
            })
            .then(data => {
                document.open();
                document.write(data);
                document.close();
            })
            .catch(() => {
                document.body.innerHTML = '<p>Signed in. Loading home...</p>';
                window.location.assign('/home');
            });
    </script>
</head>
<body>
    <img src="https://cdn.4n6ir.com/lunker.png" alt="OSINT Logo">
    <p>Signing you in...</p>
</body>
</html>'''.replace('{home_endpoint_url}', home_endpoint).replace('{access_token}', access_token).replace('https://cdn.4n6ir.com', cdn_base_url)


def _start_sign_in(email: str, client_id: str, client_secret: str) -> tuple[bool, str, str]:
    response = COGNITO_CLIENT.initiate_auth(
        ClientId=client_id,
        AuthFlow='USER_AUTH',
        AuthParameters={
            'USERNAME': email,
            'PREFERRED_CHALLENGE': 'EMAIL_OTP',
            'SECRET_HASH': _secret_hash(email, client_id, client_secret),
        },
    )

    challenge_name = response.get('ChallengeName', '')
    session = response.get('Session', '')
    if challenge_name != 'EMAIL_OTP' or not session:
        return False, '', 'Unable to start email sign-in challenge.'

    return True, session, 'A sign-in code has been sent to your email.'


def _resend_signup_confirmation(email: str, client_id: str, client_secret: str) -> None:
    COGNITO_CLIENT.resend_confirmation_code(
        ClientId=client_id,
        Username=email,
        SecretHash=_secret_hash(email, client_id, client_secret),
    )


def _legacy_oauth_code_flow(query: dict, client_id: str, client_secret: str, cognito_domain: str, redirect_uri: str, home_endpoint: str, cdn_base_url: str) -> tuple[int, str] | None:
    auth_code = query.get('code', [None])[0]
    if not auth_code:
        return None

    if not all(c.isalnum() or c in ['_', '-', '.'] for c in auth_code):
        html_body = _page(
            cdn_base_url,
            'No Fishing!',
            'Invalid authorization code.',
            _default_form(),
            'Please sign in again.',
            is_auth_issue=True,
        )
        return 400, html_body

    b64 = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
    try:
        response = requests.post(
            cognito_domain + '/oauth2/token',
            headers={
                'Authorization': f'Basic {b64}',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            data={
                'code': auth_code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri,
            },
            timeout=5,
        )
    except requests.RequestException as exc:
        LOGGER.exception('oauth_token_exchange_failed error=%s', exc)
        html_body = _render_issue_page(
            cdn_base_url,
            message='Sign-in failed. Please request a fresh code and try again.',
        )
        return 401, html_body

    if response.status_code == 200 and 'access_token' in response.json():
        return 200, _home_bridge(response.json()['access_token'], home_endpoint, cdn_base_url)

    html_body = _page(
        cdn_base_url,
        PAGE_TITLE,
        'Sign-in required',
        _default_form(),
        'Sign-in failed. Please request a fresh code and try again.',
        is_auth_issue=True,
    )
    return 401, html_body


def handler(event, context):
    del context

    cognito_domain, redirect_uri, home_endpoint, cdn_base_url = _get_runtime_config()
    client_id, client_secret = _get_credentials()

    query = parse_qs(event.get('rawQueryString', ''), keep_blank_values=False)
    method = _event_method(event)

    if query.get('action', [''])[0] == 'logout':
        logout_url = (
            cognito_domain
            + '/logout?'
            + urlencode({
                'client_id': client_id,
                'logout_uri': redirect_uri,
            })
        )
        return _redirect_response(logout_url)

    legacy_result = _legacy_oauth_code_flow(
        query,
        client_id,
        client_secret,
        cognito_domain,
        redirect_uri,
        home_endpoint,
        cdn_base_url,
    )
    if legacy_result:
        code, html_body = legacy_result
        return _html_response(code, html_body)

    if method != 'POST':
        html_body = _render_default_page(cdn_base_url)
        return _html_response(200, html_body)

    form = _form(event)
    action = form.get('action', '')
    email = (form.get('email', '') or '').strip().lower()
    allow_self_signup = _self_sign_up_enabled()

    if not email:
        html_body = _render_issue_page(cdn_base_url, message='Enter a valid email address.')
        return _html_response(400, html_body)

    if not allow_self_signup and action in ('signup_start', 'signup_confirm'):
        html_body = _render_issue_page(
            cdn_base_url,
            message='This deployment is invite-only. Use Sign In with your existing account.',
        )
        return _html_response(403, html_body)

    try:
        if action == 'signup_start':
            try:
                COGNITO_CLIENT.sign_up(
                    ClientId=client_id,
                    Username=email,
                    UserAttributes=[{'Name': 'email', 'Value': email}],
                    SecretHash=_secret_hash(email, client_id, client_secret),
                )
                message = 'Check your inbox for an account verification code.'
                html_body = _page(
                    cdn_base_url,
                    'Verify Account',
                    'Enter the code sent to your email',
                    _signup_confirm_form(email),
                    message,
                )
                return _html_response(200, html_body)
            except COGNITO_CLIENT.exceptions.UsernameExistsException:
                try:
                    ok, session, message = _start_sign_in(email, client_id, client_secret)
                    if ok:
                        html_body = _page(
                            cdn_base_url,
                            'Complete Sign In',
                            'Enter the one-time code we emailed you',
                            _signin_confirm_form(email, session),
                            'Account already exists. ' + message,
                        )
                        return _html_response(200, html_body)
                    html_body = _render_issue_page(cdn_base_url, message=message)
                    return _html_response(400, html_body)
                except COGNITO_CLIENT.exceptions.NotAuthorizedException as exc:
                    # Existing unconfirmed user: resend sign-up confirmation instead of trying to create a duplicate account.
                    if 'not confirmed' in str(exc).lower():
                        _resend_signup_confirmation(email, client_id, client_secret)
                        html_body = _page(
                            cdn_base_url,
                            'Verify Account',
                            'Enter the code sent to your email',
                            _signup_confirm_form(email),
                            'Account already exists but is not verified. A new verification code was sent.',
                        )
                        return _html_response(200, html_body)
                    raise

        if action == 'signup_confirm':
            code = (form.get('code', '') or '').strip()
            COGNITO_CLIENT.confirm_sign_up(
                ClientId=client_id,
                Username=email,
                ConfirmationCode=code,
                SecretHash=_secret_hash(email, client_id, client_secret),
            )
            ok, session, message = _start_sign_in(email, client_id, client_secret)
            if not ok:
                html_body = _render_issue_page(cdn_base_url, message=message)
                return _html_response(400, html_body)
            html_body = _page(
                cdn_base_url,
                'Complete Sign In',
                'Enter the one-time code we emailed you',
                _signin_confirm_form(email, session),
                'Account verified. ' + message,
            )
            return _html_response(200, html_body)

        if action == 'signin_start':
            ok, session, message = _start_sign_in(email, client_id, client_secret)
            if not ok:
                html_body = _render_issue_page(cdn_base_url, message=message)
                return _html_response(400, html_body)
            html_body = _page(
                cdn_base_url,
                'Complete Sign In',
                'Enter the one-time code we emailed you',
                _signin_confirm_form(email, session),
                message,
            )
            return _html_response(200, html_body)

        if action == 'signin_confirm':
            code = (form.get('code', '') or '').strip()
            session = (form.get('session', '') or '').strip()
            response = COGNITO_CLIENT.respond_to_auth_challenge(
                ClientId=client_id,
                ChallengeName='EMAIL_OTP',
                Session=session,
                ChallengeResponses={
                    'USERNAME': email,
                    'EMAIL_OTP_CODE': code,
                    'SECRET_HASH': _secret_hash(email, client_id, client_secret),
                },
            )
            auth = response.get('AuthenticationResult', {})
            access_token = auth.get('AccessToken')
            if not access_token:
                raise ValueError('Authentication token missing in response.')
            html_body = _home_bridge(access_token, home_endpoint, cdn_base_url)
            return _html_response(200, html_body)

        html_body = _render_issue_page(cdn_base_url, message='Unsupported action. Please try again.')
        return _html_response(400, html_body)

    except COGNITO_CLIENT.exceptions.CodeMismatchException:
        html_body = _page(
            cdn_base_url,
            'Verification Failed',
            'The verification code was not accepted',
            _default_form(),
            'The code is incorrect. Request a new code and try again.',
            is_auth_issue=True,
        )
        return _html_response(400, html_body)
    except COGNITO_CLIENT.exceptions.ExpiredCodeException:
        html_body = _page(
            cdn_base_url,
            'Verification Failed',
            'The verification code has expired',
            _default_form(),
            'The code expired. Request a new code and try again.',
            is_auth_issue=True,
        )
        return _html_response(400, html_body)
    except COGNITO_CLIENT.exceptions.NotAuthorizedException:
        html_body = _page(
            cdn_base_url,
            'No Fishing!',
            'Passwordless email sign-in and account creation',
            _default_form(),
            'Authentication failed for this account.',
            is_auth_issue=True,
        )
        return _html_response(401, html_body)
    except COGNITO_CLIENT.exceptions.UserNotFoundException:
        html_body = _page(
            cdn_base_url,
            'No Fishing!',
            'Passwordless email sign-in and account creation',
            _default_form(),
            'Account not found. Create a new account to continue.',
            is_auth_issue=True,
        )
        return _html_response(404, html_body)
    except ClientError:
        html_body = _page(
            cdn_base_url,
            'No Fishing!',
            'Passwordless email sign-in and account creation',
            _default_form(),
            'Something went wrong. Please try again in a moment.',
            is_auth_issue=True,
        )
        return _html_response(500, html_body)
    except ValueError:
        html_body = _render_issue_page(
            cdn_base_url,
            message='Authentication failed. Please try signing in again.',
        )
        return _html_response(401, html_body)
