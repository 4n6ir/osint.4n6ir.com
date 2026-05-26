import base64
import boto3
import json
import os
import requests
from urllib.parse import parse_qs, urlencode

_secrets = boto3.client('secretsmanager')


def _get_credentials() -> tuple[str, str]:
    secret_arn = os.environ['CREDENTIALS_SECRET_ARN']
    response = _secrets.get_secret_value(SecretId=secret_arn)
    payload = json.loads(response['SecretString'])
    return payload['CLIENT_ID'], payload['CLIENT_SECRET']


def _get_runtime_config() -> tuple[str, str, str]:
    return (
        os.environ['COGNITO_DOMAIN'],
        os.environ['COGNITO_REDIRECT_URI'],
        os.environ['CDN_BASE_URL']
    )

def handler(event, _context):
    cognito_domain, redirect_uri, cdn_base_url = _get_runtime_config()

    client_id, client_secret = _get_credentials()
    query = parse_qs(event.get('rawQueryString', ''), keep_blank_values=False)

    # Redirect through Cognito hosted UI logout to clear Cognito session cookies.
    if query.get('action', [''])[0] == 'logout':
        logout_url = (
            cognito_domain
            + '/logout?'
            + urlencode({
                'client_id': client_id,
                'logout_uri': redirect_uri
            })
        )
        return {
            'statusCode': 302,
            'body': '',
            'headers': {
                'Location': logout_url,
                'Cache-Control': 'no-store',
                'Pragma': 'no-cache'
            }
        }

    code = 401
    login_url = (
        cognito_domain + '/login?'
        + urlencode({
            'client_id': client_id,
            'response_type': 'code',
            'scope': 'openid',
            'redirect_uri': redirect_uri
        })
    )
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>No Fishing!</title>
    <style>
        body {
            font-family: sans-serif;
            margin: 0;
            background: #f4f7fb;
            color: #10233c;
        }

        body.modal-open {
            overflow: hidden;
        }

        main {
            position: relative;
            max-width: 540px;
            margin: 48px auto;
            padding: 32px;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 18px 40px rgba(16, 35, 60, 0.12);
            text-align: center;
        }

        .help-button {
            position: absolute;
            top: 16px;
            right: 16px;
            width: 34px;
            height: 34px;
            border: 1px solid #cbd5e1;
            border-radius: 50%;
            background: #ffffff;
            color: #10233c;
            font-size: 1rem;
            font-weight: 700;
            line-height: 1;
            cursor: pointer;
        }

        .help-button:hover {
            background: #f8fafc;
        }

        .help-modal-overlay {
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            background: rgba(16, 35, 60, 0.45);
            padding: 16px;
            z-index: 1000;
        }

        .help-modal-overlay.open {
            display: flex;
        }

        .help-modal {
            width: min(420px, 100%);
            padding: 18px 18px 14px;
            border: 1px solid #dbe4ee;
            border-radius: 14px;
            background: #ffffff;
            box-shadow: 0 18px 36px rgba(16, 35, 60, 0.2);
            text-align: left;
            max-height: 80vh;
            overflow-y: auto;
        }

        .help-modal h2 {
            margin: 0 0 12px;
            font-size: 1rem;
        }

        .help-steps {
            margin: 0;
            padding-left: 20px;
            color: #486581;
            font-size: 0.92rem;
        }

        .help-steps li {
            margin-bottom: 12px;
        }

        .help-steps span {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            color: #10233c;
        }

        .help-close {
            display: inline-block;
            margin-top: 12px;
            border: 0;
            border-radius: 999px;
            background: #0e7490;
            color: #ffffff;
            font-size: 1rem;
            padding: 12px 28px;
            cursor: pointer;
        }

        img {
            display: block;
            margin: 0 auto 16px;
            max-width: 220px;
        }

        h1 {
            margin: 0 0 24px;
        }

        a {
            display: inline-block;
            border: 0;
            border-radius: 999px;
            background: #0e7490;
            color: #ffffff;
            cursor: pointer;
            font-size: 1rem;
            padding: 12px 28px;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <section id="osint-help" class="help-modal-overlay" aria-hidden="true" aria-live="polite">
        <div class="help-modal" role="dialog" aria-modal="true" aria-label="OSINT Help">
            <h2 style="text-align:center">OSINT Help</h2>
            <ol class="help-steps">
                <li>
                    <span>Why you are on this page</span>
                    This screen appears when access is required or your session has ended.
                </li>
                <li>
                    <span>Sign in again</span>
                    Select <b>Sign In</b>, enter your account email, and continue.
                </li>
                <li>
                    <span>Verify with one-time code</span>
                    Use the code sent to your email to complete authentication. Delivery is usually within 1-2 minutes.
                </li>
                <li>
                    <span>Expected result</span>
                    A successful sign-in forwards you to the application automatically.
                </li>
                <li>
                    <span>If authentication fails</span>
                    Invalid or expired codes return you to sign-in so you can request another code.
                </li>
                <li>
                    <span>No code in inbox</span>
                    Check spam or junk folders first and look for mail from <b>hello@4n6ir.com</b>. If needed, restart sign-in and request a new one-time code.
                </li>
                <li>
                    <span>Need support</span>
                    If access still fails, contact your sponsor or administrator to verify your invitation.
                </li>
            </ol>
            <div style="text-align:center">
                <button class="help-close" type="button" onclick="closeHelp()">Close</button>
            </div>
        </div>
    </section>
    <main>
        <button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>
        <img src="https://cdn.4n6ir.com/nofishing.png" alt="No Fishing Logo">
        <a href="{login_url}">Sign In</a>
    </main>
    <script>
        function toggleHelp() {
            const modal = document.getElementById('osint-help');
            modal.classList.toggle('open');
            document.body.classList.toggle('modal-open', modal.classList.contains('open'));
        }

        function closeHelp() {
            const modal = document.getElementById('osint-help');
            modal.classList.remove('open');
            document.body.classList.remove('modal-open');
        }

        window.addEventListener('click', function(event) {
            const modal = document.getElementById('osint-help');
            if (event.target === modal) {
                closeHelp();
            }
        });
    </script>
</body>
</html>'''.replace('{login_url}', login_url).replace('https://cdn.4n6ir.com', cdn_base_url)

    auth_code = query.get('code', [None])[0]
    if auth_code:
        if not all(c.isalnum() or c in ['_', '-', '.'] for c in auth_code):
            code = 400
        else:
            b64 = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            url = cognito_domain + '/oauth2/token'
            headers = {
               'Authorization': f'Basic {b64}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = {
                'code': auth_code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri
            }
            response = requests.post(url, headers=headers, data=data, timeout=5)
            if response.status_code == 200 and 'id_token' in response.json():
                code = 200
                access_token = response.json()['access_token']
                home_endpoint = os.getenv('HOME_ENDPOINT', 'https://dev.osint.4n6ir.com/home')
                html = '''<!DOCTYPE html>
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
        }

        body.modal-open {
            overflow: hidden;
        }

        main {
            position: relative;
            max-width: 540px;
            margin: 48px auto;
            padding: 32px;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 18px 40px rgba(16, 35, 60, 0.12);
            text-align: center;
        }

        .help-button {
            position: absolute;
            top: 16px;
            right: 16px;
            width: 34px;
            height: 34px;
            border: 1px solid #cbd5e1;
            border-radius: 50%;
            background: #ffffff;
            color: #10233c;
            font-size: 1rem;
            font-weight: 700;
            line-height: 1;
            cursor: pointer;
        }

        .help-button:hover {
            background: #f8fafc;
        }

        .help-modal-overlay {
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            background: rgba(16, 35, 60, 0.45);
            padding: 16px;
            z-index: 1000;
        }

        .help-modal-overlay.open {
            display: flex;
        }

        .help-modal {
            width: min(420px, 100%);
            padding: 18px 18px 14px;
            border: 1px solid #dbe4ee;
            border-radius: 14px;
            background: #ffffff;
            box-shadow: 0 18px 36px rgba(16, 35, 60, 0.2);
            text-align: left;
            max-height: 80vh;
            overflow-y: auto;
        }

        .help-modal h2 {
            margin: 0 0 12px;
            font-size: 1rem;
        }

        .help-steps {
            margin: 0;
            padding-left: 20px;
            color: #486581;
            font-size: 0.92rem;
        }

        .help-steps li {
            margin-bottom: 12px;
        }

        .help-steps span {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            color: #10233c;
        }

        .help-close {
            display: inline-block;
            margin-top: 12px;
            border: 0;
            border-radius: 999px;
            background: #0e7490;
            color: #ffffff;
            font-size: 1rem;
            padding: 12px 28px;
            cursor: pointer;
        }

        img {
            display: block;
            margin: 0 auto 16px;
            max-width: 220px;
        }

        h1 {
            margin: 0 0 8px;
        }
    </style>
    <script>
        const headers = { 'Authorization': 'Bearer ' + '{access_token}' };
        fetch('{home_endpoint_url}', { headers: headers })
            .then(response => response.text())
            .then(data => { document.write(data); });
    </script>
</head>
<body>
    <section id="osint-help" class="help-modal-overlay" aria-hidden="true" aria-live="polite">
        <div class="help-modal" role="dialog" aria-modal="true" aria-label="OSINT Help">
            <h2>OSINT Help</h2>
            <ol class="help-steps">
                <li>
                    <span>Invite-only sign-in</span>
                    Access is limited to invited accounts. Use the invited email address during sign-in.
                </li>
                <li>
                    <span>Email confirmation</span>
                    After entering your email, a one-time verification code is sent to your inbox.
                </li>
                <li>
                    <span>Code-based login</span>
                    Enter the verification code to continue. No password is required, and codes usually arrive within 1-2 minutes.
                </li>
                <li>
                    <span>Automatic redirect</span>
                    Successful verification redirects you to the main application without additional steps.
                </li>
                <li>
                    <span>Retry path</span>
                    If the code is expired or incorrect, return to sign-in and request a fresh code.
                </li>
                <li>
                    <span>Session behavior</span>
                    For security, inactive sessions may expire and require sign-in again.
                </li>
                <li>
                    <span>Invite access issues</span>
                    If login still fails, verify you are using the invited email account. Non-invited addresses are rejected, and support can be requested through your sponsor or administrator.
                </li>
            </ol>
            <div style="text-align:center">
                <button class="help-close" type="button" onclick="closeHelp()">Close</button>
            </div>
        </div>
    </section>
    <main>
        <button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>
        <img src="https://cdn.4n6ir.com/lunker.png" alt="OSINT Logo">
        <h1>Happy Fishing!</h1>
    </main>
    <script>
        function toggleHelp() {
            const modal = document.getElementById('osint-help');
            modal.classList.toggle('open');
            document.body.classList.toggle('modal-open', modal.classList.contains('open'));
        }

        function closeHelp() {
            const modal = document.getElementById('osint-help');
            modal.classList.remove('open');
            document.body.classList.remove('modal-open');
        }

        window.addEventListener('click', function(event) {
            const modal = document.getElementById('osint-help');
            if (event.target === modal) {
                closeHelp();
            }
        });
    </script>
</body>
</html>'''.replace('{home_endpoint_url}', home_endpoint).replace('{access_token}', access_token).replace('https://cdn.4n6ir.com', cdn_base_url)

    return {
        'statusCode': code,
        'body': html,
        'headers': {
            'Content-Type': 'text/html'
        }
    }