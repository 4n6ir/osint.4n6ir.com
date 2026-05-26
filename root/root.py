import os
from urllib.parse import urlencode

def handler(_event, _context):

    clientid = os.environ['CLIENT_ID']
    cognito_domain = os.environ['COGNITO_DOMAIN']
    redirect_uri = os.environ['COGNITO_REDIRECT_URI']
    cdn_base_url = os.environ['CDN_BASE_URL']
    login_url = (
        cognito_domain + '/login?'
        + urlencode({
            'client_id': clientid,
            'response_type': 'code',
            'scope': 'openid',
            'redirect_uri': redirect_uri
        })
    )

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Let's Fish!</title>
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

        .help-button {{
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
        }}

        .help-button:hover {{
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

        img {{
            display: block;
            margin: 0 auto 16px;
            max-width: 220px;
        }}

        h1 {{
            margin: 0 0 8px;
        }}

        p {{
            margin: 0 0 24px;
            color: #486581;
            line-height: 1.5;
        }}

        a {{
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

        .disclaimer {{
            margin: 16px 0 0;
            padding: 10px 12px;
            border: 1px solid #d8e2f0;
            border-radius: 10px;
            background: #f8fafc;
            color: #5c6f84;
            font-size: 0.78rem;
            line-height: 1.4;
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
                    <span>Start here</span>
                    This is the application landing page. Select <b>Sign In</b> to begin secure access.
                </li>
                <li>
                    <span>Use your account email</span>
                    Enter the same email address used for your access and continue to verification.
                </li>
                <li>
                    <span>Confirm with one-time code</span>
                    A code is sent to your inbox, usually within 1-2 minutes. Enter it to complete login. No password is required.
                </li>
                <li>
                    <span>After sign-in</span>
                    When verification succeeds, you are redirected to your Home view automatically.
                </li>
                <li>
                    <span>If something fails</span>
                    Expired or invalid codes return you to sign-in. Request a new code and try again.
                </li>
                <li>
                    <span>Code did not arrive</span>
                    Check spam or junk folders, confirm the email address is correct, and look for mail from <b>hello@4n6ir.com</b>. Then request a fresh sign-in code.
                </li>
                <li>
                    <span>Need support</span>
                    If sign-in still fails, contact your sponsor or administrator to confirm your invited account access.
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
        <h1>Let's Fish!</h1>
        <p>Sign in to continue to the fishing grounds.</p>
        <a href="{login_url}">Sign In</a>
        <p class="disclaimer">
            Disclaimer: This service is provided as-is with no warranty or liability for losses, interruptions, or actions taken from its data. By signing in, you consent to receive email messages required for login and operational alerts, including alert digests and account/security notifications. Privacy: We only use your email for login and service alerts; we do not sell personal data. Third-party subscriptions are not provided as part of this service.
        </p>
    </main>
    <script>
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

        window.addEventListener('click', function(event) {{
            const modal = document.getElementById('osint-help');
            if (event.target === modal) {{
                closeHelp();
            }}
        }});
    </script>
</body>
</html>'''.replace('https://cdn.4n6ir.com', cdn_base_url)

    return {
        'statusCode': 200,
        'body': html,
        'headers': {
            'Content-Type': 'text/html; charset=utf-8'
        }
    }