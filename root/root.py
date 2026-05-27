import os

def handler(_event, _context):

    cdn_base_url = os.environ['CDN_BASE_URL']
    login_url = '/auth'

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

        main {{
            width: min(540px, calc(100% - 48px));
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
    <main>
        <img src="https://cdn.4n6ir.com/lunker.png" alt="OSINT Logo">
        <h1>Let's Fish!</h1>
        <p>Sign in to continue to the fishing grounds.</p>
        <a href="{login_url}">Sign In</a>
        <p class="disclaimer">
            Disclaimer: This service is provided as-is with no warranty or liability for losses, interruptions, or actions taken from its data. By signing in, you consent to receive email messages required for login and operational alerts, including alert digests and account/security notifications. Privacy: We only use your email for login and service alerts; we do not sell personal data. Third-party subscriptions are not provided as part of this service.
        </p>
    </main>
</body>
</html>'''.replace('https://cdn.4n6ir.com', cdn_base_url)

    return {
        'statusCode': 200,
        'body': html,
        'headers': {
            'Content-Type': 'text/html; charset=utf-8'
        }
    }