# pyright: reportPrivateUsage=none

import importlib
import os
import unittest
from unittest.mock import Mock, patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('CREDENTIALS_SECRET_ARN', 'arn:aws:secretsmanager:us-east-1:111122223333:secret:test')
os.environ.setdefault('COGNITO_DOMAIN', 'https://auth.example.com')
os.environ.setdefault('COGNITO_REDIRECT_URI', 'https://app.example.com/auth')
os.environ.setdefault('HOME_ENDPOINT', 'https://api.example.com/home')
os.environ.setdefault('CDN_BASE_URL', 'https://cdn.example.com')
os.environ.setdefault('ACCESS_TOKEN_COOKIE_NAME', 'osint_at')


class _FakeCognitoExceptions:
    class UsernameExistsException(Exception):
        pass

    class NotAuthorizedException(Exception):
        pass

    class CodeMismatchException(Exception):
        pass

    class ExpiredCodeException(Exception):
        pass

    class UserNotFoundException(Exception):
        pass


class AuthHandlerTests(unittest.TestCase):
    def setUp(self):
        self.auth = importlib.import_module('auth.auth')
        self.auth = importlib.reload(self.auth)

    def _event(self, body: str):
        return {
            'requestContext': {'http': {'method': 'POST'}},
            'body': body,
            'isBase64Encoded': False,
        }

    def _get_event(self):
        return {
            'requestContext': {'http': {'method': 'GET'}},
            'rawQueryString': '',
        }

    def _patch_common(self, cognito_client):
        return patch.object(self.auth, 'COGNITO_CLIENT', cognito_client), patch.object(
            self.auth, '_get_credentials', return_value=('client-id', 'client-secret')
        )

    def test_signup_start_existing_confirmed_user_routes_to_signin(self):
        fake_cognito = Mock()
        fake_cognito.exceptions = _FakeCognitoExceptions
        fake_cognito.sign_up.side_effect = _FakeCognitoExceptions.UsernameExistsException('exists')
        fake_cognito.initiate_auth.return_value = {
            'ChallengeName': 'EMAIL_OTP',
            'Session': 'session-1',
        }

        patch_cognito, patch_credentials = self._patch_common(fake_cognito)
        with patch_cognito, patch_credentials:
            response = self.auth.handler(
                self._event('action=signup_start&email=user%40example.com'),
                None,
            )

        self.assertEqual(response['statusCode'], 200)
        self.assertIn('Complete Sign In', response['body'])
        self.assertIn('Account already exists.', response['body'])
        fake_cognito.sign_up.assert_called_once()
        fake_cognito.resend_confirmation_code.assert_not_called()

    def test_signup_start_existing_unconfirmed_user_resends_code(self):
        fake_cognito = Mock()
        fake_cognito.exceptions = _FakeCognitoExceptions
        fake_cognito.sign_up.side_effect = _FakeCognitoExceptions.UsernameExistsException('exists')
        fake_cognito.initiate_auth.side_effect = _FakeCognitoExceptions.NotAuthorizedException(
            'User is not confirmed.'
        )

        patch_cognito, patch_credentials = self._patch_common(fake_cognito)
        with patch_cognito, patch_credentials:
            response = self.auth.handler(
                self._event('action=signup_start&email=user%40example.com'),
                None,
            )

        self.assertEqual(response['statusCode'], 200)
        self.assertIn('Verify Account', response['body'])
        self.assertIn('new verification code was sent', response['body'])
        fake_cognito.resend_confirmation_code.assert_called_once_with(
            ClientId='client-id',
            Username='user@example.com',
            SecretHash=unittest.mock.ANY,
        )

    def test_signin_confirm_sets_cookie_and_redirects_home(self):
        fake_cognito = Mock()
        fake_cognito.exceptions = _FakeCognitoExceptions
        fake_cognito.respond_to_auth_challenge.return_value = {
            'AuthenticationResult': {'AccessToken': 'access-token-1'}
        }

        patch_cognito, patch_credentials = self._patch_common(fake_cognito)
        with patch_cognito, patch_credentials, patch.dict(
            os.environ,
            {
                'HOME_ENDPOINT': 'https://api.example.com/home',
                'COGNITO_DOMAIN': 'https://auth.example.com',
                'COGNITO_REDIRECT_URI': 'https://app.example.com/auth',
                'CDN_BASE_URL': 'https://cdn.example.com',
            },
            clear=False,
        ):
            response = self.auth.handler(
                self._event(
                    'action=signin_confirm&email=user%40example.com&code=123456&session=session-1'
                ),
                None,
            )

        self.assertEqual(response['statusCode'], 302)
        self.assertEqual(response['headers']['Location'], '/home')
        self.assertIn('cookies', response)
        self.assertTrue(any(cookie.startswith('osint_at=access-token-1;') for cookie in response['cookies']))
        self.assertTrue(any('HttpOnly' in cookie for cookie in response['cookies']))
        self.assertTrue(any('Secure' in cookie for cookie in response['cookies']))

    def test_signin_confirm_uses_custom_cookie_name_from_env(self):
        fake_cognito = Mock()
        fake_cognito.exceptions = _FakeCognitoExceptions
        fake_cognito.respond_to_auth_challenge.return_value = {
            'AuthenticationResult': {'AccessToken': 'access-token-1'}
        }

        with patch.dict(os.environ, {'ACCESS_TOKEN_COOKIE_NAME': 'custom_at'}, clear=False):
            auth_module = importlib.reload(importlib.import_module('auth.auth'))
            patch_cognito = patch.object(auth_module, 'COGNITO_CLIENT', fake_cognito)
            patch_credentials = patch.object(
                auth_module,
                '_get_credentials',
                return_value=('client-id', 'client-secret'),
            )
            with patch_cognito, patch_credentials:
                response = auth_module.handler(
                    self._event('action=signin_confirm&email=user%40example.com&code=123456&session=session-1'),
                    None,
                )

        self.assertEqual(response['statusCode'], 302)
        self.assertTrue(any(cookie.startswith('custom_at=access-token-1;') for cookie in response['cookies']))

    def test_get_invite_only_hides_create_account_button(self):
        with patch.dict(os.environ, {'AUTH_SELF_SIGN_UP_ENABLED': 'false'}, clear=False), patch.object(
            self.auth,
            '_get_credentials',
            return_value=('client-id', 'client-secret'),
        ):
            response = self.auth.handler(self._get_event(), None)

        self.assertEqual(response['statusCode'], 200)
        self.assertNotIn('Create Account', response['body'])
        self.assertIn('name="action" value="signin_start"', response['body'])

    def test_invite_only_rejects_signup_actions(self):
        fake_cognito = Mock()
        fake_cognito.exceptions = _FakeCognitoExceptions

        patch_cognito, patch_credentials = self._patch_common(fake_cognito)
        with patch.dict(os.environ, {'AUTH_SELF_SIGN_UP_ENABLED': 'false'}, clear=False), patch_cognito, patch_credentials:
            response = self.auth.handler(
                self._event('action=signup_start&email=user%40example.com'),
                None,
            )

        self.assertEqual(response['statusCode'], 403)
        self.assertIn('invite-only', response['body'])
        fake_cognito.sign_up.assert_not_called()


if __name__ == '__main__':
    unittest.main()
