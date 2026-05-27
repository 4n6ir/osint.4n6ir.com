# pyright: reportPrivateUsage=none

import importlib
import os
import unittest
from unittest.mock import Mock, patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('ACCESS_TOKEN_COOKIE_NAME', 'osint_at')


class AuthorizerTests(unittest.TestCase):
    def setUp(self):
        self.authorizer = importlib.import_module('authorizer.authorizer')
        self.authorizer = importlib.reload(self.authorizer)

    def test_handler_authorizes_from_bearer_header(self):
        event = {'headers': {'Authorization': 'Bearer access-token-1'}}
        fake_idp = Mock()
        fake_idp.get_user.return_value = {
            'Username': 'user-1',
            'UserAttributes': [
                {'Name': 'email', 'Value': 'user@example.com'},
                {'Name': 'email_verified', 'Value': 'true'},
            ],
        }

        with patch.object(self.authorizer, 'COGNITO_IDP', fake_idp):
            response = self.authorizer.handler(event, None)

        self.assertTrue(response['isAuthorized'])
        self.assertEqual(response['context']['email'], 'user@example.com')

    def test_handler_authorizes_from_cookie_when_header_missing(self):
        event = {'headers': {'Cookie': 'foo=bar; osint_at=access-token-2; theme=dark'}}
        fake_idp = Mock()
        fake_idp.get_user.return_value = {
            'Username': 'user-2',
            'UserAttributes': [
                {'Name': 'email', 'Value': 'cookie@example.com'},
            ],
        }

        with patch.object(self.authorizer, 'COGNITO_IDP', fake_idp):
            response = self.authorizer.handler(event, None)

        self.assertTrue(response['isAuthorized'])
        self.assertEqual(response['context']['email'], 'cookie@example.com')
        fake_idp.get_user.assert_called_once_with(AccessToken='access-token-2')

    def test_handler_denies_when_token_missing(self):
        event = {'headers': {'Cookie': 'foo=bar'}}

        response = self.authorizer.handler(event, None)

        self.assertEqual(response, {'isAuthorized': False})

    def test_handler_authorizes_from_event_cookies_array(self):
        event = {'headers': {}, 'cookies': ['foo=bar', 'osint_at=access-token-4']}
        fake_idp = Mock()
        fake_idp.get_user.return_value = {
            'Username': 'user-4',
            'UserAttributes': [
                {'Name': 'email', 'Value': 'array@example.com'},
            ],
        }

        with patch.object(self.authorizer, 'COGNITO_IDP', fake_idp):
            response = self.authorizer.handler(event, None)

        self.assertTrue(response['isAuthorized'])
        self.assertEqual(response['context']['email'], 'array@example.com')
        fake_idp.get_user.assert_called_once_with(AccessToken='access-token-4')

    def test_handler_authorizes_from_quoted_cookie_value(self):
        event = {'headers': {'Cookie': 'osint_at="access-token-6"'}}
        fake_idp = Mock()
        fake_idp.get_user.return_value = {
            'Username': 'user-6',
            'UserAttributes': [
                {'Name': 'email', 'Value': 'quoted@example.com'},
            ],
        }

        with patch.object(self.authorizer, 'COGNITO_IDP', fake_idp):
            response = self.authorizer.handler(event, None)

        self.assertTrue(response['isAuthorized'])
        fake_idp.get_user.assert_called_once_with(AccessToken='access-token-6')

    def test_handler_authorizes_from_multivalue_headers_cookie(self):
        event = {'headers': {}, 'multiValueHeaders': {'Cookie': ['foo=bar', 'osint_at=access-token-7']}}
        fake_idp = Mock()
        fake_idp.get_user.return_value = {
            'Username': 'user-7',
            'UserAttributes': [
                {'Name': 'email', 'Value': 'multi@example.com'},
            ],
        }

        with patch.object(self.authorizer, 'COGNITO_IDP', fake_idp):
            response = self.authorizer.handler(event, None)

        self.assertTrue(response['isAuthorized'])
        fake_idp.get_user.assert_called_once_with(AccessToken='access-token-7')

    def test_handler_uses_custom_cookie_name_from_env(self):
        event = {'headers': {'Cookie': 'foo=bar; custom_at=custom-token-3'}}
        fake_idp = Mock()
        fake_idp.get_user.return_value = {
            'Username': 'user-3',
            'UserAttributes': [
                {'Name': 'email', 'Value': 'custom@example.com'},
            ],
        }

        with patch.dict(os.environ, {'ACCESS_TOKEN_COOKIE_NAME': 'custom_at'}, clear=False):
            authorizer_module = importlib.reload(importlib.import_module('authorizer.authorizer'))
            with patch.object(authorizer_module, 'COGNITO_IDP', fake_idp):
                response = authorizer_module.handler(event, None)

        self.assertTrue(response['isAuthorized'])
        self.assertEqual(response['context']['email'], 'custom@example.com')
        fake_idp.get_user.assert_called_once_with(AccessToken='custom-token-3')

    def test_handler_accepts_legacy_cookie_name_with_custom_env(self):
        event = {'headers': {'Cookie': 'osint_at=legacy-token-1'}}
        fake_idp = Mock()
        fake_idp.get_user.return_value = {
            'Username': 'user-5',
            'UserAttributes': [
                {'Name': 'email', 'Value': 'legacy@example.com'},
            ],
        }

        with patch.dict(os.environ, {'ACCESS_TOKEN_COOKIE_NAME': 'custom_at'}, clear=False):
            authorizer_module = importlib.reload(importlib.import_module('authorizer.authorizer'))
            with patch.object(authorizer_module, 'COGNITO_IDP', fake_idp):
                response = authorizer_module.handler(event, None)

        self.assertTrue(response['isAuthorized'])
        self.assertEqual(response['context']['email'], 'legacy@example.com')
        fake_idp.get_user.assert_called_once_with(AccessToken='legacy-token-1')


if __name__ == '__main__':
    unittest.main()
