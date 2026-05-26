# pyright: reportPrivateUsage=none, reportUnusedVariable=none
# pylint: disable=protected-access,unused-variable

import base64
from decimal import Decimal
import json
import os
import time
import unittest
from unittest.mock import Mock, patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')

from home import home as home_shared


GET_DOMAIN_SECTIONS = getattr(home_shared, '_get_domain_sections')


def _post_event(action, entry='example.com', authorization='token'):
    return {
        'requestContext': {
            'http': {
                'method': 'POST'
            }
        },
        'headers': {
            'Authorization': authorization
        },
        'body': json.dumps({'action': action, 'entry': entry}),
    }


class WebUiHandlerTests(unittest.TestCase):
    def setUp(self):
        home_shared.IDENTITY_CACHE.clear()
        home_shared.TABLE_CACHE.clear()
        os.environ['AWS_REGION'] = 'us-east-1'
        os.environ['TLD_TABLE'] = 'tld-table'
        os.environ['WATCHLIST_TABLE'] = 'watchlist-table'
        os.environ['USERS_TABLE'] = 'users-table'
        os.environ['DOMAINS_TABLE'] = 'domains-table'

    def test_get_request_renders_form(self):
        event = {
            'requestContext': {
                'http': {
                    'method': 'GET'
                }
            },
            'headers': {
                'Authorization': 'test-token'
            },
        }

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com', 'region': 'use1'}) as fetch_identity, \
                patch.object(home_shared, '_get_env_table', return_value=object()), \
                patch.object(home_shared, '_list_watchlist_domains', return_value=['example.com']), \
                patch.object(home_shared, '_get_matched_slds', return_value={'example'}):
            response = home_shared._handle_request(event, None)  # noqa: SLF001

        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['headers']['Content-Type'], 'text/html; charset=utf-8')
        self.assertIn('Gone Fishing!', response['body'])
        self.assertIn('example.com', response['body'])
        fetch_identity.assert_called_once_with('test-token')

    def test_post_get_domain_sections_success(self):
        event = _post_event('GetDomainSections')

        expected_sections = {'suspect': {'openSourceIntelligence': [], 'domainsMonitorSubscription': []}}

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_get_env_table', return_value=object()), \
                patch.object(home_shared, '_get_domains_monitor_subscription', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_get_domain_sections', return_value=expected_sections), \
            patch.object(home_shared, '_get_permutation_count', return_value=7):
            response = home_shared._handle_request(event, None)  # noqa: SLF001

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['headers']['Content-Type'], 'application/json; charset=utf-8')
        self.assertEqual(payload['sections'], expected_sections)
        self.assertEqual(payload['permutations'], 7)

    def test_post_get_domain_sections_failure_falls_back(self):
        event = _post_event('GetDomainSections')

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_get_domain_sections', side_effect=TypeError('boom')):
            response = home_shared._handle_request(event, None)  # noqa: SLF001

        payload = json.loads(response['body'])
        self.assertEqual(payload['sections'], {})
        self.assertEqual(payload['permutations'], 0)

    def test_post_get_domain_sections_action_is_case_and_whitespace_insensitive(self):
        event = _post_event('   GetDomainSections   ')

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}) as fetch_identity, \
                patch.object(home_shared, '_get_domain_sections', return_value={'suspect': {'openSourceIntelligence': [], 'domainsMonitorSubscription': []}}) as get_sections, \
            patch.object(home_shared, '_get_permutation_count', return_value=1) as get_count:
            home_shared._handle_request(event, None)  # noqa: SLF001

        get_sections.assert_called_once_with('example.com', 'user@example.com')
        get_count.assert_called_once_with('example.com', 'user@example.com')
        fetch_identity.assert_called_once_with('token')

    def test_post_get_domain_permutations_success(self):
        event = _post_event('GetDomainPermutations')

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_get_domain_permutation_entries', return_value=[
                    {'permutation': 'a', 'enabled': 'ON', 'unique_domains': 7, 'unique_sources': 3},
                    {'permutation': 'b', 'enabled': 'OFF', 'unique_domains': 1, 'unique_sources': 1},
                ]):
            response = home_shared._handle_request(event, None)  # noqa: SLF001

        payload = json.loads(response['body'])
        self.assertEqual(payload['permutations'], ['a'])
        self.assertEqual(payload['permutationStates'], [
            {'permutation': 'a', 'enabled': 'ON', 'unique_domains': 7, 'unique_sources': 3},
            {'permutation': 'b', 'enabled': 'OFF', 'unique_domains': 1, 'unique_sources': 1},
        ])

    def test_post_get_domain_permutations_failure_falls_back(self):
        event = _post_event('GetDomainPermutations')

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_get_domain_permutation_entries', side_effect=TypeError('boom')):
            response = home_shared._handle_request(event, None)  # noqa: SLF001

        payload = json.loads(response['body'])
        self.assertEqual(payload['permutations'], [])
        self.assertEqual(payload['permutationStates'], [])

    def test_post_put_item_success_renders_submission_result(self):
        event = _post_event('PutItem')

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_process_submission', return_value=('example.com', True, 'saved')), \
                patch.object(home_shared, '_render_result', return_value='<html>ok</html>') as render_result:
            response = home_shared._handle_request(event, None)  # noqa: SLF001

        self.assertEqual(response['body'], '<html>ok</html>')
        render_result.assert_called_once_with('example.com', True, 'token', 'submission')

    def test_post_put_item_failure_renders_failure_message(self):
        event = _post_event('PutItem', entry='bad')

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_process_submission', return_value=('bad', False, 'Invalid domain')), \
                patch.object(home_shared, '_render_result', return_value='<html>fail</html>') as render_result:
            response = home_shared._handle_request(event, None)  # noqa: SLF001

        self.assertEqual(response['body'], '<html>fail</html>')
        render_result.assert_called_once_with('bad\n\nInvalid domain', False, 'token', 'submission')

    def test_post_delete_item_success_renders_deletion_result(self):
        event = _post_event('DeleteItem')

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_process_submission', return_value=('example.com', True, 'deleted')), \
                patch.object(home_shared, '_render_result', return_value='<html>deleted</html>') as render_result:
            response = home_shared._handle_request(event, None)  # noqa: SLF001

        self.assertEqual(response['body'], '<html>deleted</html>')
        render_result.assert_called_once_with('example.com', True, 'token', 'deletion')

    def test_post_delete_item_failure_renders_failure_message(self):
        event = _post_event('DeleteItem')

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_process_submission', return_value=('example.com', False, 'Nothing to delete.')), \
                patch.object(home_shared, '_render_result', return_value='<html>delete-fail</html>') as render_result:
            response = home_shared._handle_request(event, None)

        self.assertEqual(response['body'], '<html>delete-fail</html>')
        render_result.assert_called_once_with('example.com\n\nNothing to delete.', False, 'token', 'deletion')

    def test_post_invalid_json_defaults_to_put_item(self):
        event = {
            'requestContext': {
                'http': {
                    'method': 'POST'
                }
            },
            'headers': {
                'Authorization': 'token'
            },
            'body': '{invalid-json',
        }

        with patch.object(home_shared, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home_shared, '_process_submission', return_value=('example.com', True, 'saved')) as process_submission, \
                patch.object(home_shared, '_render_result', return_value='<html>ok</html>'):
            home_shared._handle_request(event, None)  # noqa: SLF001

        process_submission.assert_called_once_with('', 'user@example.com', 'PutItem')


class DomainNormalizationTests(unittest.TestCase):
    def test_normalize_domain_strips_whitespace(self):
        self.assertEqual(home_shared._normalize_domain('  Example.COM  '), 'example.com')  # noqa: SLF001

    def test_normalize_domain_removes_trailing_dot(self):
        self.assertEqual(home_shared._normalize_domain('example.com.'), 'example.com')  # noqa: SLF001

    def test_normalize_domain_empty_string_returns_empty(self):
        self.assertEqual(home_shared._normalize_domain(''), '')  # noqa: SLF001

    def test_normalize_domain_non_string_returns_empty(self):
        self.assertEqual(home_shared._normalize_domain(None), '')  # noqa: SLF001
        self.assertEqual(home_shared._normalize_domain(123), '')  # noqa: SLF001
        self.assertEqual(home_shared._normalize_domain([]), '')  # noqa: SLF001

    def test_normalize_domain_multiple_dots(self):
        self.assertEqual(home_shared._normalize_domain('sub.example.com'), 'sub.example.com')  # noqa: SLF001


class DomainValidationTests(unittest.TestCase):
    def test_validate_domain_valid_format(self):
        is_valid, msg = home_shared._validate_domain('example.com')  # noqa: SLF001
        self.assertTrue(is_valid)
        self.assertEqual(msg, '')

    def test_validate_domain_empty_string(self):
        is_valid, msg = home_shared._validate_domain('')  # noqa: SLF001
        self.assertFalse(is_valid)
        self.assertIn('required', msg.lower())

    def test_validate_domain_no_dot(self):
        is_valid, msg = home_shared._validate_domain('example')  # noqa: SLF001
        self.assertFalse(is_valid)
        self.assertIn('single dot', msg.lower())

    def test_validate_domain_trailing_dot_format(self):
        is_valid, msg = home_shared._validate_domain('example.')  # noqa: SLF001
        self.assertFalse(is_valid)

    def test_validate_domain_subdomain(self):
        is_valid, msg = home_shared._validate_domain('sub.example.com')
        self.assertFalse(is_valid)
        self.assertIn('exactly one dot', msg.lower())

    def test_validate_domain_multiple_subdomains(self):
        is_valid, msg = home_shared._validate_domain('a.b.c.example.com')
        self.assertFalse(is_valid)
        self.assertIn('exactly one dot', msg.lower())


class JwtDecodingTests(unittest.TestCase):
    def test_decode_jwt_payload_no_authorization(self):
        payload = home_shared._decode_jwt_payload('')
        self.assertEqual(payload, {})

    def test_decode_jwt_payload_invalid_format(self):
        payload = home_shared._decode_jwt_payload('invalid-token')
        self.assertEqual(payload, {})

    def test_decode_jwt_payload_valid_jwt(self):
        token_payload = {'email': 'user@example.com', 'region': 'us-east-1'}
        encoded_payload = base64.urlsafe_b64encode(json.dumps(token_payload).encode()).decode().rstrip('=')
        token = f'Bearer header.{encoded_payload}.signature'

        payload = home_shared._decode_jwt_payload(token)
        self.assertEqual(payload['email'], 'user@example.com')
        self.assertEqual(payload['region'], 'us-east-1')

    def test_decode_jwt_payload_non_dict_payload(self):
        encoded_payload = base64.urlsafe_b64encode(b'"not a dict"').decode().rstrip('=')
        token = f'Bearer header.{encoded_payload}.signature'

        payload = home_shared._decode_jwt_payload(token)
        self.assertEqual(payload, {})

    def test_decode_jwt_payload_malformed_json(self):
        encoded_payload = base64.urlsafe_b64encode(b'{invalid json}').decode().rstrip('=')
        token = f'Bearer header.{encoded_payload}.signature'

        payload = home_shared._decode_jwt_payload(token)
        self.assertEqual(payload, {})


class IdentityBuildingTests(unittest.TestCase):
    def test_build_identity_with_email_field(self):
        payload = {'email': 'test@example.com', 'region': 'us-west-2'}
        identity = home_shared._build_identity(payload, 'default-region')
        self.assertEqual(identity['email'], 'test@example.com')
        self.assertEqual(identity['region'], 'us-west-2')

    def test_build_identity_fallback_to_username(self):
        payload = {'username': 'testuser', 'region': 'us-east-1'}
        identity = home_shared._build_identity(payload, 'default-region')
        self.assertEqual(identity['email'], 'testuser')

    def test_build_identity_fallback_to_cognito_username(self):
        payload = {'cognito:username': 'cognito-user', 'zoneinfo': 'UTC'}
        identity = home_shared._build_identity(payload, 'default-region')
        self.assertEqual(identity['email'], 'cognito-user')
        self.assertEqual(identity['region'], 'UTC')

    def test_build_identity_fallback_to_custom_region(self):
        payload = {'email': 'test@example.com', 'custom:region': 'ap-south-1'}
        identity = home_shared._build_identity(payload, 'default-region')
        self.assertEqual(identity['region'], 'ap-south-1')

    def test_build_identity_all_unknown(self):
        identity = home_shared._build_identity({}, 'default-region')
        self.assertEqual(identity['email'], 'unknown')
        self.assertEqual(identity['region'], 'default-region')


class AuthorizationNormalizationTests(unittest.TestCase):
    def test_normalize_authorization_with_bearer_prefix(self):
        result = home_shared._normalize_authorization('Bearer token123')  # noqa: SLF001
        self.assertEqual(result, 'Bearer token123')

    def test_normalize_authorization_without_prefix(self):
        result = home_shared._normalize_authorization('token123')  # noqa: SLF001
        self.assertEqual(result, 'Bearer token123')

    def test_normalize_authorization_empty_string(self):
        result = home_shared._normalize_authorization('')  # noqa: SLF001
        self.assertEqual(result, '')

    def test_normalize_authorization_whitespace_only(self):
        result = home_shared._normalize_authorization('   ')  # noqa: SLF001
        self.assertEqual(result, '')

    def test_normalize_authorization_case_insensitive_prefix(self):
        result = home_shared._normalize_authorization('bearer token123')  # noqa: SLF001
        self.assertEqual(result, 'bearer token123')


class ProcessSubmissionTests(unittest.TestCase):
    def setUp(self):
        os.environ['TLD_TABLE'] = 'tld-table'
        os.environ['WATCHLIST_TABLE'] = 'watchlist-table'
        os.environ['USERS_TABLE'] = 'users-table'

    def test_process_submission_invalid_domain_format(self):
        domain, success, msg = home_shared._process_submission('invalid', 'user@example.com', 'PutItem')  # noqa: SLF001
        self.assertFalse(success)
        self.assertIn('single dot', msg.lower())

    def test_process_submission_unknown_email(self):
        domain, success, msg = home_shared._process_submission('example.com', 'unknown', 'PutItem')  # noqa: SLF001
        self.assertFalse(success)
        self.assertIn('identity', msg.lower())

    def test_process_submission_empty_email(self):
        domain, success, msg = home_shared._process_submission('example.com', '', 'PutItem')  # noqa: SLF001
        self.assertFalse(success)

    def test_process_submission_tld_not_found(self):
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=False):
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        self.assertFalse(success)
        self.assertIn('unknown top-level domain', msg.lower())

    def test_process_submission_put_item_success(self):
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record') as ensure_user_record, \
                patch.object(home_shared, '_get_user_monitors_count', return_value=1), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=0), \
                patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_put_watchlist_domain') as put_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        self.assertTrue(success)
        self.assertEqual(domain, 'example.com')
        put_domain.assert_called_once_with(mock_watchlist_table, 'user@example.com', 'example.com')
        ensure_user_record.assert_called_once_with(mock_users_table, 'user@example.com')

    def test_process_submission_put_item_rejects_duplicate_domain(self):
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record') as ensure_user_record, \
                patch.object(home_shared, '_get_user_monitors_count', return_value=1), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=1), \
                patch.object(home_shared, '_watchlist_domain_exists', return_value=True), \
                patch.object(home_shared, '_put_watchlist_domain') as put_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        self.assertFalse(success)
        self.assertEqual(domain, 'example.com')
        self.assertIn('already exists', msg.lower())
        # _ensure_user_record is called early as part of the flow
        ensure_user_record.assert_called_once()
        put_domain.assert_not_called()

    def test_process_submission_put_item_allows_when_under_monitors_limit(self):
        """User should be able to add domains when below their monitors limit"""
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record') as ensure_user_record, \
                patch.object(home_shared, '_get_user_monitors_count', return_value=5), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=2), \
                patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_put_watchlist_domain') as put_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        self.assertTrue(success)
        self.assertEqual(domain, 'example.com')
        ensure_user_record.assert_called_once()
        put_domain.assert_called_once()

    def test_process_submission_put_item_rejects_when_monitors_limit_reached(self):
        """User should NOT be able to add domains when at their monitors limit"""
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record') as ensure_user_record, \
                patch.object(home_shared, '_get_user_monitors_count', return_value=2), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=2), \
            patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_put_watchlist_domain') as put_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        self.assertFalse(success)
        self.assertEqual(domain, 'example.com')
        self.assertIn('reached your monitors limit', msg.lower())
        # _ensure_user_record is called to set up default monitors before quota check
        ensure_user_record.assert_called_once()
        # Domain should not be added since quota was reached
        put_domain.assert_not_called()

    def test_process_submission_put_item_rejects_when_over_monitors_limit(self):
        """User should NOT be able to add domains when they exceed their monitors limit"""
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record') as ensure_user_record, \
                patch.object(home_shared, '_get_user_monitors_count', return_value=2), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=5), \
            patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_put_watchlist_domain') as put_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        self.assertFalse(success)
        self.assertEqual(domain, 'example.com')
        self.assertIn('reached your monitors limit', msg.lower())
        # _ensure_user_record is called to set up default monitors before quota check
        ensure_user_record.assert_called_once()
        # Domain should not be added since quota was exceeded
        put_domain.assert_not_called()

    def test_process_submission_put_item_allows_with_zero_monitors_limit(self):
        """User with monitors=0 (no limit) should always be able to add domains"""
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record') as ensure_user_record, \
                patch.object(home_shared, '_get_user_monitors_count', return_value=0), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=100), \
                patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_put_watchlist_domain') as put_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        self.assertTrue(success)
        self.assertEqual(domain, 'example.com')
        ensure_user_record.assert_called_once()
        put_domain.assert_called_once()

    def test_process_submission_post_submission_verification_catches_violation(self):
        """Post-submission check should catch if domain count exceeds limit after adding"""
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        # Simulate race condition: pre-check sees count=0, but another client adds
        # so post-check sees count=2 (exceeding limit of 1)
        get_count_calls = [0, 2]  # First call (pre-check) returns 0, second call (post-check) returns 2
        count_side_effect = iter(get_count_calls)
        
        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record'), \
                patch.object(home_shared, '_get_user_monitors_count', side_effect=[1, 1]), \
                patch.object(home_shared, '_get_watchlist_domain_count', side_effect=lambda *args: next(count_side_effect)), \
                patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_put_watchlist_domain'), \
                patch.object(home_shared, '_delete_watchlist_domain') as delete_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        # Should fail because post-check detected violation (count 2 exceeds limit 1)
        self.assertFalse(success)
        self.assertIn('reached your monitors limit', msg.lower())
        # Domain should be deleted after being added due to violation
        delete_domain.assert_called_once_with(mock_watchlist_table, 'user@example.com', 'example.com')

    def test_process_submission_new_user_cannot_exceed_default_monitors_limit(self):
        """New user with default monitors=1 should not be able to add more than 1 domain"""
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record') as ensure_user, \
                patch.object(home_shared, '_get_user_monitors_count', return_value=1), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=1), \
            patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_put_watchlist_domain') as put_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        # Should reject because new user + existing domain = at limit
        self.assertFalse(success)
        self.assertIn('reached your monitors limit', msg.lower())
        # Ensure user record must be called to set up default monitors=1
        ensure_user.assert_called_once_with(mock_users_table, 'user@example.com')
        # Domain should not be added
        put_domain.assert_not_called()

    def test_process_submission_delete_item_success(self):
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_delete_watchlist_domain') as delete_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'DeleteItem')  # noqa: SLF001

        self.assertTrue(success)
        self.assertEqual(domain, 'example.com')
        delete_domain.assert_called_once_with(mock_watchlist_table, 'user@example.com', 'example.com')

    def test_process_submission_delete_item_rejects_missing_domain(self):
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_delete_watchlist_domain') as delete_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'DeleteItem')  # noqa: SLF001

        self.assertFalse(success)
        self.assertEqual(domain, 'example.com')
        self.assertIn('nothing to delete', msg.lower())
        delete_domain.assert_not_called()

    def test_process_submission_delete_item_bypasses_monitors_limit(self):
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_get_user_monitors_count', return_value=1), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=5), \
                patch.object(home_shared, '_watchlist_domain_exists', return_value=True), \
                patch.object(home_shared, '_delete_watchlist_domain') as delete_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'DeleteItem')  # noqa: SLF001

        self.assertTrue(success)
        self.assertEqual(domain, 'example.com')
        self.assertEqual(msg, 'Deleted')
        delete_domain.assert_called_once_with(mock_watchlist_table, 'user@example.com', 'example.com')


class WatchlistDomainCountTests(unittest.TestCase):
    def test_get_watchlist_domain_count_uses_listed_unique_domains(self):
        watchlist_table = Mock()

        with patch.object(home_shared, '_list_watchlist_domains', return_value=['alpha.com', 'beta.com']):
            count = home_shared._get_watchlist_domain_count(watchlist_table, 'user@example.com')  # noqa: SLF001

        self.assertEqual(count, 2)
        watchlist_table.query.assert_not_called()

    def test_get_watchlist_domain_count_falls_back_to_query_when_listing_fails(self):
        watchlist_table = Mock()
        watchlist_table.query.return_value = {'Count': '3'}

        with patch.object(home_shared, '_list_watchlist_domains', side_effect=TypeError('boom')):
            count = home_shared._get_watchlist_domain_count(watchlist_table, 'user@example.com')  # noqa: SLF001

        self.assertEqual(count, 3)
        watchlist_table.query.assert_called_once()


class UserMonitorsCountTests(unittest.TestCase):
    def test_get_user_monitors_count_supports_decimal_values(self):
        users_table = Mock()

        with patch.object(home_shared, '_query_user_record', return_value={'monitors': Decimal('2')}):
            count = home_shared._get_user_monitors_count(users_table, 'user@example.com')  # noqa: SLF001

        self.assertEqual(count, 2)

    def test_process_submission_rejects_when_decimal_monitors_limit_reached(self):
        mock_tld_table = Mock()
        mock_watchlist_table = Mock()
        mock_users_table = Mock()

        with patch.object(home_shared, '_get_env_table', side_effect=[mock_tld_table, mock_watchlist_table, mock_users_table]), \
                patch.object(home_shared, '_tld_exists', return_value=True), \
                patch.object(home_shared, '_ensure_user_record') as ensure_user_record, \
                patch.object(home_shared, '_query_user_record', return_value={'monitors': Decimal('1')}), \
                patch.object(home_shared, '_get_watchlist_domain_count', return_value=1), \
            patch.object(home_shared, '_watchlist_domain_exists', return_value=False), \
                patch.object(home_shared, '_put_watchlist_domain') as put_domain:
            domain, success, msg = home_shared._process_submission('example.com', 'user@example.com', 'PutItem')  # noqa: SLF001

        self.assertFalse(success)
        self.assertEqual(domain, 'example.com')
        self.assertIn('reached your monitors limit', msg.lower())
        ensure_user_record.assert_called_once_with(mock_users_table, 'user@example.com')
        put_domain.assert_not_called()


class RenderFormTests(unittest.TestCase):
    def test_render_form_with_empty_domains(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, [], set())  # noqa: SLF001
        self.assertIn('Gone Fishing!', html)
        self.assertIn('user@example.com', html)
        self.assertNotIn('us-east-1', html)
        self.assertIn('Empty!', html)

    def test_render_form_with_domains(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())  # noqa: SLF001
        self.assertIn('example.com', html)

    def test_render_form_with_matched_slds_highlights(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com', 'test.com'], {'example'})  # noqa: SLF001
        self.assertIn('matched-domain', html)

    def test_render_form_html_escaping(self):
        html = home_shared._render_form('token', {'email': '<script>alert("xss")</script>', 'region': 'us-east-1'}, [], set())  # noqa: SLF001
        self.assertIn('<strong>Email:</strong> &lt;script&gt;', html)
        self.assertIn('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;', html)

    def test_render_form_none_domains_defaults_to_empty(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, None, None)  # noqa: SLF001
        self.assertIn('Gone Fishing!', html)
        self.assertIn('Empty!', html)

    def test_render_form_uses_contains_for_sld_matches(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['phreeesia.com'], {'phreeesia'})  # noqa: SLF001
        self.assertIn('matched-domain', html)

    def test_render_form_includes_refresh_button(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())  # noqa: SLF001
        self.assertIn('refreshCurrentView(event)', html)

    def test_render_form_toolbar_button_order_help_refresh_logoff(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())  # noqa: SLF001
        help_index = html.index('toggleHelp()')
        refresh_index = html.index('refreshCurrentView(event)')
        logoff_index = html.index('logOff()')
        self.assertLess(help_index, refresh_index)
        self.assertLess(refresh_index, logoff_index)

    def test_render_form_includes_refresh_current_view_logic(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())  # noqa: SLF001
        self.assertIn('async function refreshCurrentView(event)', html)
        self.assertIn("if (activeView.name === 'domain' && activeView.domain)", html)

    def test_render_form_refresh_error_banner_is_present(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())  # noqa: SLF001
        self.assertIn('refresh-error', html)

    def test_render_form_fetch_uses_abort_controller(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())  # noqa: SLF001
        self.assertIn('new AbortController()', html)
        self.assertIn('domainSectionsAbortController', html)

    def test_render_form_fetch_ignores_stale_response(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())  # noqa: SLF001
        self.assertIn('if (domainSectionsAbortController !== requestController) {', html)
        self.assertIn('if (domainPermutationsAbortController !== requestController) {', html)

    def test_render_form_gohome_does_not_force_api_navigation_on_failure(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())
        self.assertIn("showRefreshError('Failed to load home view. Please try again.');", html)
        self.assertNotIn("window.location.href = 'https://", html)

    def test_render_form_refresh_keeps_domain_view_active(self):
        html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())
        self.assertIn("activeView.name === 'domain'", html)
        self.assertIn('await showDomain(activeView.domain);', html)

    def test_render_form_logoff_uses_auth_logout_route(self):
        with patch.object(home_shared, 'LOGOUT_ENDPOINT', 'https://hello.dev.osint.4n6ir.com/logout'):
            html = home_shared._render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], set())  # noqa: SLF001
        self.assertIn('window.location.assign("https://hello.dev.osint.4n6ir.com/auth?action=logout")', html)


class RenderResultTests(unittest.TestCase):
    def test_render_result_success_submission(self):
        html = home_shared._render_result('Domain saved', success=True, authorization_header='token', operation='submission')  # noqa: SLF001
        self.assertIn('Submission Successful', html)
        self.assertIn('Domain saved', html)
        self.assertIn('#166534', html)

    def test_render_result_failure_submission(self):
        html = home_shared._render_result('Invalid domain', success=False, authorization_header='token', operation='submission')  # noqa: SLF001
        self.assertIn('Submission Failed', html)
        self.assertIn('Invalid domain', html)
        self.assertIn('#b42318', html)

    def test_render_result_success_deletion(self):
        html = home_shared._render_result('example.com', success=True, authorization_header='token', operation='deletion')  # noqa: SLF001
        self.assertIn('Deletion Successful', html)

    def test_render_result_failure_deletion(self):
        html = home_shared._render_result('Error', success=False, authorization_header='token', operation='deletion')  # noqa: SLF001
        self.assertIn('Deletion Failed', html)

    def test_render_result_html_escaping(self):
        html = home_shared._render_result('<script>alert("xss")</script>', success=True, authorization_header='token')  # noqa: SLF001
        self.assertIn('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;', html)

    def test_render_result_success_submission_hides_refresh_button(self):
        html = home_shared._render_result('Domain saved', success=True, authorization_header='token')  # noqa: SLF001
        self.assertNotIn('<button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>', html)

    def test_render_result_gohome_does_not_force_api_navigation_on_failure(self):
        html = home_shared._render_result('Invalid domain', success=False, authorization_header='token')  # noqa: SLF001
        self.assertIn("console.error('Failed to load home view.'", html)
        self.assertIn('function showRefreshError(message) {', html)
        self.assertIn("showRefreshError('Failed to load home view. Please try again.');", html)
        self.assertIn("const authHeader = \"token\" || '';", html)
        self.assertIn("headers: authHeader ? { 'Authorization': authHeader } : {}", html)
        self.assertIn("credentials: 'include'", html)
        self.assertIn("cache: 'no-store'", html)
        self.assertIn('if (!response.ok || response.redirected) {', html)
        self.assertNotIn("window.location.href = 'https://", html)

    def test_render_result_logoff_uses_auth_logout_route(self):
        with patch.object(home_shared, 'LOGOUT_ENDPOINT', 'https://hello.dev.osint.4n6ir.com/logout'):
            html = home_shared._render_result('Invalid domain', success=False, authorization_header='token')  # noqa: SLF001
        self.assertIn('window.location.assign("https://hello.dev.osint.4n6ir.com/auth?action=logout")', html)


class FetchUserIdentityTests(unittest.TestCase):
    def setUp(self):
        os.environ['AWS_REGION'] = 'us-east-1'
        home_shared.IDENTITY_CACHE.clear()

    def test_fetch_user_identity_no_authorization(self):
        identity = home_shared._fetch_user_identity('')  # noqa: SLF001
        self.assertEqual(identity['email'], 'unknown')
        self.assertEqual(identity['region'], 'us-east-1')

    def test_fetch_user_identity_cached_entry(self):
        token = 'Bearer test-token'
        cached_identity = {'email': 'cached@example.com', 'region': 'us-west-2'}
        home_shared.IDENTITY_CACHE['Bearer test-token'] = (time.time(), cached_identity)  # noqa: SLF001

        with patch.object(home_shared, '_normalize_authorization', return_value='Bearer test-token'):
            identity = home_shared._fetch_user_identity(token)  # noqa: SLF001

        self.assertEqual(identity['email'], 'cached@example.com')

    def test_fetch_user_identity_expired_cache(self):
        token = 'Bearer test-token'
        old_time = time.time() - (home_shared.IDENTITY_CACHE_TTL_SECONDS + 10)
        home_shared.IDENTITY_CACHE['Bearer test-token'] = (old_time, {'email': 'old@example.com'})  # noqa: SLF001

        with patch.object(home_shared, '_normalize_authorization', return_value='Bearer test-token'), \
                patch.object(home_shared, '_decode_jwt_payload', return_value={}):
            identity = home_shared._fetch_user_identity(token)  # noqa: SLF001

        self.assertEqual(identity['email'], 'unknown')

    def test_fetch_user_identity_http_request_success(self):
        token = 'Bearer test-token'
        normalized_token = 'Bearer test-token'

        mock_response = type('Response', (), {
            'json': lambda self: {'email': 'http@example.com', 'region': 'eu-west-1'},
            'ok': True,
        })()

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        with patch.object(home_shared, '_normalize_authorization', return_value=normalized_token), \
            patch.object(home_shared, 'HTTP_SESSION', mock_session):
            home_shared.USER_INFO_ENDPOINT = 'https://userinfo'
            identity = home_shared._fetch_user_identity(token)  # noqa: SLF001

        self.assertEqual(identity['email'], 'http@example.com')
        self.assertEqual(identity['region'], 'eu-west-1')

    def test_fetch_user_identity_http_request_failure_falls_back_to_jwt(self):
        import requests

        token = 'Bearer test-token'
        normalized_token = 'Bearer test-token'

        mock_session = Mock()
        mock_session.get.side_effect = requests.RequestException('Network error')

        with patch.object(home_shared, '_normalize_authorization', return_value=normalized_token), \
            patch.object(home_shared, 'HTTP_SESSION', mock_session), \
                patch.object(home_shared, '_decode_jwt_payload', return_value={'region': 'ap-south-1'}):
            home_shared.USER_INFO_ENDPOINT = 'https://userinfo'
            identity = home_shared._fetch_user_identity(token)  # noqa: SLF001

        self.assertEqual(identity['email'], 'unknown')
        self.assertEqual(identity['region'], 'ap-south-1')


class TableNameResolutionTests(unittest.TestCase):
    def test_table_name_from_env_arn_format(self):
        result = home_shared._table_name_from_env('arn:aws:dynamodb:us-east-1:123456789012:table/my-table')  # noqa: SLF001
        self.assertEqual(result, 'my-table')

    def test_table_name_from_env_plain_name(self):
        result = home_shared._table_name_from_env('my-table')  # noqa: SLF001
        self.assertEqual(result, 'my-table')

    def test_table_name_from_env_empty_string(self):
        result = home_shared._table_name_from_env('')  # noqa: SLF001
        self.assertEqual(result, '')

    def test_table_name_from_env_non_string(self):
        result = home_shared._table_name_from_env(None)  # noqa: SLF001
        self.assertEqual(result, '')
        result = home_shared._table_name_from_env(123)  # noqa: SLF001
        self.assertEqual(result, '')

    def test_resolve_table_identifiers_single_env_key(self):
        with patch.dict(os.environ, {'TABLE_NAME': 'my-table'}):
            result = home_shared._resolve_table_identifiers('TABLE_NAME')  # noqa: SLF001
        self.assertIn('my-table', result)

    def test_resolve_table_identifiers_multiple_env_keys(self):
        with patch.dict(os.environ, {'TABLE1': 'table-one', 'TABLE2': 'table-two'}):
            result = home_shared._resolve_table_identifiers('TABLE1', 'TABLE2')  # noqa: SLF001
        self.assertIn('table-one', result)
        self.assertIn('table-two', result)

    def test_resolve_table_identifiers_nonexistent_env_key(self):
        result = home_shared._resolve_table_identifiers('NONEXISTENT_KEY')  # noqa: SLF001
        self.assertEqual(result, [])


class SanitizationTests(unittest.TestCase):
    def test_sanitize_event_for_logging_removes_authorization(self):
        event = {'authorization': 'Bearer secret-token', 'body': 'data'}
        sanitized = home_shared._sanitize_event_for_logging(event)  # noqa: SLF001
        self.assertEqual(sanitized['authorization'], '***')
        self.assertEqual(sanitized['body'], 'data')

    def test_sanitize_event_for_logging_removes_authorization_header(self):
        event = {'headers': {'Authorization': 'Bearer secret', 'Content-Type': 'application/json'}}
        sanitized = home_shared._sanitize_event_for_logging(event)  # noqa: SLF001
        self.assertEqual(sanitized['headers']['Authorization'], '***')
        self.assertEqual(sanitized['headers']['Content-Type'], 'application/json')

    def test_sanitize_event_for_logging_non_dict_ignored(self):
        result = home_shared._sanitize_event_for_logging('not-a-dict')  # noqa: SLF001
        self.assertEqual(result, 'not-a-dict')


class DomainSectionsTests(unittest.TestCase):
    def test_invalid_domain_returns_empty_sections(self):
        self.assertEqual(GET_DOMAIN_SECTIONS('invalid-domain'), {})  # noqa: SLF001

    def test_valid_domain_returns_empty_structured_sections(self):
        sections = GET_DOMAIN_SECTIONS('example.com')  # noqa: SLF001
        self.assertIn('suspect', sections)
        self.assertIn('newRegistrations', sections)
        self.assertIn('expiredRegistrations', sections)


class PermutationAndPossibilityTests(unittest.TestCase):
    def setUp(self):
        os.environ['WATCHLIST_TABLE'] = 'watchlist-table'
        os.environ['DOMAINS_TABLE'] = 'domains-table'

    def test_get_domain_permutations_returns_sorted_unique_values(self):
        response = {
            'Item': {
                'permutations': [
                    {'permutation': 'B.example.com'},
                    {'permutation': 'legacy1'},
                    {'permutation': 'a.example.com'},
                    'A.example.com',
                    'legacy2',
                    None,
                ],
                'perm': {'L': [{'S': 'c.example.com'}, {'S': 'a.example.com'}, {'S': 'legacy3'}]},
            }
        }

        table = Mock()
        table.get_item.return_value = response

        with patch.object(home_shared, '_get_env_table', return_value=table):
            values = home_shared._get_domain_permutations('example.com', 'user@example.com')  # noqa: SLF001

        self.assertEqual(values, ['a', 'b', 'c', 'legacy1', 'legacy2', 'legacy3'])

    def test_get_domain_permutations_invalid_domain_returns_empty(self):
        self.assertEqual(home_shared._get_domain_permutations('invalid', 'user@example.com'), [])  # noqa: SLF001

    def test_get_permutation_count_prefers_count_field(self):
        table = Mock()
        table.get_item.return_value = {'Item': {'count': '7'}}

        with patch.object(home_shared, '_get_env_table', return_value=table):
            count = home_shared._get_permutation_count('example.com', 'user@example.com')  # noqa: SLF001

        self.assertEqual(count, 7)

    def test_get_permutation_count_falls_back_to_materialized_values(self):
        table = Mock()
        table.get_item.return_value = {
            'Item': {
                'permutations': [
                    {'permutation': 'one.example.com'},
                    {'permutation': 'two.example.com'},
                ]
            }
        }

        with patch.object(home_shared, '_get_env_table', return_value=table):
            count = home_shared._get_permutation_count('example.com', 'user@example.com')  # noqa: SLF001

        self.assertEqual(count, 2)

if __name__ == '__main__':
    unittest.main()