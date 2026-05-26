# pyright: reportPrivateUsage=none, reportUnusedVariable=none
# pylint: disable=protected-access,unused-variable

import json
import os
import unittest
from decimal import Decimal
from unittest.mock import patch

# pyright: reportPrivateUsage=none, reportUnusedVariable=none, reportUnusedParameter=none


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')

from home import home


class HomeHandlerTests(unittest.TestCase):
    def setUp(self):
        os.environ['WATCHLIST_TABLE'] = 'watchlist'
        os.environ['DOMAINS_TABLE'] = 'domains'
        os.environ['TLD_TABLE'] = 'tld'
        os.environ['USERS_TABLE'] = 'users'
        os.environ['SUBSCRIPTION_TABLE'] = 'subscription'
        home.IDENTITY_CACHE.clear()
        home.TABLE_CACHE.clear()

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

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com', 'region': 'use1'}) as fetch_identity, \
                patch.object(home, '_get_env_table', return_value=object()), \
                patch.object(home, '_list_watchlist_domains', return_value=['example.com']), \
                patch.object(home, '_get_matched_slds', return_value={'example'}):
            response = home.handle_request(event, None)

        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['headers']['Content-Type'], 'text/html; charset=utf-8')
        self.assertIn('Gone Fishing!', response['body'])
        self.assertIn('example.com', response['body'])
        fetch_identity.assert_called_once_with('test-token')

    def test_get_request_renders_active_domains_monitor_subscription(self):
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

        class WatchlistTable:
            def query(self, **_kwargs):
                return {'Items': [{'domain': 'example.com'}]}

        class UsersTable:
            def query(self, **_kwargs):
                return {'Items': []}

        class SubscriptionTable:
            def get_item(self, **_kwargs):
                return {
                    'Item': {
                        'pk': 'OSINT#',
                        'sk': 'OSINT#DM#user@example.com#',
                        'email': 'user@example.com',
                        'status': 'paid',
                        'license': 'Pro',
                        'ttl': 1803135900,
                    }
                }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com', 'region': 'use1'}), \
                patch.object(home, '_get_env_table', side_effect=[WatchlistTable(), UsersTable(), SubscriptionTable()]), \
                patch.object(home, '_get_matched_slds', return_value={'example'}):
            response = home.handle_request(event, None)

        self.assertEqual(response['statusCode'], 200)
        self.assertIn('Domains Monitor Subscription', response['body'])
        self.assertIn('✓ ACTIVE', response['body'])

    def test_get_request_renders_active_domains_monitor_subscription_with_decimal_ttl(self):
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

        class WatchlistTable:
            def query(self, **_kwargs):
                return {'Items': [{'domain': 'example.com'}]}

        class UsersTable:
            def query(self, **_kwargs):
                return {'Items': []}

        class SubscriptionTable:
            def get_item(self, **_kwargs):
                return {
                    'Item': {
                        'pk': 'OSINT#',
                        'sk': 'OSINT#DM#user@example.com#',
                        'email': 'user@example.com',
                        'status': 'paid',
                        'license': 'Pro',
                        'ttl': Decimal('1803135900'),
                    }
                }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com', 'region': 'use1'}), \
                patch.object(home, '_get_env_table', side_effect=[WatchlistTable(), UsersTable(), SubscriptionTable()]), \
                patch.object(home, '_get_matched_slds', return_value={'example'}):
            response = home.handle_request(event, None)

        self.assertEqual(response['statusCode'], 200)
        self.assertIn('✓ ACTIVE', response['body'])
        self.assertIn('Domains Monitor', response['body'])

    def test_get_request_renders_active_domains_monitor_subscription_when_item_uses_domains_monitor_email(self):
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

        class WatchlistTable:
            def query(self, **_kwargs):
                return {'Items': [{'domain': 'example.com'}]}

        class UsersTable:
            def query(self, **_kwargs):
                return {'Items': []}

        class SubscriptionTable:
            def get_item(self, **_kwargs):
                return {
                    'Item': {
                        'pk': 'OSINT#',
                        'sk': 'OSINT#DM#user@example.com#',
                        'domains_monitor_email': 'formyorders@mac.com',
                        'cognito_email': 'user@example.com',
                        'status': 'paid',
                        'license': 'Pro',
                        'ttl': 1803135900,
                    }
                }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com', 'region': 'use1'}), \
                patch.object(home, '_get_env_table', side_effect=[WatchlistTable(), UsersTable(), SubscriptionTable()]), \
                patch.object(home, '_get_matched_slds', return_value={'example'}):
            response = home.handle_request(event, None)

        self.assertEqual(response['statusCode'], 200)
        self.assertIn('✓ ACTIVE', response['body'])
        self.assertIn('<strong>Email:</strong> formyorders@mac.com', response['body'])

    def test_post_get_domain_sections_success(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'GetDomainSections', 'entry': 'example.com'}),
        }

        expected_sections = {'suspect': {'openSourceIntelligence': [], 'domainsMonitorSubscription': []}}

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
            patch.object(home, '_get_env_table', return_value=object()), \
            patch.object(home, '_get_domains_monitor_subscription', return_value={'email': 'user@example.com'}), \
            patch.object(home, '_get_domain_sections', return_value=expected_sections), \
            patch.object(home, '_get_permutation_count', return_value=7):
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['headers']['Content-Type'], 'application/json; charset=utf-8')
        self.assertEqual(payload['sections'], expected_sections)
        self.assertEqual(payload['permutations'], 7)

    def test_post_get_domain_permutations_returns_states(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'GetDomainPermutations', 'entry': 'example.com'}),
        }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
            patch.object(home, '_get_domain_permutation_entries', return_value=[
                {'permutation': 'examp1e', 'enabled': 'ON', 'unique_domains': 12, 'unique_sources': 4},
                {'permutation': 'exampl3', 'enabled': 'OFF', 'unique_domains': 3, 'unique_sources': 2},
            ]):
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(payload['permutations'], ['examp1e'])
        self.assertEqual(payload['permutationStates'], [
            {'permutation': 'examp1e', 'enabled': 'ON', 'unique_domains': 12, 'unique_sources': 4},
            {'permutation': 'exampl3', 'enabled': 'OFF', 'unique_domains': 3, 'unique_sources': 2},
        ])

    def test_get_domain_permutation_entries_uses_watchlist_metrics(self):
        class WatchlistTable:
            def get_item(self, **_kwargs):
                return {
                    'Item': {
                        'permutations': [
                            {'permutation': 'lukah', 'enabled': 'ON', 'unique_domains': 2, 'unique_sources': 2},
                            {'permutation': 'lukac', 'enabled': 'ON', 'unique_domains': 1, 'unique_sources': 1},
                            {'permutation': 'foo', 'enabled': 'OFF', 'unique_domains': 0, 'unique_sources': 0},
                        ]
                    }
                }

        with patch.object(home, '_get_env_table', return_value=WatchlistTable()):
            entries = home._get_domain_permutation_entries('example.com', 'user@example.com')

        by_term = {entry['permutation']: entry for entry in entries}
        self.assertEqual(by_term['lukah']['unique_domains'], 2)
        self.assertEqual(by_term['lukah']['unique_sources'], 2)
        self.assertEqual(by_term['lukac']['unique_domains'], 1)
        self.assertEqual(by_term['lukac']['unique_sources'], 1)
        self.assertEqual(by_term['foo']['unique_domains'], 0)
        self.assertEqual(by_term['foo']['unique_sources'], 0)

    def test_post_toggle_domain_permutation_success(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({
                'action': 'ToggleDomainPermutation',
                'entry': 'example.com',
                'permutation': 'exampl3',
                'enabled': 'OFF',
            }),
        }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
            patch.object(home, '_set_domain_permutation_enabled', return_value=(True, 'Permutation updated.')) as toggle:
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(payload, {'ok': True, 'message': 'Permutation updated.'})
        toggle.assert_called_once_with('example.com', 'user@example.com', 'exampl3', 'OFF')

    def test_post_toggle_domain_permutation_failure(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({
                'action': 'ToggleDomainPermutation',
                'entry': 'example.com',
                'permutation': 'exampl3',
                'enabled': 'OFF',
            }),
        }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
            patch.object(home, '_set_domain_permutation_enabled', return_value=(False, 'Permutation was not found for this domain.')):
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 400)
        self.assertEqual(payload, {'ok': False, 'message': 'Permutation was not found for this domain.'})

    def test_post_get_domain_sections_without_subscription_hides_domains_monitor_views(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'GetDomainSections', 'entry': 'example.com'}),
        }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
            patch.object(home, '_get_env_table', return_value=object()), \
            patch.object(home, '_get_domains_monitor_subscription', return_value={}), \
            patch.object(home, '_get_domain_sections', return_value={
                'suspect': {
                    'openSourceIntelligence': ['osint.example.com'],
                    'domainsMonitorSubscription': ['should-hide.example.com'],
                },
                'newRegistrations': {'daily': ['new.example.com'], 'weekly': [], 'monthly': []},
                'expiredRegistrations': {'daily': ['old.example.com'], 'weekly': [], 'monthly': []},
            }), \
            patch.object(home, '_get_permutation_count', return_value=7):
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(payload['permutations'], 7)
        self.assertTrue(payload['sections'].get('_noDomainsMonitor'))
        self.assertEqual(payload['sections']['suspect']['openSourceIntelligence'], ['osint.example.com'])
        self.assertEqual(payload['sections']['suspect']['domainsMonitorSubscription'], [])
        self.assertEqual(payload['sections']['newRegistrations'], {'daily': [], 'weekly': [], 'monthly': []})
        self.assertEqual(payload['sections']['expiredRegistrations'], {'daily': [], 'weekly': [], 'monthly': []})

    def test_post_put_item_failure_renders_failure_message(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'PutItem', 'entry': 'bad'}),
        }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home, '_process_submission', return_value=('bad', False, 'Invalid domain')), \
                patch.object(home, '_render_result', return_value='<html>fail</html>') as render_result:
            response = home.handle_request(event, None)

        self.assertEqual(response['body'], '<html>fail</html>')
        render_result.assert_called_once_with('bad\n\nInvalid domain', False, 'token', 'submission')

    def test_post_delete_item_success_renders_deletion_result(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'DeleteItem', 'entry': 'example.com'}),
        }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home, '_process_submission', return_value=('example.com', True, 'deleted')), \
                patch.object(home, '_render_result', return_value='<html>deleted</html>') as render_result:
            response = home.handle_request(event, None)

        self.assertEqual(response['body'], '<html>deleted</html>')
        render_result.assert_called_once_with('example.com', True, 'token', 'deletion')

    def test_post_delete_item_failure_renders_failure_message(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'DeleteItem', 'entry': 'example.com'}),
        }

        with patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home, '_process_submission', return_value=('example.com', False, 'Nothing to delete.')), \
                patch.object(home, '_render_result', return_value='<html>delete-fail</html>') as render_result:
            response = home.handle_request(event, None)

        self.assertEqual(response['body'], '<html>delete-fail</html>')
        render_result.assert_called_once_with('example.com\n\nNothing to delete.', False, 'token', 'deletion')

    def test_post_verify_domains_monitor_token_success(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'VerifyDomainsMonitorToken', 'apiToken': 'abc123'}),
        }

        account = {
            'email': 'user@example.com',
            'status': 'paid',
            'license': 'Pro',
            'ttl': 1803135900,
        }

        with patch.object(home, '_verify_domains_monitor_account', return_value=(account, '')), \
            patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home, '_get_env_table', return_value=object()) as get_table, \
                patch.object(home, '_put_domains_monitor_subscription') as put_subscription:
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 200)
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['email'], 'user@example.com')
        self.assertEqual(payload['status'], 'paid')
        self.assertEqual(payload['license'], 'Pro')
        self.assertEqual(payload['ttl'], 1803135900)
        get_table.assert_called_once_with('SUBSCRIPTION_TABLE', 'subscription')
        put_subscription.assert_called_once_with(get_table.return_value, account, cognito_email='user@example.com')

    def test_post_verify_domains_monitor_token_mismatch_still_saves_but_not_success(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'VerifyDomainsMonitorToken', 'apiToken': 'abc123'}),
        }

        account = {
            'email': 'domains-monitor@example.test',
            'status': 'paid',
            'license': 'Pro',
            'ttl': 1803135900,
        }

        with patch.object(home, '_verify_domains_monitor_account', return_value=(account, '')), \
            patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home, '_get_env_table', return_value=object()) as get_table, \
                patch.object(home, '_put_domains_monitor_subscription') as put_subscription:
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 200)
        self.assertFalse(payload['ok'])
        self.assertIn('does not match', payload['message'].lower())
        self.assertEqual(payload['email'], 'domains-monitor@example.test')
        self.assertEqual(payload['status'], 'paid')
        self.assertEqual(payload['license'], 'Pro')
        self.assertEqual(payload['ttl'], 1803135900)
        get_table.assert_called_once_with('SUBSCRIPTION_TABLE', 'subscription')
        put_subscription.assert_called_once_with(get_table.return_value, account, cognito_email='user@example.com')

    def test_post_verify_domains_monitor_token_matching_email_returns_success(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'VerifyDomainsMonitorToken', 'apiToken': 'abc123'}),
        }

        account = {
            'email': 'user@example.com',
            'status': 'paid',
            'license': 'Pro',
            'ttl': 1803135900,
        }

        with patch.object(home, '_verify_domains_monitor_account', return_value=(account, '')), \
            patch.object(home, '_fetch_user_identity', return_value={'email': 'user@example.com'}), \
                patch.object(home, '_get_env_table', return_value=object()), \
                patch.object(home, '_put_domains_monitor_subscription'):
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 200)
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['message'], 'Token verified and subscription saved.')

    def test_put_domains_monitor_subscription_stores_email_fields(self):
        domains_monitor_email = 'domains-monitor@example.test'
        cognito_email = 'user@example.test'

        class Table:
            def __init__(self):
                self.items = []

            def put_item(self, Item):
                self.items.append(Item)

        table = Table()
        home._put_domains_monitor_subscription(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            table,
            {
                'email': domains_monitor_email,
                'status': 'paid',
                'license': 'Pro',
                'ttl': 1803135900,
            },
            cognito_email=cognito_email,
        )

        self.assertEqual(len(table.items), 1)
        item = table.items[0]
        self.assertEqual(item['pk'], 'OSINT#')
        self.assertEqual(item['sk'], f'OSINT#DM#{domains_monitor_email}#')
        self.assertEqual(item['domains_monitor_email'], domains_monitor_email)
        self.assertEqual(item['cognito_email'], cognito_email)
        self.assertNotIn('subscription', item)
        self.assertEqual(item['status'], 'paid')
        self.assertEqual(item['license'], 'Pro')
        self.assertEqual(item['ttl'], 1803135900)

    def test_get_domains_monitor_subscription_uses_cognito_key(self):
        class Table:
            def __init__(self):
                self.last_key = None

            def get_item(self, **_kwargs):
                self.last_key = _kwargs.get('Key')
                return {
                    'Item': {
                        'pk': 'OSINT#',
                        'sk': 'OSINT#DM#user@example.com#',
                        'domains_monitor_email': 'domains-monitor@example.test',
                        'cognito_email': 'user@example.com',
                        'status': 'paid',
                        'license': 'Pro',
                        'ttl': 1803135900,
                    }
                }

        table = Table()
        subscription = home._get_domains_monitor_subscription(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            table,
            'user@example.com',
        )

        self.assertEqual(table.last_key, {'pk': 'OSINT#', 'sk': 'OSINT#DM#user@example.com#'})
        self.assertEqual(subscription.get('email'), 'domains-monitor@example.test')
        self.assertEqual(subscription.get('cognito_email'), 'user@example.com')
        self.assertEqual(subscription.get('status'), 'paid')

    def test_get_domains_monitor_subscription_returns_item_even_when_expired(self):
        class Table:
            def get_item(self, **_kwargs):
                return {
                    'Item': {
                        'pk': 'OSINT#',
                        'sk': 'OSINT#DM#user@example.com#',
                        'domains_monitor_email': 'formyorders@mac.com',
                        'cognito_email': 'user@example.com',
                        'status': 'paid',
                        'license': 'Pro',
                        'ttl': 1,
                    }
                }

        subscription = home._get_domains_monitor_subscription(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            Table(),
            'user@example.com',
        )

        self.assertEqual(subscription.get('email'), 'formyorders@mac.com')
        self.assertEqual(subscription.get('cognito_email'), 'user@example.com')
        self.assertEqual(subscription.get('status'), 'paid')

    def test_post_verify_domains_monitor_token_validation_error(self):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'Authorization': 'token'},
            'body': json.dumps({'action': 'VerifyDomainsMonitorToken', 'apiToken': ''}),
        }

        with patch.object(home, '_verify_domains_monitor_account', return_value=({}, 'API token is required.')):
            response = home.handle_request(event, None)

        payload = json.loads(response['body'])
        self.assertEqual(response['statusCode'], 400)
        self.assertFalse(payload['ok'])
        self.assertIn('required', payload['message'].lower())


class WatchlistTests(unittest.TestCase):
    def test_list_watchlist_domains_uses_osint_key_pattern(self):
        class Table:
            def __init__(self):
                self.last_kwargs = None

            def query(self, **_kwargs):
                self.last_kwargs = _kwargs
                return {
                    'Items': [
                        {'domain': 'example.com'},
                    ]
                }

        table = Table()
        domains = home.list_watchlist_domains(table, 'user@example.com')
        self.assertEqual(domains, ['example.com'])
        self.assertIn('KeyConditionExpression', table.last_kwargs)
        self.assertEqual(table.last_kwargs.get('ProjectionExpression'), '#domain')
        self.assertEqual(table.last_kwargs.get('ExpressionAttributeNames'), {'#domain': 'domain'})

    def test_process_submission_unknown_email(self):
        domain, success, message = home.process_submission('example.com', 'unknown', 'PutItem')
        self.assertFalse(success)
        self.assertEqual(domain, 'example.com')
        self.assertIn('identity', message.lower())

    def test_ensure_user_record_puts_default_when_missing(self):
        class UsersTable:
            def __init__(self):
                self.queries = []
                self.puts = []

            def query(self, **kwargs):
                self.queries.append(kwargs)
                return {'Items': []}

            def put_item(self, Item):
                self.puts.append(Item)

        table = UsersTable()
        home.ensure_user_record(table, 'user@example.com')  # pyright: ignore[reportPrivateUsage]

        self.assertEqual(len(table.queries), 1)
        self.assertEqual(len(table.puts), 1)
        self.assertEqual(table.puts[0]['pk'], 'OSINT#')
        self.assertEqual(table.puts[0]['sk'], 'OSINT#user@example.com#')
        self.assertEqual(table.puts[0]['email'], 'user@example.com')
        self.assertEqual(table.puts[0]['sponsor'], 'Basic')
        self.assertEqual(table.puts[0]['monitors'], 1)
        self.assertEqual(table.puts[0]['threshold'], 100)

    def test_ensure_user_record_skips_put_when_exists(self):
        class UsersTable:
            def __init__(self):
                self.put_calls = 0

            def query(self, **_kwargs):
                return {'Items': [{'pk': 'OSINT#', 'sk': 'OSINT#user@example.com#'}]}

            def put_item(self, Item):
                _ = Item
                self.put_calls += 1

        table = UsersTable()
        home.ensure_user_record(table, 'user@example.com')  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(table.put_calls, 0)

    def test_put_watchlist_domain_uses_expected_schema(self):
        class WatchlistTable:
            def __init__(self):
                self.item = None

            def put_item(self, Item):
                self.item = Item

        table = WatchlistTable()
        home.put_watchlist_domain(table, 'user@example.com', 'example.com')  # pyright: ignore[reportPrivateUsage]

        self.assertEqual(table.item['pk'], 'OSINT#')
        self.assertEqual(table.item['sk'], 'OSINT#user@example.com#example.com#')
        self.assertEqual(table.item['domain'], 'example.com')
        self.assertEqual(table.item['email'], 'user@example.com')
        self.assertEqual(table.item['sld'], 'example')
        self.assertEqual(table.item['tld'], 'com')
        self.assertIn('count', table.item)
        self.assertIn('permutations', table.item)
        self.assertEqual(table.item['count'], len(table.item['permutations']))
        if table.item['permutations']:
            first = table.item['permutations'][0]
            self.assertIn('permutation', first)
            self.assertEqual(first.get('enabled'), 'ON')
            self.assertNotIn('.', first.get('permutation', ''))

    def test_process_submission_put_item_ensures_user_before_watchlist_put(self):
        call_order = []

        with patch.object(home, '_get_env_table', side_effect=[object(), object(), object()]), \
                patch.object(home, '_tld_exists', return_value=True), \
            patch.object(home, '_watchlist_domain_exists', return_value=False), \
                patch.object(home, '_ensure_user_record', side_effect=lambda _table, _email: call_order.append('ensure')), \
                patch.object(home, '_put_watchlist_domain', side_effect=lambda _table, _email, _domain: call_order.append('put')):
            domain, success, message = home.process_submission('example.com', 'user@example.com', 'PutItem')

        self.assertTrue(success)
        self.assertEqual(domain, 'example.com')
        self.assertEqual(message, 'Saved')
        self.assertEqual(call_order, ['ensure', 'put'])

    def test_process_submission_put_item_rejects_duplicate_domain(self):
        with patch.object(home, '_get_env_table', side_effect=[object(), object(), object()]), \
                patch.object(home, '_tld_exists', return_value=True), \
                patch.object(home, '_ensure_user_record') as ensure_user_record, \
                patch.object(home, '_get_user_monitors_count', return_value=1), \
                patch.object(home, '_get_watchlist_domain_count', return_value=1), \
                patch.object(home, '_watchlist_domain_exists', return_value=True), \
                patch.object(home, '_put_watchlist_domain') as put_domain:
            domain, success, message = home.process_submission('example.com', 'user@example.com', 'PutItem')

        self.assertFalse(success)
        self.assertEqual(domain, 'example.com')
        self.assertIn('already exists', message.lower())
        # _ensure_user_record is now called early as part of the flow
        ensure_user_record.assert_called_once()
        put_domain.assert_not_called()

    def test_process_submission_delete_item_rejects_missing_domain(self):
        with patch.object(home, '_get_env_table', side_effect=[object(), object(), object()]), \
                patch.object(home, '_tld_exists', return_value=True), \
                patch.object(home, '_watchlist_domain_exists', return_value=False), \
                patch.object(home, '_delete_watchlist_domain') as delete_domain:
            domain, success, message = home.process_submission('example.com', 'user@example.com', 'DeleteItem')

        self.assertFalse(success)
        self.assertEqual(domain, 'example.com')
        self.assertIn('nothing to delete', message.lower())
        delete_domain.assert_not_called()


class RenderFormTests(unittest.TestCase):
    def test_render_form_with_empty_domains(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, [], set())
        self.assertIn('Gone Fishing!', html)
        self.assertIn('user@example.com', html)
        self.assertNotIn('<strong>Region:</strong>', html)
        self.assertIn('<ul><li>Empty!</li></ul>', html)

    def test_render_form_includes_configuration_settings_between_email_and_sponsor(self):
        html = home.render_form(
            'token',
            {'email': 'user@example.com', 'region': 'us-east-1'},
            ['example.com'],
            {'example'},
            {'sponsor': 'Data'},
        )
        email_row = '<strong>Email:</strong> user@example.com'
        config_row = '<strong>Configuration:</strong> <a class="inline-link" href="#" onclick="showSettings(); return false;">Settings</a>'
        sponsor_row = '<strong>Sponsor:</strong> Data'

        self.assertIn(config_row, html)
        self.assertLess(html.index(email_row), html.index(config_row))
        self.assertLess(html.index(config_row), html.index(sponsor_row))

    def test_render_form_hides_configuration_settings_for_basic_and_core(self):
        basic_html = home.render_form(
            'token',
            {'email': 'user@example.com', 'region': 'us-east-1'},
            ['example.com'],
            {'example'},
            {'sponsor': 'Basic'},
        )
        core_html = home.render_form(
            'token',
            {'email': 'user@example.com', 'region': 'us-east-1'},
            ['example.com'],
            {'example'},
            {'sponsor': 'Core'},
        )
        config_row = '<strong>Configuration:</strong> <a class="inline-link" href="#" onclick="showSettings(); return false;">Settings</a>'

        self.assertNotIn(config_row, basic_html)
        self.assertNotIn(config_row, core_html)

    def test_render_form_includes_cleaned_up_configuration_copy(self):
        html = home.render_form(
            'token',
            {'email': 'user@example.com', 'region': 'us-east-1'},
            ['example.com'],
            {'example'},
            {'sponsor': 'Data'},
        )

        self.assertIn('Verify your API token to save the subscription record.', html)
        self.assertIn('<h1>Configuration</h1>', html)
        self.assertIn('<strong>Saved Subscription</strong><br>', html)
        self.assertIn('const safeAccountExpiry = escapeHtml(formatSubscriptionExpiry(account?.ttl));', html)
        self.assertIn('<strong>Expires:</strong>', html)

    def test_render_form_with_matched_slds_highlights(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com', 'test.com'], {'example'})
        self.assertIn('matched-domain', html)

    def test_render_form_includes_refresh_button(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('<button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>', html)

    def test_render_form_toolbar_button_order_help_refresh_logoff(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        help_index = html.index('<button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>')
        refresh_index = html.index('<button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>')
        logoff_index = html.index('<button class="logoff-button" type="button" title="Cognito Log Off" onclick="logOff()">X</button>')
        self.assertTrue(help_index < refresh_index < logoff_index)

    def test_render_form_includes_refresh_current_view_logic(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('async function refreshCurrentView(event) {', html)
        self.assertIn('event.preventDefault();', html)
        self.assertIn('event.stopPropagation();', html)
        self.assertIn('if (refreshInFlight) {', html)
        self.assertIn('refreshInFlight = true;', html)
        self.assertIn('setRefreshButtonsDisabled(true);', html)
        self.assertIn('refreshInFlight = false;', html)
        self.assertIn('setRefreshButtonsDisabled(false);', html)
        self.assertIn("if (activeView.name === 'domain' && activeView.domain) {", html)
        self.assertIn('domainDetailsCache.delete(activeView.domain);', html)
        self.assertIn('domainPermutationsCache.delete(activeView.domain);', html)
        self.assertIn("if (activeView.name === 'permutations' && activeView.domain) {", html)
        self.assertIn('await showPermutations(activeView.domain);', html)
        self.assertIn('await goHome();', html)

    def test_render_form_hides_domains_and_new_expired_when_no_subscription(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('const hasDomainsMonitor = !Boolean(safeSections?._noDomainsMonitor);', html)
        self.assertIn("(hasDomainsMonitor", html)
        self.assertIn("renderCollapsibleList('Domains Monitor Subscription'", html)
        self.assertIn("'<h3>New Domains</h3>'", html)
        self.assertIn("'<h3>Expired Domains</h3>'", html)

    def test_render_form_fetch_uses_abort_controller(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('domainSectionsAbortController = new AbortController();', html)
        self.assertIn('domainPermutationsAbortController = new AbortController();', html)
        self.assertIn('signal: requestController.signal,', html)
        self.assertIn("if (err && err.name === 'AbortError') {", html)

    def test_render_form_fetch_ignores_stale_response(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('if (domainSectionsAbortController !== requestController) {', html)
        self.assertIn('if (domainPermutationsAbortController !== requestController) {', html)

    def test_render_form_includes_permutation_toggle_controls(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('.permutation-action.enable', html)
        self.assertIn('.permutation-action.disable', html)
        self.assertIn('.permutation-count', html)
        self.assertIn('const sortedRows = [...rows].sort((left, right) => {', html)
        self.assertIn('return rightDomains - leftDomains;', html)
        self.assertIn('return leftPermutation.localeCompare(rightPermutation);', html)
        self.assertIn('Domains: ', html)
        self.assertIn('Sources: ', html)
        self.assertIn("action: 'ToggleDomainPermutation'", html)
        self.assertIn('data-permutation-toggle="true"', html)

    def test_render_form_includes_webui_styles_and_logo(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('<style>', html)
        self.assertIn('background: #f4f7fb;', html)
        self.assertIn('OSINT Logo', html)

    def test_render_form_normalizes_api_endpoint_to_home_path(self):
        with patch.object(home, 'API_ENDPOINT', 'https://api.test'):
            html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('fetch("https://api.test/home"', html)

    def test_render_form_uses_configured_api_endpoint_path(self):
        with patch.object(home, 'API_ENDPOINT', 'https://api.test/home'):
            html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('fetch("https://api.test/home"', html)

    def test_render_form_includes_user_extra_fields(self):
        html = home.render_form(
            'token',
            {'email': 'user@example.com', 'region': 'us-east-1'},
            ['example.com'],
            {'example'},
            {'sponsor': 'Gold', 'monitors': '3', 'threshold': '85'},
        )
        sponsor_row = '<strong>Sponsor:</strong> Gold'
        monitors_row = '<strong>Monitors:</strong> 3'
        threshold_row = '<strong>Threshold:</strong> 85'

        self.assertIn(sponsor_row, html)
        self.assertIn(monitors_row, html)
        self.assertIn(threshold_row, html)
        self.assertLess(html.index(sponsor_row), html.index(threshold_row))
        self.assertLess(html.index(threshold_row), html.index(monitors_row))

    def test_render_form_threshold_field(self):
        html = home.render_form(
            'token',
            {'email': 'user@example.com', 'region': 'us-east-1'},
            ['example.com'],
            {'example'},
            {'sponsor': 'Basic', 'monitors': '1', 'threshold': '100'},
        )

        self.assertIn('<strong>Threshold:</strong> 100', html)
        self.assertNotIn('<strong>Visibility:</strong>', html)


class UserExtraFieldsTests(unittest.TestCase):
    def test_get_user_extra_fields_prefers_ostin_sk(self):
        class UsersTable:
            def __init__(self):
                self.queries = []

            def query(self, **kwargs):
                self.queries.append(kwargs)
                return {
                    'Items': [{
                        'pk': 'OSINT#',
                        'sk': 'OSTIN#user@example.com#',
                        'email': 'user@example.com',
                        'sponsor': 'Premium',
                        'monitors': 5,
                    }]
                }

        table = UsersTable()
        fields = home.get_user_extra_fields(table, 'user@example.com')

        self.assertEqual(fields['sponsor'], 'Premium')
        self.assertEqual(fields['monitors'], '5')
        self.assertNotIn('pk', fields)
        self.assertNotIn('sk', fields)
        self.assertNotIn('email', fields)
        self.assertEqual(len(table.queries), 1)

    def test_get_user_extra_fields_stringifies_decimal_threshold(self):
        class UsersTable:
            def query(self, **_kwargs):
                return {
                    'Items': [{
                        'pk': 'OSINT#',
                        'sk': 'OSINT#user@example.com#',
                        'email': 'user@example.com',
                        'threshold': Decimal('85'),
                    }]
                }

        fields = home.get_user_extra_fields(UsersTable(), 'user@example.com')
        self.assertEqual(fields['threshold'], '85')

    def test_get_user_extra_fields_falls_back_to_osint_sk(self):
        class UsersTable:
            def __init__(self):
                self.calls = 0

            def query(self, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    return {'Items': []}
                return {
                    'Items': [{
                        'pk': 'OSINT#',
                        'sk': 'OSINT#user@example.com#',
                        'email': 'user@example.com',
                        'threshold': 100,
                    }]
                }

        fields = home.get_user_extra_fields(UsersTable(), 'user@example.com')
        self.assertEqual(fields['threshold'], '100')

    def test_get_user_extra_fields_returns_empty_on_table_error(self):
        class UsersTable:
            def query(self, **_kwargs):
                raise AttributeError('query not supported')

        fields = home.get_user_extra_fields(UsersTable(), 'user@example.com')
        self.assertEqual(fields, {})

    def test_render_form_logoff_uses_auth_logout_route(self):
        with patch.object(home, 'LOGOUT_ENDPOINT', 'https://hello.dev.osint.4n6ir.com/logout'):
            html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('window.location.assign("https://hello.dev.osint.4n6ir.com/auth?action=logout")', html)


class OsintAttributionTests(unittest.TestCase):
    def test_extract_osint_source_urls_supports_mixed_separators(self):
        urls = home._extract_osint_source_urls(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            {'S': 'https://example.test/list-a|https://example.test/list-b;https://example.test/list-c'}
        )

        self.assertEqual(
            urls,
            [
                'https://example.test/list-a',
                'https://example.test/list-b',
                'https://example.test/list-c',
            ],
        )

    def test_partition_suspect_domains_merges_osint_attribution(self):
        suspect = home._partition_suspect_domains(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            [
                {
                    'domain': 'osint.example.com',
                    'attribution': [
                        {'name': 'alpha/list-a', 'url': 'https://github.com/alpha/list-a'},
                    ],
                },
                {
                    'domain': 'osint.example.com',
                    'attribution': [
                        {'name': 'beta/list-b', 'url': 'https://github.com/beta/list-b'},
                    ],
                },
            ],
            [],
        )

        self.assertEqual(
            suspect['openSourceIntelligence'],
            [
                {
                    'domain': 'osint.example.com',
                    'attribution': [
                        {'name': 'alpha/list-a', 'url': 'https://github.com/alpha/list-a'},
                        {'name': 'beta/list-b', 'url': 'https://github.com/beta/list-b'},
                    ],
                }
            ],
        )

    def test_render_form_includes_osint_attribution_ui(self):
        html = home.render_form(
            'token',
            {'email': 'user@example.com', 'region': 'us-east-1'},
            ['example.com'],
            {'example'},
        )

        self.assertIn('showAttribution: true', html)
        self.assertIn('.attribution-chip {', html)
        self.assertIn('function _renderAttribution(item) {', html)


class RenderResultTests(unittest.TestCase):
    def test_render_result_success_submission(self):
        html = home.render_result('Domain saved', success=True, authorization_header='token', operation='submission')
        self.assertIn('Submission Successful', html)
        self.assertIn('Domain saved', html)
        self.assertIn('#166534', html)

    def test_render_result_failure_submission(self):
        html = home.render_result('Invalid domain', success=False, authorization_header='token', operation='submission')
        self.assertIn('Submission Failed', html)
        self.assertIn('Invalid domain', html)
        self.assertIn('#b42318', html)

    def test_render_result_failure_includes_refresh_button(self):
        html = home.render_result('Invalid domain', success=False, authorization_header='token')
        self.assertIn('<button class="refresh-button" type="button" title="Refresh Data" onclick="refreshCurrentView(event)">↺</button>', html)

    def test_render_result_refresh_stays_on_failure_result_view(self):
        html = home.render_result('Invalid domain', success=False, authorization_header='token')
        self.assertIn('function refreshCurrentView(event) {', html)
        self.assertIn('event.preventDefault();', html)
        self.assertIn('event.stopPropagation();', html)
        self.assertIn('goHome();', html)
        self.assertNotIn('window.location.reload();', html)

    def test_render_result_includes_webui_styles_and_logo(self):
        html = home.render_result('Invalid domain', success=False, authorization_header='token')
        self.assertIn('<style>', html)
        self.assertIn('background: #f4f7fb;', html)
        self.assertIn('OSINT Logo', html)

    def test_render_result_normalizes_api_endpoint_to_home_path(self):
        with patch.object(home, 'API_ENDPOINT', 'https://api.test'):
            html = home.render_result('Invalid domain', success=False, authorization_header='token')
        self.assertIn('fetch("https://api.test/home"', html)

    def test_render_result_logoff_uses_auth_logout_route(self):
        with patch.object(home, 'LOGOUT_ENDPOINT', 'https://hello.dev.osint.4n6ir.com/logout'):
            html = home.render_result('Invalid domain', success=False, authorization_header='token')
        self.assertIn('window.location.assign("https://hello.dev.osint.4n6ir.com/auth?action=logout")', html)

    def test_render_result_success_includes_help_button(self):
        html = home.render_result('Domain saved', success=True, authorization_header='token', operation='submission')
        self.assertIn('<button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>', html)

    def test_render_result_failure_includes_help_button(self):
        html = home.render_result('Invalid domain', success=False, authorization_header='token', operation='submission')
        self.assertIn('<button class="help-button" type="button" title="OSINT Help" onclick="toggleHelp()">?</button>', html)

    def test_render_result_help_includes_easy_dismiss_controls(self):
        html = home.render_result('Invalid domain', success=False, authorization_header='token', operation='submission')
        self.assertIn('onclick="closeHelp()"', html)
        self.assertIn('class="help-modal-overlay"', html)
        self.assertIn('<h2 style="text-align:center">OSINT Help</h2>', html)
        self.assertIn("window.addEventListener('click'", html)
        self.assertNotIn("window.addEventListener('keydown'", html)

    def test_render_form_help_uses_sticky_footer(self):
        html = home.render_form('token', {'email': 'user@example.com', 'region': 'us-east-1'}, ['example.com'], {'example'})
        self.assertIn('.help-modal-overlay {', html)
        self.assertIn('.help-modal-overlay.open {', html)
        self.assertIn('<h2 style="text-align:center">OSINT Help</h2>', html)
        self.assertNotIn('class="help-dismiss"', html)


class CreateHandlerTests(unittest.TestCase):
    def test_create_handler_applies_configured_endpoints(self):
        configured_handler = home.create_handler('api-url', 'logout-url', 'user-info-url')
        captured = {}

        def fake_handle_request(_event, _context):
            captured['endpoints'] = (
                home.API_ENDPOINT,
                home.LOGOUT_ENDPOINT,
                home.USER_INFO_ENDPOINT,
            )
            return {'statusCode': 200, 'body': 'ok', 'headers': {}}

        with patch.object(home, '_handle_request', side_effect=fake_handle_request):
            configured_handler({}, None)

        self.assertEqual(captured['endpoints'], ('api-url', 'logout-url', 'user-info-url'))

    def test_create_handler_restores_endpoints_after_exception(self):
        old_api = home.API_ENDPOINT
        old_logout = home.LOGOUT_ENDPOINT
        old_user_info = home.USER_INFO_ENDPOINT
        configured_handler = home.create_handler('api-url', 'logout-url', 'user-info-url')

        with patch.object(home, '_handle_request', side_effect=RuntimeError('fail')):
            with self.assertRaises(RuntimeError):
                configured_handler({}, None)

        self.assertEqual(home.API_ENDPOINT, old_api)
        self.assertEqual(home.LOGOUT_ENDPOINT, old_logout)
        self.assertEqual(home.USER_INFO_ENDPOINT, old_user_info)


if __name__ == '__main__':
    unittest.main()
