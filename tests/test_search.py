# pyright: reportPrivateUsage=none

import importlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('WATCHLIST_TABLE', 'watchlist-table')
os.environ.setdefault('OSINT_TABLE', 'osint-table')
os.environ.setdefault('MALWARE_TABLE', 'malware-table')
os.environ.setdefault('DAILYREMOVE_TABLE', 'dailyremove-table')
os.environ.setdefault('DAILYUPDATE_TABLE', 'dailyupdate-table')
os.environ.setdefault('WEEKLYREMOVE_TABLE', 'weeklyremove-table')
os.environ.setdefault('WEEKLYUPDATE_TABLE', 'weeklyupdate-table')
os.environ.setdefault('MONTHLYREMOVE_TABLE', 'monthlyremove-table')
os.environ.setdefault('MONTHLYUPDATE_TABLE', 'monthlyupdate-table')
os.environ.setdefault('USERS_TABLE', 'users-table')


class _FakeBatchWriter:
    def __init__(self):
        self.put_items = []
        self.delete_keys = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def put_item(self, Item):
        self.put_items.append(Item)

    def delete_item(self, Key):
        self.delete_keys.append(Key)


class _FakeTable:
    def __init__(self):
        self.writer = _FakeBatchWriter()

    def batch_writer(self):
        return self.writer


class _FakeS3Client:
    def __init__(self, source_path):
        self.source_path = source_path
        self.download_calls = 0
        self.head_calls = 0

    def head_object(self, Bucket, Key):
        del Bucket
        del Key
        self.head_calls += 1
        return {
            'ETag': 'etag-1',
            'ContentLength': os.path.getsize(self.source_path),
        }

    def download_file(self, Bucket, Key, Filename):
        del Bucket
        del Key
        self.download_calls += 1
        shutil.copyfile(self.source_path, Filename)


class SearchLambdaTests(unittest.TestCase):
    def setUp(self):
        self.search_lambda = importlib.import_module('search.search')
        self.search_lambda = importlib.reload(self.search_lambda)
        self.search_lambda.TABLE_CACHE.clear()

    def test_sqlite_connect_downloads_and_reuses_local_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = os.path.join(temp_dir, 'source.sqlite3')
            local_path = os.path.join(temp_dir, 'local.sqlite3')
            meta_path = os.path.join(temp_dir, 'local.sqlite3.meta.json')

            conn = sqlite3.connect(source_path)
            conn.execute('CREATE TABLE example (id INTEGER PRIMARY KEY, value TEXT NOT NULL)')
            conn.execute("INSERT INTO example(value) VALUES ('alpha')")
            conn.commit()
            conn.close()

            fake_s3_client = _FakeS3Client(source_path)

            with patch.object(self.search_lambda, 'S3_CLIENT', fake_s3_client), \
                    patch.object(self.search_lambda, 'SQLITE_BUCKET_NAME', 'sqlite-bucket'), \
                    patch.object(self.search_lambda, 'TARGET_SQLITE_KEY', 'osint.sqlite3'), \
                    patch.object(self.search_lambda, '_sqlite_local_path', return_value=local_path), \
                    patch.object(self.search_lambda, '_sqlite_local_metadata_path', return_value=meta_path):
                first_conn = self.search_lambda._sqlite_connect('osint.sqlite3')
                first_rows = first_conn.execute('SELECT value FROM example').fetchall()
                first_conn.close()

                second_conn = self.search_lambda._sqlite_connect('osint.sqlite3')
                second_rows = second_conn.execute('SELECT value FROM example').fetchall()
                second_conn.close()

            self.assertEqual([row['value'] for row in first_rows], ['alpha'])
            self.assertEqual([row['value'] for row in second_rows], ['alpha'])
            self.assertEqual(fake_s3_client.download_calls, 1)
            self.assertEqual(fake_s3_client.head_calls, 2)
            self.assertTrue(os.path.exists(local_path))
            self.assertTrue(os.path.exists(meta_path))

    def test_threshold_exceeded_turns_permutation_off_and_updates_once(self):
        watchlist_item = {
            'sld': 'alpha',
            'permutations': [
                {'permutation': 'bad', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
            ],
        }

        final_rows = {
            'alpha': [('alpha', 'com', 'https://source/alpha')],
            'bad': [
                ('bad-1', 'com', 'https://source/bad-a'),
                ('bad-2', 'com', 'https://source/bad-b'),
            ],
        }

        with patch.object(self.search_lambda, '_get_watchlist_item', return_value=watchlist_item), \
                patch.object(self.search_lambda, '_get_user_threshold', return_value=1), \
                patch.object(self.search_lambda, '_sqlite_fetch_rows', return_value=final_rows) as sqlite_fetch_rows, \
                patch.object(self.search_lambda, '_update_watchlist_permutations') as update_watchlist, \
            patch.object(self.search_lambda, '_refresh_permutation_counts_from_tables') as refresh_counts, \
                patch.object(self.search_lambda, '_list_table_domains', return_value={}), \
                patch.object(self.search_lambda, '_sync_table', return_value=(1, 0)) as sync_osint:
            self.search_lambda._process_message('alpha.com', 'user@example.com', 'NO', 'YES')

        self.assertEqual(sqlite_fetch_rows.call_count, 2)
        self.assertEqual(sqlite_fetch_rows.call_args_list[0].args, ('osint.sqlite3', 'alpha', {'bad'}))
        self.assertEqual(sqlite_fetch_rows.call_args_list[1].args, ('osint.sqlite3', 'alpha', set()))
        self.assertEqual(update_watchlist.call_count, 1)
        self.assertEqual(refresh_counts.call_count, 1)
        self.assertEqual(
            refresh_counts.call_args.args[3],
            [
                os.environ['OSINT_TABLE'],
                os.environ['MALWARE_TABLE'],
                os.environ['DAILYREMOVE_TABLE'],
                os.environ['DAILYUPDATE_TABLE'],
                os.environ['WEEKLYREMOVE_TABLE'],
                os.environ['WEEKLYUPDATE_TABLE'],
                os.environ['MONTHLYREMOVE_TABLE'],
                os.environ['MONTHLYUPDATE_TABLE'],
            ],
        )

        updated_permutations = update_watchlist.call_args_list[0].args[2]
        self.assertEqual(updated_permutations[0]['permutation'], 'bad')
        self.assertEqual(updated_permutations[0]['enabled'], 'OFF')
        self.assertEqual(updated_permutations[0]['unique_domains'], 0)
        self.assertEqual(updated_permutations[0]['unique_sources'], 0)

        self.assertEqual(sync_osint.call_count, 1)
        synced_results = sync_osint.call_args_list[0].args[2]
        self.assertNotIn('bad-1.com', synced_results)
        self.assertNotIn('bad-2.com', synced_results)

    def test_invalid_sqlite_rows_are_excluded_from_metrics_and_results(self):
        permutations = [
            {'permutation': 'bad', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
        ]
        aggregate_metrics = {}
        rows_by_term = {
            'alpha': [('alpha', 'com', 'https://source/alpha')],
            'bad': [
                ('bad-valid', 'com', 'https://source/bad-1'),
                ('bad-missing-tld', '', 'https://source/bad-2'),
                ('', 'com', 'https://source/bad-3'),
            ],
        }

        with patch.object(self.search_lambda, '_sqlite_fetch_rows', return_value=rows_by_term):
            sqlite_results = self.search_lambda._apply_threshold_and_fetch(
                'osint.sqlite3',
                'alpha',
                permutations,
                threshold=0,
                email='user@example.com',
                domain='alpha.com',
                aggregate_metrics=aggregate_metrics,
            )

        self.assertIn('bad-valid.com', sqlite_results)
        self.assertNotIn('bad-missing-tld.', sqlite_results)
        self.assertNotIn('.com', sqlite_results)
        self.assertEqual(permutations[0]['unique_domains'], 1)
        self.assertEqual(permutations[0]['unique_sources'], 1)
        self.assertEqual(sqlite_results['bad-valid.com']['matched_permutations'], ['bad'])
        self.assertEqual(sqlite_results['bad-valid.com']['sld_found'], 'NO')

    def test_metrics_match_normalized_result_set_sources(self):
        permutations = [
            {'permutation': 'lukah', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
        ]
        aggregate_metrics = {}
        rows_by_term = {
            'lukach': [('lukach', 'io', 'https://source/base')],
            'lukah': [
                ('x-lukah-1', 'com', 'https://source/a'),
                ('x-lukah-1', 'com', 'https://source/b'),
                ('x-lukah-2', 'net', 'https://source/a'),
                ('x-lukah-3', '', 'https://source/invalid'),
            ],
        }

        with patch.object(self.search_lambda, '_sqlite_fetch_rows', return_value=rows_by_term):
            sqlite_results = self.search_lambda._apply_threshold_and_fetch(
                'osint.sqlite3',
                'lukach',
                permutations,
                threshold=0,
                email='user@example.com',
                domain='lukach.io',
                aggregate_metrics=aggregate_metrics,
            )

        self.assertIn('x-lukah-1.com', sqlite_results)
        self.assertEqual(
            sqlite_results['x-lukah-1.com']['sources'],
            ['https://source/a', 'https://source/b'],
        )
        self.assertEqual(sqlite_results['x-lukah-1.com']['matched_permutations'], ['lukah'])
        self.assertEqual(permutations[0]['unique_domains'], 2)
        self.assertEqual(permutations[0]['unique_sources'], 2)

    def test_rows_with_full_domain_in_sld_are_accepted(self):
        permutations = [
            {'permutation': 'lukah', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
        ]
        aggregate_metrics = {}
        rows_by_term = {
            'lukach': [('lukach.io', '', 'https://source/base')],
            'lukah': [
                ('x-lukah-1.com', '', 'https://source/a'),
                ('x-lukah-1.com', '', 'https://source/b'),
            ],
        }

        with patch.object(self.search_lambda, '_sqlite_fetch_rows', return_value=rows_by_term):
            sqlite_results = self.search_lambda._apply_threshold_and_fetch(
                'osint.sqlite3',
                'lukach',
                permutations,
                threshold=0,
                email='user@example.com',
                domain='lukach.io',
                aggregate_metrics=aggregate_metrics,
            )

        self.assertIn('lukach.io', sqlite_results)
        self.assertIn('x-lukah-1.com', sqlite_results)
        self.assertEqual(
            sqlite_results['x-lukah-1.com']['sources'],
            ['https://source/a', 'https://source/b'],
        )
        self.assertEqual(sqlite_results['lukach.io']['sld_found'], 'YES')

    def test_non_osint_file_updates_metrics_when_searched(self):
        permutations = [
            {'permutation': 'lukah', 'enabled': 'ON', 'unique_domains': 2, 'unique_sources': 2},
        ]
        aggregate_metrics = {
            'lukah': {
                'domains': {'x-lukah-1.com', 'x-lukah-2.net'},
                'sources': {'https://source/a', 'https://source/b'},
            }
        }
        rows_by_term = {
            'lukach': [('lukach.io', '', 'https://source/base-non-osint')],
            'lukah': [('x-lukah-3.org', '', 'https://source/c')],
        }

        with patch.object(self.search_lambda, '_sqlite_fetch_rows', return_value=rows_by_term):
            sqlite_results = self.search_lambda._apply_threshold_and_fetch(
                'malware.sqlite3',
                'lukach',
                permutations,
                threshold=0,
                email='user@example.com',
                domain='lukach.io',
                aggregate_metrics=aggregate_metrics,
            )

        self.assertIn('x-lukah-3.org', sqlite_results)
        self.assertEqual(permutations[0]['unique_domains'], 3)
        self.assertEqual(permutations[0]['unique_sources'], 3)

    def test_permutation_attribution_uses_sqlite_query_term(self):
        # 'lukac' is a query term; SQLite (LIKE '%lukac%') returns 'lukach.io'
        # because 'lukac' is a substring.  The matched_permutations on the
        # result must record 'lukac' — the query IS the authority.  Counts
        # reflect exactly what SQLite returned, which may trigger threshold
        # auto-disable if the permutation is too broad.
        permutations = [
            {'permutation': 'lukac', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
            {'permutation': 'lukah', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
        ]
        aggregate_metrics = {}
        rows_by_term = {
            'lukach': [('lukach', 'io', 'https://source/base')],
            'lukac': [
                ('lukach', 'io', 'https://source/base'),
            ],
            'lukah': [
                ('x-lukah-1', 'com', 'https://source/a'),
            ],
        }

        with patch.object(self.search_lambda, '_sqlite_fetch_rows', return_value=rows_by_term):
            results = self.search_lambda._apply_threshold_and_fetch(
                'osint.sqlite3',
                'lukach',
                permutations,
                threshold=0,
                email='user@example.com',
                domain='lukach.io',
                aggregate_metrics=aggregate_metrics,
            )

        by_term = {entry['permutation']: entry for entry in permutations}
        # 'lukac' found 'lukach.io' via SQLite — must be recorded and counted.
        self.assertEqual(by_term['lukac']['unique_domains'], 1)
        self.assertEqual(by_term['lukac']['unique_sources'], 1)
        self.assertIn('lukac', results.get('lukach.io', {}).get('matched_permutations', []))
        # 'lukah' found 'x-lukah-1.com' — also recorded and counted.
        self.assertEqual(by_term['lukah']['unique_domains'], 1)
        self.assertEqual(by_term['lukah']['unique_sources'], 1)

    def test_sync_table_uses_batch_writes(self):
        fake_table = _FakeTable()
        sqlite_results = {
            'new.com': {
                'sld': 'new',
                'tld': 'com',
                'sources': ['https://source/new'],
                'matched_permutations': ['newperm'],
                'sld_found': 'YES',
            },
            'keep.com': {
                'sld': 'keep',
                'tld': 'com',
                'sources': ['https://source/keep'],
                'matched_permutations': ['keepperm'],
                'sld_found': 'NO',
            },
        }
        stored_items = {
            'keep.com': {
                'sk': 'OSINT#user@example.com#alpha.com#keep.com#',
                'sources': ['https://source/keep'],
                'matched_permutations': ['keepperm'],
                'sld_found': 'NO',
            },
            'old.com': {
                'sk': 'OSINT#user@example.com#alpha.com#old.com#',
                'sources': ['https://source/old'],
                'matched_permutations': ['oldperm'],
                'sld_found': 'YES',
            },
        }

        with patch.object(self.search_lambda, '_get_table', return_value=fake_table):
            added, removed = self.search_lambda._sync_table(
                email='user@example.com',
                domain='alpha.com',
                sqlite_results=sqlite_results,
                stored_items=stored_items,
                table_name='osint-table',
            )

        self.assertEqual(added, 1)
        self.assertEqual(removed, 1)
        self.assertEqual(len(fake_table.writer.put_items), 1)
        self.assertEqual(fake_table.writer.put_items[0]['result'], 'new.com')
        self.assertEqual(fake_table.writer.put_items[0]['source'], ['https://source/new'])
        self.assertEqual(fake_table.writer.put_items[0]['permutations'], ['newperm'])
        self.assertEqual(fake_table.writer.put_items[0]['sldfound'], 'YES')
        self.assertIn('ttl', fake_table.writer.put_items[0])
        self.assertEqual(len(fake_table.writer.delete_keys), 1)
        self.assertEqual(
            fake_table.writer.delete_keys[0]['sk'],
            'OSINT#user@example.com#alpha.com#old.com#',
        )

    def test_collect_sqlite_results_merges_multiple_sources_per_domain(self):
        rows_by_term = {
            'alpha': [
                ('shared', 'com', 'https://source/a'),
                ('shared', 'com', 'https://source/b'),
            ],
            'shared': [
                ('shared', 'com', 'https://source/c'),
            ],
        }

        permutations = [
            {'permutation': 'shared', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
        ]

        with patch.object(self.search_lambda, '_sqlite_fetch_rows', return_value=rows_by_term):
            sqlite_results = self.search_lambda._collect_sqlite_results('osint.sqlite3', 'alpha', permutations)

        self.assertIn('shared.com', sqlite_results)
        self.assertEqual(
            sqlite_results['shared.com'],
            {
                'sld': 'shared',
                'tld': 'com',
                'sources': ['https://source/a', 'https://source/b', 'https://source/c'],
                'matched_permutations': ['shared'],
                'sld_found': 'NO',
            },
        )

    def test_sync_table_updates_existing_record_when_new_sources_found(self):
        fake_table = _FakeTable()
        sqlite_results = {
            'keep.com': {
                'sld': 'keep',
                'tld': 'com',
                'sources': ['https://source/keep', 'https://source/new'],
                'matched_permutations': ['keepperm', 'newperm'],
                'sld_found': 'YES',
            },
        }
        stored_items = {
            'keep.com': {
                'sk': 'OSINT#user@example.com#alpha.com#keep.com#',
                'sources': ['https://source/keep'],
                'matched_permutations': ['keepperm'],
                'sld_found': 'NO',
            },
        }

        with patch.object(self.search_lambda, '_get_table', return_value=fake_table):
            added, removed = self.search_lambda._sync_table(
                email='user@example.com',
                domain='alpha.com',
                sqlite_results=sqlite_results,
                stored_items=stored_items,
                table_name='osint-table',
            )

        self.assertEqual(added, 0)
        self.assertEqual(removed, 0)
        self.assertEqual(len(fake_table.writer.put_items), 1)
        self.assertEqual(
            fake_table.writer.put_items[0]['source'],
            ['https://source/keep', 'https://source/new'],
        )
        self.assertEqual(
            fake_table.writer.put_items[0]['permutations'],
            ['keepperm', 'newperm'],
        )
        self.assertEqual(fake_table.writer.put_items[0]['sldfound'], 'YES')

    def test_handler_cleans_up_local_sqlite_copy(self):
        event = {
            'Records': [
                {
                    'messageId': 'msg-1',
                    'body': json.dumps(
                        {
                            'domain': 'alpha.com',
                            'email': 'user@example.com',
                            'subscription': 'NO',
                            'osintsearch': 'YES',
                        }
                    ),
                }
            ]
        }

        with patch.object(self.search_lambda, '_process_message') as process_message, \
                patch.object(self.search_lambda, '_sqlite_cleanup_local_copy') as cleanup_local_copy:
            response = self.search_lambda.handler(event, None)

        process_message.assert_called_once_with('alpha.com', 'user@example.com', 'NO', 'YES')
        cleanup_local_copy.assert_called_once()
        self.assertEqual(response, {'batchItemFailures': []})

    def test_sqlite_target_table_mapping_is_one_to_one(self):
        expected_mapping = {
            'osint.sqlite3': os.environ['OSINT_TABLE'],
            'malware.sqlite3': os.environ['MALWARE_TABLE'],
            'dailyremove.sqlite3': os.environ['DAILYREMOVE_TABLE'],
            'dailyupdate.sqlite3': os.environ['DAILYUPDATE_TABLE'],
            'weeklyremove.sqlite3': os.environ['WEEKLYREMOVE_TABLE'],
            'weeklyupdate.sqlite3': os.environ['WEEKLYUPDATE_TABLE'],
            'monthlyremove.sqlite3': os.environ['MONTHLYREMOVE_TABLE'],
            'monthlyupdate.sqlite3': os.environ['MONTHLYUPDATE_TABLE'],
        }
        self.assertEqual(self.search_lambda.SQLITE_TARGET_TABLE_BY_KEY, expected_mapping)

    def test_subscription_only_refreshes_watchlist_counts_from_all_tables(self):
        watchlist_item = {
            'sld': 'alpha',
            'permutations': [
                {'permutation': 'bad', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
            ],
        }

        with patch.object(self.search_lambda, '_get_watchlist_item', return_value=watchlist_item), \
                patch.object(self.search_lambda, '_collect_sqlite_results', return_value={}) as collect_results, \
                patch.object(self.search_lambda, '_list_table_domains', return_value={}), \
                patch.object(self.search_lambda, '_sync_table', return_value=(0, 0)) as sync_table, \
                patch.object(self.search_lambda, '_refresh_permutation_counts_from_tables') as refresh_counts, \
                patch.object(self.search_lambda, '_update_watchlist_permutations') as update_watchlist, \
                patch.object(self.search_lambda, '_sqlite_delete_one'):
            self.search_lambda._process_message('alpha.com', 'user@example.com', 'YES', 'NO')

        self.assertEqual(collect_results.call_count, 7)
        self.assertEqual(sync_table.call_count, 7)
        self.assertEqual(refresh_counts.call_count, 1)
        self.assertEqual(
            refresh_counts.call_args.args[3],
            [
                os.environ['OSINT_TABLE'],
                os.environ['MALWARE_TABLE'],
                os.environ['DAILYREMOVE_TABLE'],
                os.environ['DAILYUPDATE_TABLE'],
                os.environ['WEEKLYREMOVE_TABLE'],
                os.environ['WEEKLYUPDATE_TABLE'],
                os.environ['MONTHLYREMOVE_TABLE'],
                os.environ['MONTHLYUPDATE_TABLE'],
            ],
        )
        self.assertEqual(update_watchlist.call_count, 1)

    def test_refresh_permutation_counts_uses_all_tables_and_dynamodb_rows(self):
        permutations = [
            {'permutation': 'lukah', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
            {'permutation': 'alpha', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
        ]

        table_rows = {
            os.environ['OSINT_TABLE']: {
                'x-lukah-1.com': {
                    'sources': ['https://source/osint-a', 'https://source/osint-b'],
                    'matched_permutations': ['lukah'],
                }
            },
            os.environ['MALWARE_TABLE']: {
                'x-lukah-2.net': {
                    'sources': ['https://domains-monitor.com'],
                    'matched_permutations': ['lukah'],
                }
            },
            os.environ['DAILYUPDATE_TABLE']: {
                'alpha-update.org': {
                    'sources': ['https://domains-monitor.com'],
                    'matched_permutations': ['alpha'],
                }
            },
        }

        def _fake_list_table_domains(table_name, _email, _domain):
            return table_rows.get(table_name, {})

        with patch.object(self.search_lambda, '_list_table_domains', side_effect=_fake_list_table_domains):
            self.search_lambda._refresh_permutation_counts_from_tables(
                email='user@example.com',
                domain='lukach.io',
                permutations=permutations,
                table_names=[
                    os.environ['OSINT_TABLE'],
                    os.environ['MALWARE_TABLE'],
                    os.environ['DAILYREMOVE_TABLE'],
                    os.environ['DAILYUPDATE_TABLE'],
                    os.environ['WEEKLYREMOVE_TABLE'],
                    os.environ['WEEKLYUPDATE_TABLE'],
                    os.environ['MONTHLYREMOVE_TABLE'],
                    os.environ['MONTHLYUPDATE_TABLE'],
                ],
            )

        by_term = {entry['permutation']: entry for entry in permutations}
        self.assertEqual(by_term['lukah']['unique_domains'], 2)
        self.assertEqual(by_term['lukah']['unique_sources'], 3)
        self.assertEqual(by_term['alpha']['unique_domains'], 1)
        self.assertEqual(by_term['alpha']['unique_sources'], 1)

    def test_refresh_permutation_counts_ignores_rows_without_stored_matches(self):
        permutations = [
            {'permutation': 'lukah', 'enabled': 'ON', 'unique_domains': 0, 'unique_sources': 0},
        ]

        table_rows = {
            os.environ['MALWARE_TABLE']: {
                # Row without stored permutation attribution must not be counted.
                'x-lukah-legacy.net': {
                    'sources': ['https://domains-monitor.com'],
                    'matched_permutations': [],
                }
            }
        }

        def _fake_list_table_domains(table_name, _email, _domain):
            return table_rows.get(table_name, {})

        with patch.object(self.search_lambda, '_list_table_domains', side_effect=_fake_list_table_domains):
            self.search_lambda._refresh_permutation_counts_from_tables(
                email='user@example.com',
                domain='lukach.io',
                permutations=permutations,
                table_names=[os.environ['MALWARE_TABLE']],
            )

        self.assertEqual(permutations[0]['unique_domains'], 0)
        self.assertEqual(permutations[0]['unique_sources'], 0)


if __name__ == '__main__':
    unittest.main()
