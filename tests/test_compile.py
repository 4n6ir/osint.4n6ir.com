import os
import unittest
from datetime import datetime, timedelta, timezone


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')

from compile import compile as compile_module


class CompileSelectionTests(unittest.TestCase):
    def test_select_recent_keys_per_source_filters_by_24h_and_caps_to_24(self):
        now = datetime(2026, 5, 22, 12, 0, 0, tzinfo=timezone.utc)
        objects = []

        for index in range(30):
            objects.append(
                {
                    'Key': f'onehosts/file-{index:02d}.txt',
                    'LastModified': now - timedelta(minutes=index),
                }
            )

        objects.append(
            {
                'Key': 'onehosts/old.txt',
                'LastModified': now - timedelta(hours=25),
            }
        )
        objects.append(
            {
                'Key': 'urlhaus/recent.txt',
                'LastModified': now - timedelta(hours=1),
            }
        )

        selected = compile_module._select_recent_keys_per_source(
            objects,
            now=now,
            lookback_hours=24,
            max_files_per_source=24,
        )

        onehosts_keys = [key for key in selected if key.startswith('onehosts/')]
        urlhaus_keys = [key for key in selected if key.startswith('urlhaus/')]

        self.assertEqual(len(onehosts_keys), 24)
        self.assertNotIn('onehosts/old.txt', onehosts_keys)
        self.assertEqual(onehosts_keys[0], 'onehosts/file-00.txt')
        self.assertEqual(onehosts_keys[-1], 'onehosts/file-23.txt')

        self.assertEqual(urlhaus_keys, ['urlhaus/recent.txt'])

    def test_select_recent_keys_per_source_handles_root_and_skips_invalid_items(self):
        now = datetime(2026, 5, 22, 12, 0, 0, tzinfo=timezone.utc)
        objects = [
            {
                'Key': 'root-file.txt',
                'LastModified': now - timedelta(minutes=10),
            },
            {
                'Key': 'folder/',
                'LastModified': now - timedelta(minutes=5),
            },
            {
                'Key': 'no-modified.txt',
            },
        ]

        selected = compile_module._select_recent_keys_per_source(
            objects,
            now=now,
            lookback_hours=24,
            max_files_per_source=24,
        )

        self.assertEqual(selected, ['root-file.txt'])


if __name__ == '__main__':
    unittest.main()
