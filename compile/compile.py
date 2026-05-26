import json
import logging
import os
import shutil
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

import boto3  # pyright: ignore[reportMissingImports]
from botocore.exceptions import ClientError  # pyright: ignore[reportMissingImports]


S3_CLIENT = boto3.client('s3')
CHUNK_LINE_LIMIT = int(os.getenv('CHUNK_LINE_LIMIT', '200000'))
LOOKBACK_HOURS = int(os.getenv('COMPILE_LOOKBACK_HOURS', '24'))
MAX_FILES_PER_SOURCE = int(os.getenv('COMPILE_MAX_FILES_PER_SOURCE', '24'))
LOGGER = logging.getLogger(__name__)


def _dir_size_bytes(path: str) -> int:
	total = 0
	for root, _, files in os.walk(path):
		for name in files:
			file_path = os.path.join(root, name)
			if os.path.exists(file_path):
				total += os.path.getsize(file_path)
	return total


def _log_tmp_usage(tmpdir: str, label: str) -> None:
	usage = shutil.disk_usage('/tmp')
	work_size = _dir_size_bytes(tmpdir)
	print(
		f"TMP [{label}] fs_used_mb={usage.used // (1024 * 1024)} "
		f"fs_free_mb={usage.free // (1024 * 1024)} "
		f"workdir_mb={work_size // (1024 * 1024)}"
	)


def _source_from_key(key: str) -> str:
	return key.split('/', 1)[0] if '/' in key else 'root'


def _select_recent_keys_per_source(
	objects: Iterable[dict],
	now: datetime,
	lookback_hours: int,
	max_files_per_source: int,
) -> list[str]:
	cutoff = now - timedelta(hours=lookback_hours)
	grouped_objects: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

	for obj in objects:
		key = obj.get('Key', '')
		if not key or key.endswith('/'):
			continue

		modified = obj.get('LastModified')
		if not isinstance(modified, datetime):
			continue
		if modified.tzinfo is None:
			modified = modified.replace(tzinfo=timezone.utc)

		if modified < cutoff:
			continue

		source = _source_from_key(key)
		grouped_objects[source].append((modified, key))

	selected_keys: list[str] = []
	for source in sorted(grouped_objects):
		entries = grouped_objects[source]
		entries.sort(key=lambda item: (item[0], item[1]), reverse=True)
		selected_keys.extend(key for _, key in entries[:max_files_per_source])

	return selected_keys


def _iter_bucket_objects(bucket_name: str):
	paginator = S3_CLIENT.get_paginator('list_objects_v2')
	for page in paginator.paginate(Bucket=bucket_name):
		for obj in page.get('Contents', []):
			yield obj


def _list_domain_keys(bucket_name: str) -> list[str]:
	return _select_recent_keys_per_source(
		_iter_bucket_objects(bucket_name),
		now=datetime.now(timezone.utc),
		lookback_hours=LOOKBACK_HOURS,
		max_files_per_source=MAX_FILES_PER_SOURCE,
	)


def _flush_chunk(lines: set[str], chunks_dir: str, prefix: str, index: int) -> str:
	chunk_path = os.path.join(chunks_dir, f'{prefix}-{index:08d}.txt')
	with open(chunk_path, 'w', encoding='utf-8') as handle:
		for line in sorted(lines):
			handle.write(line + '\n')
	return chunk_path


def _iter_non_empty_lines(path: str):
	with open(path, 'r', encoding='utf-8') as handle:
		for line in handle:
			value = line.rstrip('\n')
			if value:
				yield value


def _merge_two_sorted_files(left_path: str, right_path: str, output_path: str) -> int:
	left_iter = _iter_non_empty_lines(left_path)
	right_iter = _iter_non_empty_lines(right_path)

	left = next(left_iter, None)
	right = next(right_iter, None)
	last_seen = None
	unique_count = 0

	with open(output_path, 'w', encoding='utf-8') as output:
		while left is not None or right is not None:
			if right is None or (left is not None and left <= right):
				candidate = left
				left = next(left_iter, None)
			else:
				candidate = right
				right = next(right_iter, None)

			if candidate == last_seen:
				continue

			output.write(candidate + '\n')
			last_seen = candidate
			unique_count += 1

	return unique_count


def _merge_chunk_into_stage(
	chunk_lines: set[str],
	chunks_dir: str,
	prefix: str,
	chunk_index: int,
	stage_path: str,
	merge_path: str,
) -> int:
	if not chunk_lines:
		return chunk_index

	chunk_path = _flush_chunk(chunk_lines, chunks_dir, prefix, chunk_index)
	chunk_lines.clear()

	_ = _merge_two_sorted_files(stage_path, chunk_path, merge_path)
	os.replace(merge_path, stage_path)
	os.remove(chunk_path)

	return chunk_index + 1


def _count_lines(path: str) -> int:
	count = 0
	for _ in _iter_non_empty_lines(path):
		count += 1
	return count


def _build_grouped_keys(keys: list[str]) -> dict[str, list[str]]:
	grouped_keys: dict[str, list[str]] = defaultdict(list)
	for key in keys:
		source = _source_from_key(key)
		grouped_keys[source].append(key)
	return grouped_keys


def _count_selected_per_source(grouped_keys: dict[str, list[str]]) -> dict[str, int]:
	return {source: len(source_keys) for source, source_keys in sorted(grouped_keys.items())}


def _stage_source(bucket_name: str, source: str, source_keys: list[str], tmpdir: str) -> tuple[str, int, int]:
	chunks_dir = os.path.join(tmpdir, 'chunks')
	os.makedirs(chunks_dir, exist_ok=True)

	stage_path = os.path.join(tmpdir, f'stage-{source}.txt')
	merge_path = os.path.join(tmpdir, f'stage-{source}.merge.txt')
	with open(stage_path, 'w', encoding='utf-8') as _:
		pass

	chunk_lines: set[str] = set()
	chunk_index = 0
	count_before = 0
	skipped_missing = 0

	for key in sorted(source_keys):
		try:
			response = S3_CLIENT.get_object(Bucket=bucket_name, Key=key)
		except S3_CLIENT.exceptions.NoSuchKey:
			print(f'Skipping missing key during staging: s3://{bucket_name}/{key}')
			skipped_missing += 1
			continue
		except ClientError as error:
			error_code = error.response.get('Error', {}).get('Code', '')
			if error_code in {'NoSuchKey', '404', 'NotFound'}:
				print(f'Skipping missing key during staging: s3://{bucket_name}/{key}')
				skipped_missing += 1
				continue
			raise
		for raw_line in response['Body'].iter_lines(chunk_size=1024 * 1024):
			if isinstance(raw_line, bytes):
				raw_line = raw_line.decode('utf-8', errors='replace')

			line = (raw_line or '').strip()
			if not line:
				continue

			count_before += 1
			chunk_lines.add(line)

			if len(chunk_lines) >= CHUNK_LINE_LIMIT:
				chunk_index = _merge_chunk_into_stage(
					chunk_lines,
					chunks_dir,
					source,
					chunk_index,
					stage_path,
					merge_path,
				)

	if chunk_lines:
		chunk_index = _merge_chunk_into_stage(
			chunk_lines,
			chunks_dir,
			source,
			chunk_index,
			stage_path,
			merge_path,
		)

	_ = chunk_index
	return stage_path, count_before, skipped_missing


def _upload_compiled_csv(path: str, bucket_name: str) -> str:
	key = 'osint.csv'

	S3_CLIENT.upload_file(
		path,
		bucket_name,
		key,
		ExtraArgs={
			'ContentType': 'text/csv',
		},
	)

	return key


def handler(event, context):
	_ = (event, context)
	domains_bucket = os.environ.get('S3_DOMAINS_BUCKET', '')
	download_bucket = os.environ.get('S3_DOWNLOAD_BUCKET', '')
	keys: list[str] = []
	grouped_keys: dict[str, list[str]] = {}
	selected_per_source: dict[str, int] = {}
	count_before = 0
	total_missing_keys_skipped = 0

	try:
		keys = _list_domain_keys(domains_bucket)
		print(
			f'Files selected in domains bucket: {len(keys)} '
			f'(lookback_hours={LOOKBACK_HOURS}, max_files_per_source={MAX_FILES_PER_SOURCE})'
		)

		grouped_keys = _build_grouped_keys(keys)
		selected_per_source = _count_selected_per_source(grouped_keys)
		print(f'Selected files per source: {json.dumps(selected_per_source, sort_keys=True)}')

		with tempfile.TemporaryDirectory(dir='/tmp') as tmpdir:
			_log_tmp_usage(tmpdir, 'start')

			global_stage_path = os.path.join(tmpdir, 'global-stage.txt')
			global_merge_path = os.path.join(tmpdir, 'global-stage.merge.txt')
			with open(global_stage_path, 'w', encoding='utf-8') as _:
				pass

			for source, source_keys in sorted(grouped_keys.items()):
				staged_source_path, source_count_before, source_skipped_missing = _stage_source(
					domains_bucket,
					source,
					source_keys,
					tmpdir,
				)
				count_before += source_count_before
				total_missing_keys_skipped += source_skipped_missing
				print(
					f'Staged source {source}: {source_count_before} lines before dedupe '
					f'({source_skipped_missing} missing keys skipped)'
				)

				_ = _merge_two_sorted_files(global_stage_path, staged_source_path, global_merge_path)
				os.replace(global_merge_path, global_stage_path)
				os.remove(staged_source_path)

			final_path = os.path.join(tmpdir, 'osint.csv')
			count_after = _count_lines(global_stage_path)
			os.replace(global_stage_path, final_path)
			_log_tmp_usage(tmpdir, 'before-upload')

			print(f'Count before unique/sort: {count_before}')
			print(f'Count after unique/sort: {count_after}')
			print(f'Missing keys skipped during staging: {total_missing_keys_skipped}')

			output_key = _upload_compiled_csv(final_path, download_bucket)
			_log_tmp_usage(tmpdir, 'after-upload')
		print(f'Compiled output: s3://{download_bucket}/{output_key}')
	except Exception:
		LOGGER.exception(
			'ERROR Compile failed. domains_bucket=%s download_bucket=%s keys_found=%d grouped_sources=%d '
			'count_before=%d missing_keys_skipped=%d',
			domains_bucket,
			download_bucket,
			len(keys),
			len(grouped_keys),
			count_before,
			total_missing_keys_skipped,
		)
		raise

	return {
		'statusCode': 200,
		'body': json.dumps(
			{
				'files_processed': len(keys),
				'selected_per_source': selected_per_source,
				'missing_keys_skipped': total_missing_keys_skipped,
				'count_before': count_before,
				'count_after': count_after,
				'output_key': output_key,
			}
		),
	}
