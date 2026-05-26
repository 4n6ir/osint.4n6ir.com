from __future__ import annotations

import json
import logging
import os
import posixpath
import struct
import time
import zlib
from dataclasses import dataclass
from typing import Callable
from urllib.parse import unquote_plus

import boto3


S3_CLIENT = boto3.client('s3')
CHUNK_SIZE = 8 * 1024 * 1024
PART_SIZE = 64 * 1024 * 1024
LINES_PER_FILE = int(os.environ.get('LINES_PER_FILE', '10000000'))
TARGET_ZIP_ENTRY_NAME = os.environ.get('TARGET_ZIP_ENTRY_NAME', 'domains.txt').lower()
SOURCE_ID = os.environ.get('SOURCE_ID', 'M').strip() or 'M'
ZIP64_SENTINEL = 0xFFFFFFFF
LOGGER = logging.getLogger(__name__)


def _normalize_domain(value: str) -> str:
    domain = (value or '').strip().lower().rstrip('.')
    if domain.startswith('*.'):
        domain = domain[2:]
    return domain


def _format_output_row(raw_line: bytes) -> bytes | None:
    domain = _normalize_domain(raw_line.decode('utf-8', errors='replace'))
    if not domain:
        return None

    labels = [label for label in domain.split('.') if label]
    if len(labels) < 2:
        return None

    sld = labels[-2]
    tld = labels[-1]
    if not sld or not tld:
        return None

    return f'{sld},{tld},{SOURCE_ID}\n'.encode('utf-8')


@dataclass
class ProcessingMetrics:
    s3_read_bytes: int = 0
    s3_read_seconds: float = 0.0
    inflate_seconds: float = 0.0
    line_split_seconds: float = 0.0
    s3_upload_bytes: int = 0
    s3_upload_seconds: float = 0.0
    files_created: int = 0

    def to_dict(self, total_seconds: float) -> dict[str, float | int]:
        read_mib = self.s3_read_bytes / (1024 * 1024)
        upload_mib = self.s3_upload_bytes / (1024 * 1024)
        return {
            'total_seconds': round(total_seconds, 3),
            's3_read_seconds': round(self.s3_read_seconds, 3),
            'inflate_seconds': round(self.inflate_seconds, 3),
            'line_split_seconds': round(self.line_split_seconds, 3),
            's3_upload_seconds': round(self.s3_upload_seconds, 3),
            's3_read_bytes': self.s3_read_bytes,
            's3_upload_bytes': self.s3_upload_bytes,
            's3_read_mib_per_sec': round(read_mib / self.s3_read_seconds, 3) if self.s3_read_seconds else 0.0,
            's3_upload_mib_per_sec': round(upload_mib / self.s3_upload_seconds, 3) if self.s3_upload_seconds else 0.0,
            'files_created': self.files_created,
        }


class StreamReader:
    def __init__(self, body, metrics: ProcessingMetrics, chunk_size: int = CHUNK_SIZE) -> None:
        self._iter = body.iter_chunks(chunk_size=chunk_size)
        self._buffer = bytearray()
        self._metrics = metrics

    def _fill(self, minimum: int) -> None:
        while len(self._buffer) < minimum:
            try:
                read_started = time.perf_counter()
                chunk = next(self._iter)
                self._metrics.s3_read_seconds += time.perf_counter() - read_started
            except StopIteration:
                break
            if chunk:
                self._buffer.extend(chunk)
                self._metrics.s3_read_bytes += len(chunk)

    def read_exact(self, size: int) -> bytes:
        self._fill(size)
        if len(self._buffer) < size:
            raise EOFError(
                f'Unexpected end of stream while reading {size} bytes '
                f'(only {len(self._buffer)} bytes available)'
            )

        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def read_signature_or_none(self) -> bytes | None:
        self._fill(1)
        if not self._buffer:
            return None
        return self.read_exact(4)

    def pull_chunk(self, preferred_size: int = CHUNK_SIZE) -> bytes:
        self._fill(1)
        if not self._buffer:
            return b''

        self._fill(preferred_size)
        take = min(len(self._buffer), preferred_size)
        data = bytes(self._buffer[:take])
        del self._buffer[:take]
        return data

    def unread(self, data: bytes) -> None:
        if not data:
            return
        self._buffer = bytearray(data) + self._buffer


class MultipartWriter:
    def __init__(self, bucket: str, key: str, metrics: ProcessingMetrics) -> None:
        self.bucket = bucket
        self.key = key
        self._buffer = bytearray()
        self._upload_id: str | None = None
        self._parts: list[dict[str, int | str]] = []
        self._part_number = 1
        self._metrics = metrics

    def _ensure_multipart(self) -> None:
        if self._upload_id is not None:
            return
        upload_started = time.perf_counter()
        response = S3_CLIENT.create_multipart_upload(
            Bucket=self.bucket,
            Key=self.key,
            ContentType='text/csv',
        )
        self._metrics.s3_upload_seconds += time.perf_counter() - upload_started
        self._upload_id = response['UploadId']

    def _upload_part(self, body: bytes) -> None:
        self._ensure_multipart()
        upload_started = time.perf_counter()
        response = S3_CLIENT.upload_part(
            Bucket=self.bucket,
            Key=self.key,
            PartNumber=self._part_number,
            UploadId=self._upload_id,
            Body=body,
        )
        self._metrics.s3_upload_seconds += time.perf_counter() - upload_started
        self._metrics.s3_upload_bytes += len(body)
        self._parts.append({'PartNumber': self._part_number, 'ETag': response['ETag']})
        self._part_number += 1

    def write(self, data: bytes) -> None:
        if not data:
            return

        self._buffer.extend(data)
        while len(self._buffer) >= PART_SIZE:
            chunk = bytes(self._buffer[:PART_SIZE])
            del self._buffer[:PART_SIZE]
            self._upload_part(chunk)

    def close(self) -> None:
        if self._upload_id is None:
            upload_started = time.perf_counter()
            S3_CLIENT.put_object(Bucket=self.bucket, Key=self.key, Body=bytes(self._buffer), ContentType='text/csv')
            self._metrics.s3_upload_seconds += time.perf_counter() - upload_started
            self._metrics.s3_upload_bytes += len(self._buffer)
            self._buffer.clear()
            return

        if self._buffer:
            self._upload_part(bytes(self._buffer))
            self._buffer.clear()

        upload_started = time.perf_counter()
        S3_CLIENT.complete_multipart_upload(
            Bucket=self.bucket,
            Key=self.key,
            UploadId=self._upload_id,
            MultipartUpload={'Parts': self._parts},
        )
        self._metrics.s3_upload_seconds += time.perf_counter() - upload_started
        self._upload_id = None

    def abort(self) -> None:
        if self._upload_id is None:
            return
        S3_CLIENT.abort_multipart_upload(
            Bucket=self.bucket,
            Key=self.key,
            UploadId=self._upload_id,
        )
        self._upload_id = None


class ChunkedLineUploader:
    def __init__(self, bucket: str, output_prefix: str, entry_name: str, lines_per_file: int, metrics: ProcessingMetrics) -> None:
        base_name = posixpath.basename(entry_name)
        stem, _ext = posixpath.splitext(base_name)
        self.bucket = bucket
        self.output_prefix = output_prefix
        normalized_stem = stem or 'file'
        if normalized_stem.startswith('full'):
            self.stem = normalized_stem
        else:
            self.stem = f'full-{normalized_stem}'
        self.ext = '.csv'
        self.lines_per_file = lines_per_file
        self._metrics = metrics

        self._line_count_in_part = 0
        self._part_index = 1
        self._pending = b''
        self._writer: MultipartWriter | None = None
        self.generated_keys: list[str] = []

    def _current_key(self) -> str:
        filename = f'{self.stem}.part-{self._part_index:05d}{self.ext}'
        if self.output_prefix:
            return f'{self.output_prefix}/{filename}'
        return filename

    def _ensure_writer(self) -> None:
        if self._writer is not None:
            return
        key = self._current_key()
        self.generated_keys.append(key)
        self._writer = MultipartWriter(self.bucket, key, self._metrics)

    def _rotate_writer_if_needed(self) -> None:
        if self._line_count_in_part < self.lines_per_file:
            return
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        self._part_index += 1
        self._line_count_in_part = 0

    def _write_line(self, line: bytes) -> None:
        self._ensure_writer()
        self._writer.write(line)
        self._line_count_in_part += 1
        self._rotate_writer_if_needed()

    def feed(self, data: bytes) -> None:
        if not data:
            return

        started = time.perf_counter()

        buffer = self._pending + data
        lines = buffer.split(b'\n')
        self._pending = lines.pop()

        for line in lines:
            formatted = _format_output_row(line)
            if formatted is None:
                continue
            self._write_line(formatted)

        self._metrics.line_split_seconds += time.perf_counter() - started

    def finish(self) -> list[str]:
        if self._pending:
            formatted = _format_output_row(self._pending)
            if formatted is not None:
                self._write_line(formatted)
            self._pending = b''

        if self._writer is not None:
            self._writer.close()
            self._writer = None

        return self.generated_keys

    def abort(self) -> None:
        if self._writer is not None:
            self._writer.abort()
            self._writer = None


@dataclass
class LocalFileHeader:
    flags: int
    compression_method: int
    compressed_size: int
    uncompressed_size: int
    file_name: str


def _resolve_zip64_sizes(
    compressed_size: int,
    uncompressed_size: int,
    extra: bytes,
) -> tuple[int, int]:
    if compressed_size != ZIP64_SENTINEL and uncompressed_size != ZIP64_SENTINEL:
        return compressed_size, uncompressed_size

    offset = 0
    while offset + 4 <= len(extra):
        header_id, data_size = struct.unpack_from('<HH', extra, offset)
        offset += 4

        if offset + data_size > len(extra):
            break

        if header_id != 0x0001:
            offset += data_size
            continue

        data = extra[offset : offset + data_size]
        cursor = 0

        resolved_uncompressed = uncompressed_size
        resolved_compressed = compressed_size

        if uncompressed_size == ZIP64_SENTINEL:
            if cursor + 8 > len(data):
                raise ValueError('Invalid ZIP64 extra field: missing uncompressed size')
            resolved_uncompressed = struct.unpack_from('<Q', data, cursor)[0]
            cursor += 8

        if compressed_size == ZIP64_SENTINEL:
            if cursor + 8 > len(data):
                raise ValueError('Invalid ZIP64 extra field: missing compressed size')
            resolved_compressed = struct.unpack_from('<Q', data, cursor)[0]

        return resolved_compressed, resolved_uncompressed

    raise ValueError('ZIP64 sizes indicated in header but ZIP64 extra field is missing or incomplete')


def _read_local_file_header(reader: StreamReader) -> LocalFileHeader:
    header = reader.read_exact(26)
    (
        _version_needed,
        flags,
        compression_method,
        _mod_time,
        _mod_date,
        _crc32,
        compressed_size,
        uncompressed_size,
        file_name_len,
        extra_len,
    ) = struct.unpack('<HHHHHIIIHH', header)

    name_bytes = reader.read_exact(file_name_len)
    extra_bytes = reader.read_exact(extra_len)
    compressed_size, uncompressed_size = _resolve_zip64_sizes(compressed_size, uncompressed_size, extra_bytes)

    return LocalFileHeader(
        flags=flags,
        compression_method=compression_method,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        file_name=name_bytes.decode('utf-8', errors='replace'),
    )


def _consume_data_descriptor(reader: StreamReader) -> None:
    start = reader.read_exact(4)
    if start == b'PK\x07\x08':
        reader.read_exact(12)
        return

    # Signature may be omitted, in which case we already consumed the CRC32.
    reader.read_exact(8)


def _stream_stored(reader: StreamReader, compressed_size: int, on_data: Callable[[bytes], None]) -> None:
    remaining = compressed_size
    while remaining > 0:
        chunk = reader.read_exact(min(CHUNK_SIZE, remaining))
        remaining -= len(chunk)
        on_data(chunk)


def _stream_deflated(
    reader: StreamReader,
    compressed_size: int,
    has_descriptor: bool,
    on_data: Callable[[bytes], None],
    metrics: ProcessingMetrics,
) -> None:
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

    if has_descriptor:
        while True:
            chunk = reader.pull_chunk(CHUNK_SIZE)
            if not chunk:
                raise EOFError('Unexpected EOF while decompressing entry with data descriptor')

            inflate_started = time.perf_counter()
            output = decompressor.decompress(chunk)
            metrics.inflate_seconds += time.perf_counter() - inflate_started
            if output:
                on_data(output)

            if decompressor.eof:
                if decompressor.unused_data:
                    reader.unread(decompressor.unused_data)
                break

        inflate_started = time.perf_counter()
        tail = decompressor.flush()
        metrics.inflate_seconds += time.perf_counter() - inflate_started
        if tail:
            on_data(tail)
        _consume_data_descriptor(reader)
        return

    remaining = compressed_size
    while remaining > 0:
        chunk = reader.read_exact(min(CHUNK_SIZE, remaining))
        remaining -= len(chunk)

        inflate_started = time.perf_counter()
        output = decompressor.decompress(chunk)
        metrics.inflate_seconds += time.perf_counter() - inflate_started
        if output:
            on_data(output)

    inflate_started = time.perf_counter()
    tail = decompressor.flush()
    metrics.inflate_seconds += time.perf_counter() - inflate_started
    if tail:
        on_data(tail)


def _drain_entry_data(reader: StreamReader, header: LocalFileHeader) -> None:
    has_descriptor = bool(header.flags & 0x08)

    if header.compression_method == 0:
        if has_descriptor:
            raise ValueError('Stored entries with data descriptor are not supported for streaming')
        _stream_stored(reader, header.compressed_size, lambda _: None)
        return

    if header.compression_method == 8:
        _stream_deflated(reader, header.compressed_size, has_descriptor, lambda _: None, ProcessingMetrics())
        return

    raise ValueError(f'Unsupported ZIP compression method: {header.compression_method}')


def _process_entry(
    source_bucket: str,
    source_key: str,
    header: LocalFileHeader,
    reader: StreamReader,
    metrics: ProcessingMetrics,
) -> list[str]:
    if header.file_name.endswith('/'):
        _drain_entry_data(reader, header)
        return []

    if posixpath.basename(header.file_name).lower() != TARGET_ZIP_ENTRY_NAME:
        _drain_entry_data(reader, header)
        print(
            f'Skipping entry {header.file_name} from s3://{source_bucket}/{source_key}; '
            f'only {TARGET_ZIP_ENTRY_NAME} is processed'
        )
        return []

    target_bucket = os.environ['S3_DOWNLOAD_BUCKET']
    output_prefix = ''
    uploader = ChunkedLineUploader(
        bucket=target_bucket,
        output_prefix=output_prefix,
        entry_name=header.file_name,
        lines_per_file=LINES_PER_FILE,
        metrics=metrics,
    )

    has_descriptor = bool(header.flags & 0x08)

    try:
        if header.compression_method == 0:
            if has_descriptor:
                raise ValueError('Stored entries with data descriptor are not supported for streaming')
            _stream_stored(reader, header.compressed_size, uploader.feed)
        elif header.compression_method == 8:
            _stream_deflated(reader, header.compressed_size, has_descriptor, uploader.feed, metrics)
        else:
            raise ValueError(f'Unsupported ZIP compression method: {header.compression_method}')

        keys = uploader.finish()
        metrics.files_created += len(keys)
        destination = f's3://{target_bucket}/' if not output_prefix else f's3://{target_bucket}/{output_prefix}/'
        print(
            f'Processed entry {header.file_name} from s3://{source_bucket}/{source_key}; '
            f'created {len(keys)} file(s) in {destination}'
        )
        return keys
    except Exception:
        uploader.abort()
        raise


def _process_zip_object(source_bucket: str, source_key: str) -> dict[str, object]:
    started = time.perf_counter()
    metrics = ProcessingMetrics()
    response = S3_CLIENT.get_object(Bucket=source_bucket, Key=source_key)
    reader = StreamReader(response['Body'], metrics=metrics)

    generated_keys: list[str] = []
    entry_count = 0

    while True:
        signature = reader.read_signature_or_none()
        if signature is None:
            break

        if signature == b'PK\x03\x04':
            header = _read_local_file_header(reader)
            entry_count += 1
            generated_keys.extend(_process_entry(source_bucket, source_key, header, reader, metrics))
            continue

        # Central directory / end of central directory; processing is complete.
        if signature in {b'PK\x01\x02', b'PK\x05\x06', b'PK\x06\x06', b'PK\x06\x07'}:
            break

        raise ValueError(f'Unknown ZIP signature: {signature!r}')

    total_seconds = time.perf_counter() - started

    return {
        'source_bucket': source_bucket,
        'source_key': source_key,
        'entries_processed': entry_count,
        'generated_files': len(generated_keys),
        'sample_keys': generated_keys[:5],
        'metrics': metrics.to_dict(total_seconds),
    }


def _iter_s3_records(event: dict) -> list[dict]:
    s3_records: list[dict] = []

    for record in event.get('Records', []):
        body = record.get('body')
        if not body:
            continue

        message = json.loads(body)
        for nested in message.get('Records', []):
            if nested.get('eventSource') == 'aws:s3' and nested.get('eventName', '').startswith('ObjectCreated:'):
                s3_records.append(nested)

    return s3_records


def handler(event, _context):
    batch_failures: list[dict[str, str]] = []

    for sqs_record in event.get('Records', []):
        message_id = sqs_record.get('messageId', '')
        current_source_bucket = ''
        current_source_key = ''
        current_event_name = ''
        try:
            body = sqs_record.get('body', '{}')
            message = json.loads(body)

            for s3_record in message.get('Records', []):
                if s3_record.get('eventSource') != 'aws:s3':
                    continue
                if not s3_record.get('eventName', '').startswith('ObjectCreated:'):
                    continue

                source_bucket = s3_record.get('s3', {}).get('bucket', {}).get('name', '')
                source_key = unquote_plus(s3_record.get('s3', {}).get('object', {}).get('key', ''))
                current_source_bucket = source_bucket
                current_source_key = source_key
                current_event_name = s3_record.get('eventName', '')
                if not source_bucket or not source_key:
                    continue

                if not source_key.endswith('.zip'):
                    print(f'Skipping non-zip object s3://{source_bucket}/{source_key}')
                    continue

                summary = _process_zip_object(source_bucket, source_key)
                print(f'Completed zip processing summary: {json.dumps(summary)}')

        except Exception:
            LOGGER.exception(
                'ERROR Failed processing SQS message %s for s3://%s/%s event_name=%s. Traceback follows.',
                message_id,
                current_source_bucket,
                current_source_key,
                current_event_name,
            )
            batch_failures.append({'itemIdentifier': message_id})

    return {'batchItemFailures': batch_failures}
