from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_s3 as _s3,
    aws_s3_notifications as _s3n,
    aws_sqs as _sqs,
)

from constructs import Construct


class OsintS3(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        dlq = _sqs.Queue(
            self, 'sqldlq',
            queue_name=f'osint-sqlite-dlq-{region}',
            retention_period=Duration.days(14),
        )

        zipped_dlq = _sqs.Queue(
            self, 'zippeddlq',
            queue_name=f'osint-unzip-dlq-{region}',
            retention_period=Duration.days(14),
        )

        download_event_queue = _sqs.Queue(
            self, 'sqlqueue',
            queue_name=f'osint-sqlite-{region}',
            dead_letter_queue=_sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=dlq,
            ),
            visibility_timeout=Duration.minutes(30),
        )

        zipped_event_queue = _sqs.Queue(
            self, 'zipqueue',
            queue_name=f'osint-unzip-{region}',
            dead_letter_queue=_sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=zipped_dlq,
            ),
            visibility_timeout=Duration.minutes(30),
        )

        create_dlq = _sqs.Queue(
            self, 'createdlq',
            queue_name=f'osint-create-dlq-{region}',
            retention_period=Duration.days(14),
        )

        create_event_queue = _sqs.Queue(
            self, 'createqueue',
            queue_name=f'osint-create-{region}',
            dead_letter_queue=_sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=create_dlq,
            ),
            visibility_timeout=Duration.minutes(30),
        )

        for namespace in ['addresses','domains', 'download', 'sqlite', 'zipped']:
            bucket = _s3.Bucket(
                self,
                namespace,
                bucket_name=f'osint-{namespace}-{region}-{account}',
                encryption=_s3.BucketEncryption.S3_MANAGED,
                block_public_access=_s3.BlockPublicAccess.BLOCK_ALL,
                removal_policy=RemovalPolicy.DESTROY,
                auto_delete_objects=True,
                enforce_ssl=True,
                versioned=False,
            )

            bucket.add_lifecycle_rule(
                expiration=Duration.days(1),
                noncurrent_version_expiration=Duration.days(1),
            )

            if namespace == 'download':
                bucket.add_event_notification(
                    _s3.EventType.OBJECT_CREATED,
                    _s3n.SqsDestination(download_event_queue),
                    _s3.NotificationKeyFilter(suffix='.csv'),
                )

            if namespace == 'zipped':
                bucket.add_event_notification(
                    _s3.EventType.OBJECT_CREATED,
                    _s3n.SqsDestination(zipped_event_queue),
                    _s3.NotificationKeyFilter(suffix='.zip'),
                )

            if namespace == 'sqlite':
                bucket.add_event_notification(
                    _s3.EventType.OBJECT_CREATED,
                    _s3n.SqsDestination(create_event_queue),
                    _s3.NotificationKeyFilter(suffix='osint.sqlite3'),
                )

        self.download_queue = download_event_queue
        self.zipped_queue = zipped_event_queue
        self.create_queue = create_event_queue
