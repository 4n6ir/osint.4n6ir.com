import unittest

from aws_cdk import App, Stack, assertions
from aws_cdk import aws_dynamodb as _dynamodb

from osint.osint_digest import OsintDigest


class OsintDigestStackTests(unittest.TestCase):
    def _build_template(self):
        app = App()
        db_stack = Stack(app, 'DigestDbTestStack')

        def _table(name):
            return _dynamodb.TableV2(
                db_stack,
                name,
                table_name=name.lower(),
                partition_key={'name': 'pk', 'type': _dynamodb.AttributeType.STRING},
                sort_key={'name': 'sk', 'type': _dynamodb.AttributeType.STRING},
                billing=_dynamodb.Billing.on_demand(),
                dynamo_stream=_dynamodb.StreamViewType.NEW_IMAGE,
            )

        digest_table = _table('Digest')
        dailyremove_table = _table('DailyRemove')
        dailyupdate_table = _table('DailyUpdate')
        malware_table = _table('Malware')
        osint_table = _table('Osint')

        stack = OsintDigest(
            app,
            'DigestTestStack',
            dailyremove_table=dailyremove_table,
            dailyupdate_table=dailyupdate_table,
            digest_table=digest_table,
            malware_table=malware_table,
            osint_table=osint_table,
        )

        return assertions.Template.from_stack(stack)

    def test_creates_lambdas_and_queue(self):
        template = self._build_template()

        template.resource_count_is('AWS::Lambda::Function', 3)
        template.resource_count_is('AWS::SQS::Queue', 2)
        template.resource_count_is('AWS::Lambda::EventSourceMapping', 5)


if __name__ == '__main__':
    unittest.main()
