from aws_cdk import (
    RemovalPolicy,
    Stack,
    aws_lambda as _lambda,
    aws_s3 as _s3,
    aws_ssm as _ssm,
)

from constructs import Construct
from config import Config
class OsintLayers(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        packages_bucket = _s3.Bucket.from_bucket_name(
            self,
            'packagesbucket',
            bucket_name=Config.PACKAGES_BUCKET,
        )

        self.requests = _lambda.LayerVersion(
            self,
            'requests',
            description=Config.requests_layer_description(),
            code=_lambda.Code.from_bucket(
                bucket=packages_bucket,
                key='requests.zip',
            ),
            compatible_architectures=[_lambda.Architecture.ARM_64],
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_13],
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.parameter = _ssm.StringParameter(
            self,
            'parameter',
            parameter_name=Config.REQUESTS_LAYER_PARAM,
            string_value=self.requests.layer_version_arn,
            description='Requests Lambda Layer ARN',
            tier=_ssm.ParameterTier.STANDARD,
        )