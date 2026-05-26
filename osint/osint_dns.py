from aws_cdk import (
    RemovalPolicy,
    Stack,
    aws_certificatemanager as _acm,
    aws_iam as _iam,
    aws_logs as _logs,
    aws_route53 as _route53,
    aws_ssm as _ssm
)

from constructs import Construct
from config import Config

class OsintDns(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

    ### HOSTZONE ###

        policy_statement = _iam.PolicyStatement(
            principals = [
                _iam.ServicePrincipal('route53.amazonaws.com')
            ],
            actions = [
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            resources=[
                'arn:aws:logs:'+region+':'+account+':log-group:*'
            ]
        )

        self.resourcepolicy = _logs.ResourcePolicy(
            self, 'resourcepolicy',
            policy_statements = [
                policy_statement
            ],
            resource_policy_name = 'Route53LogsPolicy'
        )

        logs = _logs.LogGroup(
            self, 'logs',
            log_group_name = Config.ROUTE53_LOGS_GROUP,
            retention = _logs.RetentionDays.THIRTEEN_MONTHS,
            removal_policy = RemovalPolicy.DESTROY
        )

        hostzone = _route53.PublicHostedZone(
            self, 'hostzone', 
            zone_name = Config.DOMAIN,
            comment = Config.DOMAIN,
            query_logs_log_group_arn = logs.log_group_arn
        )

        # Export hosted zone for use by API and IDP stacks
        self.hostzone = hostzone

    ### ACM CERTIFICATE ###

        acm = _acm.Certificate(
            self, 'acm',
            domain_name = Config.SUBDOMAIN,
            validation = _acm.CertificateValidation.from_dns(hostzone)
        )

        # Export ACM certificate for use by API stack
        self.acm = acm

    ### PARAMETER ###

        self.parameter = _ssm.StringParameter(
            self, 'parameter',
            description = Config.DOMAIN,
            parameter_name = Config.ROUTE53_PARAM,
            string_value = hostzone.hosted_zone_id,
            tier = _ssm.ParameterTier.STANDARD
        )

        self.acmparameter = _ssm.StringParameter(
            self, 'acmparameter',
            description = Config.DOMAIN,
            parameter_name = Config.ACM_PARAM,
            string_value = acm.certificate_arn,
            tier = _ssm.ParameterTier.STANDARD
        )
