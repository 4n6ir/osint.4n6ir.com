from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigatewayv2 as _apigw,
    aws_apigatewayv2_integrations as _integrations,
    aws_apigatewayv2_authorizers as _authorizers,
    aws_certificatemanager as _acm,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_route53 as _route53,
    aws_route53_targets as _r53targets,
    aws_iam as _iam
)

from constructs import Construct
from config import Config

class OsintApi(Stack):

    def __init__(self, 
                 scope: Construct, 
                 construct_id: str,
                 dns_stack,
                 auth_lambda: _lambda.Function,
                 home_lambda: _lambda.Function,
                 root_lambda: _lambda.Function,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        hostedzone = dns_stack.hostzone

    ### ACM CERTIFICATE (us-east-2) ###

        acm = _acm.Certificate(
            self, 'acm',
            domain_name = Config.API_DOMAIN,
            validation = _acm.CertificateValidation.from_dns(hostedzone)
        )

    ### LAMBDA AUTHORIZER ###

        authorizer_fn = _lambda.Function(
            self, 'authorizer',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('authorizer'),
            handler = 'authorizer.handler',
            environment = dict(
                ACCESS_TOKEN_COOKIE_NAME = Config.ACCESS_TOKEN_COOKIE_NAME
            ),
            timeout = Duration.seconds(30),
            memory_size = 256
        )

        self.authorizerlogs = _logs.LogGroup(
            self, 'authorizerlogs',
            log_group_name = '/aws/lambda/' + authorizer_fn.function_name,
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        authorizer_fn.add_to_role_policy(
            _iam.PolicyStatement(
                actions=['cognito-idp:GetUser'],
                resources=['*'],
            )
        )

    ### CUSTOM DOMAIN ###

        domain_name = _apigw.DomainName(
            self, 'domain',
            domain_name = Config.API_DOMAIN,
            certificate = acm
        )

    ### HTTP API ###

        api = _apigw.HttpApi(
            self, 'api',
            api_name = Config.API_GATEWAY_NAME,
            default_domain_mapping = _apigw.DomainMappingOptions(
                domain_name = domain_name
            )
        )

        self.apilogs = _logs.LogGroup(
            self, 'apilogs',
            log_group_name = f'/aws/apigateway/{api.api_id}',
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

    ### HTTP AUTHORIZER ###

        http_authorizer = _authorizers.HttpLambdaAuthorizer(
            'httpauthorizer',
            authorizer_fn,
            response_types = [_authorizers.HttpLambdaResponseType.SIMPLE],
            identity_source = ['$request.header.Cookie']
        )

    ### ROUTES ###

        # GET /
        api.add_routes(
            path = '/',
            methods = [_apigw.HttpMethod.GET],
            integration = _integrations.HttpLambdaIntegration(
                'rootintegration',
                root_lambda
            )
        )

        # GET /auth
        api.add_routes(
            path = '/auth',
            methods = [_apigw.HttpMethod.GET, _apigw.HttpMethod.POST],
            integration = _integrations.HttpLambdaIntegration(
                'authintegration',
                auth_lambda,
                payload_format_version = _apigw.PayloadFormatVersion.VERSION_2_0
            )
        )

        # GET /home
        api.add_routes(
            path = '/home',
            methods = [_apigw.HttpMethod.GET, _apigw.HttpMethod.POST],
            integration = _integrations.HttpLambdaIntegration(
                'homeintegration',
                home_lambda
            ),
            authorizer = http_authorizer
        )

    ### ROUTE53 ###

        _route53.ARecord(
            self, 'api_a_record',
            zone = hostedzone,
            target = _route53.RecordTarget.from_alias(
                _r53targets.ApiGatewayv2DomainProperties(
                    domain_name.regional_domain_name,
                    domain_name.regional_hosted_zone_id
                )
            ),
            record_name = Config.API_DOMAIN
        )

        _route53.AaaaRecord(
            self, 'api_aaaa_record',
            zone = hostedzone,
            target = _route53.RecordTarget.from_alias(
                _r53targets.ApiGatewayv2DomainProperties(
                    domain_name.regional_domain_name,
                    domain_name.regional_hosted_zone_id
                )
            ),
            record_name = Config.API_DOMAIN
        )

        self.api = api
        self.authorizer = authorizer_fn
