from aws_cdk import (
    Duration,
    RemovalPolicy,
    SecretValue,
    Stack,
    custom_resources as _cr,
    aws_certificatemanager as _acm,
    aws_cognito as _cognito,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_route53 as _route53,
    aws_route53_targets as _r53targets,
    aws_secretsmanager as _secrets,
    aws_ssm as _ssm
)

from constructs import Construct
from config import Config

class OsintIdp(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account

        layer = _ssm.StringParameter.from_string_parameter_attributes(
            self, 'layer',
            parameter_name = Config.REQUESTS_LAYER_PARAM
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self, 'requests',
            layer_version_arn = layer.string_value
        )

    ### HOSTZONE ###

        hostzone = _cr.AwsCustomResource(
            self, 'hostzone',
            on_update = _cr.AwsSdkCall(
                service = 'SSM',
                action = 'getParameter',
                parameters = {
                    'Name': Config.ROUTE53_PARAM
                },
                region = Config.DNS_REGION,
                physical_resource_id = _cr.PhysicalResourceId.of(Config.ROUTE53_PARAM)
            ),
            policy = _cr.AwsCustomResourcePolicy.from_statements([
                _iam.PolicyStatement(
                    actions = [
                        'ssm:GetParameter'
                    ],
                    resources = [
                        'arn:aws:ssm:'+Config.DNS_REGION+':'+str(account)+':parameter'+Config.ROUTE53_PARAM
                    ]
                )
            ])
        )

        hostedzone = _route53.HostedZone.from_hosted_zone_attributes(
            self, 'hostedzone',
            hosted_zone_id = hostzone.get_response_field('Parameter.Value'),
            zone_name = Config.DOMAIN
        )

    ### ACM CERTIFICATE ###

        acmarn = _cr.AwsCustomResource(
            self, 'acmarn',
            on_update = _cr.AwsSdkCall(
                service = 'SSM',
                action = 'getParameter',
                parameters = {
                    'Name': Config.ACM_PARAM
                },
                region = Config.DNS_REGION,
                physical_resource_id = _cr.PhysicalResourceId.of(Config.ACM_PARAM)
            ),
            policy = _cr.AwsCustomResourcePolicy.from_statements([
                _iam.PolicyStatement(
                    actions = [
                        'ssm:GetParameter'
                    ],
                    resources = [
                        'arn:aws:ssm:'+Config.DNS_REGION+':'+str(account)+':parameter'+Config.ACM_PARAM
                    ]
                )
            ])
        )

        acm = _acm.Certificate.from_certificate_arn(
            self, 'acm',
            certificate_arn = acmarn.get_response_field('Parameter.Value')
        )

    ### COGNITO USER POOL ###

        userpool = _cognito.UserPool(
            self, 'userpool',
            user_pool_name = Config.COGNITO_USER_POOL_NAME,
            deletion_protection = True,
            removal_policy = RemovalPolicy.RETAIN,
            feature_plan = _cognito.FeaturePlan.ESSENTIALS,
            self_sign_up_enabled = True,
            sign_in_aliases = _cognito.SignInAliases(
                email = True
            ),
            email = _cognito.UserPoolEmail.with_ses(
                from_email = Config.COGNITO_FROM_EMAIL
            ),
            sign_in_case_sensitive = False,
            sign_in_policy = _cognito.SignInPolicy(
                allowed_first_auth_factors = _cognito.AllowedFirstAuthFactors(
                    password = True,
                    email_otp = True,
                    passkey = True
                )
            ),
            auto_verify = _cognito.AutoVerifiedAttrs(
                email = False,
                phone = False
            ),
            account_recovery = _cognito.AccountRecovery.NONE,
            device_tracking = _cognito.DeviceTracking(
                challenge_required_on_new_device = True,
                device_only_remembered_on_user_prompt = False
            ),
            passkey_user_verification = _cognito.PasskeyUserVerification.PREFERRED,
            mfa = _cognito.Mfa.OFF
        )

    ### COGNITO APP CLIENT ###

        appclient = userpool.add_client(
            'appclient',
            user_pool_client_name = Config.COGNITO_APP_CLIENT_NAME,
            prevent_user_existence_errors = True,
            auth_flows = _cognito.AuthFlow(
                user = True,
                user_srp = True
            ),
            o_auth = _cognito.OAuthSettings(
                default_redirect_uri = Config.COGNITO_REDIRECT_URI,
                callback_urls = [
                    Config.COGNITO_REDIRECT_URI
                ],
                logout_urls = [
                    Config.COGNITO_REDIRECT_URI
                ],
                flows = _cognito.OAuthFlows(
                    authorization_code_grant = True
                ),
                scopes = [
                    _cognito.OAuthScope.OPENID
                ]
            ),
            generate_secret = True,
            access_token_validity = Duration.hours(1),
            id_token_validity = Duration.hours(1)
        )

    #### COGNITO BRANDING ###

        branding_settings = {
            'categories': {
                'auth': {
                    'authMethodOrder': [[
                        {
                            'display': 'INPUT',
                            'type': 'USERNAME_PASSWORD'
                        }
                    ]]
                },
                'form': {
                    'displayGraphics': False,
                    'instructions': {
                        'enabled': False
                    },
                    'languageSelector': {
                        'enabled': False
                    },
                    'location': {
                        'horizontal': 'CENTER',
                        'vertical': 'CENTER'
                    },
                    'sessionTimerDisplay': 'NONE'
                },
                'global': {
                    'colorSchemeMode': 'LIGHT',
                    'pageFooter': {
                        'enabled': False
                    },
                    'pageHeader': {
                        'enabled': False
                    },
                    'spacingDensity': 'REGULAR'
                },
                'signUp': {
                    'acceptanceElements': [
                        {
                            'enforcement': 'NONE',
                            'textKey': 'en'
                        }
                    ]
                }
            },
            'componentClasses': {
                'buttons': {
                    'borderRadius': 999.0
                },
                'focusState': {
                    'lightMode': {
                        'borderColor': '0e7490ff'
                    }
                },
                'input': {
                    'borderRadius': 16.0,
                    'lightMode': {
                        'defaults': {
                            'backgroundColor': 'ffffffff',
                            'borderColor': 'cbd5e1ff'
                        },
                        'placeholderColor': '486581ff'
                    }
                },
                'inputDescription': {
                    'lightMode': {
                        'textColor': '486581ff'
                    }
                },
                'inputLabel': {
                    'lightMode': {
                        'textColor': '10233cff'
                    }
                },
                'link': {
                    'lightMode': {
                        'defaults': {
                            'textColor': '0e7490ff'
                        },
                        'hover': {
                            'textColor': '155e75ff'
                        }
                    }
                }
            },
            'components': {
                'alert': {
                    'borderRadius': 12.0,
                    'lightMode': {
                        'error': {
                            'backgroundColor': 'fff7f7ff',
                            'borderColor': 'd91515ff'
                        }
                    }
                },
                'form': {
                    'backgroundImage': {
                        'enabled': False
                    },
                    'borderRadius': 16.0,
                    'lightMode': {
                        'backgroundColor': 'ffffffff',
                        'borderColor': 'dbe4eeff'
                    },
                    'logo': {
                        'enabled': False,
                        'formInclusion': 'IN',
                        'location': 'CENTER',
                        'position': 'TOP'
                    }
                },
                'pageBackground': {
                    'image': {
                        'enabled': False
                    },
                    'lightMode': {
                        'color': 'f4f7fbff'
                    }
                },
                'pageText': {
                    'lightMode': {
                        'bodyColor': '486581ff',
                        'descriptionColor': '486581ff',
                        'headingColor': '10233cff'
                    }
                },
                'primaryButton': {
                    'lightMode': {
                        'active': {
                            'backgroundColor': '155e75ff',
                            'textColor': 'ffffffff'
                        },
                        'defaults': {
                            'backgroundColor': '0e7490ff',
                            'textColor': 'ffffffff'
                        },
                        'hover': {
                            'backgroundColor': '155e75ff',
                            'textColor': 'ffffffff'
                        }
                    }
                },
                'secondaryButton': {
                    'lightMode': {
                        'active': {
                            'backgroundColor': 'e6f4f8ff',
                            'borderColor': '155e75ff',
                            'textColor': '155e75ff'
                        },
                        'defaults': {
                            'backgroundColor': 'ffffffff',
                            'borderColor': '0e7490ff',
                            'textColor': '0e7490ff'
                        },
                        'hover': {
                            'backgroundColor': 'f2fbfdff',
                            'borderColor': '155e75ff',
                            'textColor': '155e75ff'
                        }
                    }
                }
            }
        }

        self.branding = _cognito.CfnManagedLoginBranding(
            self, 'branding',
            user_pool_id = userpool.user_pool_id,
            client_id = appclient.user_pool_client_id,
            return_merged_resources = False,
            settings = branding_settings,
            use_cognito_provided_values = False
        )

    ### COGNITO DOMAIN ###

        domain = userpool.add_domain(
            'domain',
            custom_domain = _cognito.CustomDomainOptions(
                domain_name = Config.SUBDOMAIN,
                certificate = acm
            ),
            managed_login_version = _cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN
        )

    ### COGNITO DNS ###

        self.cognitofour = _route53.ARecord(
            self, 'cognitofour',
            zone = hostedzone,
            record_name = Config.SUBDOMAIN,
            target = _route53.RecordTarget.from_alias(
                _r53targets.UserPoolDomainTarget(domain)
            )
        )

        self.cognitofsix = _route53.AaaaRecord(
            self, 'cognitofsix',
            zone = hostedzone,
            record_name = Config.SUBDOMAIN,
            target = _route53.RecordTarget.from_alias(
                _r53targets.UserPoolDomainTarget(domain)
            )
        )

    ### SECRET MANAGER ###

        credentials = _secrets.Secret(
            self, 'credentials',
            secret_name = 'credentials',
            secret_object_value = {
                'CLIENT_ID': SecretValue.unsafe_plain_text(appclient.user_pool_client_id),
                'CLIENT_SECRET': appclient.user_pool_client_secret
            }
        )

    ### IAM ROLE ###

        role = _iam.Role(
            self, 'role',
            assumed_by = _iam.ServicePrincipal(
                'lambda.amazonaws.com'
            )
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'apigateway:GET'
                ],
                resources = [
                    '*'
                ]
            )
        )

        credentials.grant_read(role)

    ### AUTH LAMBDA FUNCTION ###

        auth = _lambda.Function(
            self, 'auth',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('auth'),
            handler = 'auth.handler',
            environment = dict(
                CREDENTIALS_SECRET_ARN = credentials.secret_arn,
                HOME_ENDPOINT = f"https://{Config.API_DOMAIN}/home",
                COGNITO_DOMAIN = f"https://{Config.SUBDOMAIN}",
                COGNITO_REDIRECT_URI = Config.COGNITO_REDIRECT_URI,
                CDN_BASE_URL = Config.CDN_BASE_URL
            ),
            timeout = Duration.seconds(30),
            memory_size = 256,
            role = role,
            layers = [
                requests
            ]
        )

        self.authlogs = _logs.LogGroup(
            self, 'authlogs',
            log_group_name = '/aws/lambda/'+auth.function_name,
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        # Export lambdas for API stack attachment
        self.auth = auth


    ### ROOT LAMBDA FUNCTION ###

        root = _lambda.Function(
            self, 'root',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('root'),
            handler = 'root.handler',
            environment = dict(
                CLIENT_ID = appclient.user_pool_client_id,
                COGNITO_DOMAIN = f"https://{Config.SUBDOMAIN}",
                COGNITO_REDIRECT_URI = Config.COGNITO_REDIRECT_URI,
                CDN_BASE_URL = Config.CDN_BASE_URL
            ),
            timeout = Duration.seconds(3),
            memory_size = 128,
            role = role
        )

        self.rootlogs = _logs.LogGroup(
            self, 'rootlogs',
            log_group_name = '/aws/lambda/'+root.function_name,
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        # Export root lambda for API stack attachment
        self.root = root

        # Home lambda is not created here; should be created and attached in app.py if needed
