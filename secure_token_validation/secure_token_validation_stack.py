# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from aws_solutions_constructs.aws_alb_lambda import AlbToLambda, AlbToLambdaProps
from aws_cdk import (
    aws_lambda as _lambda,
    aws_events as events,
    aws_elasticloadbalancingv2 as alb,
    aws_cloudfront_origins as cloudfront,
    aws_cloudfront_origins as origins,
    Duration,
    aws_lambda_python_alpha as lambda_python,
    aws_ec2 as ec2,
    aws_stepfunctions_tasks as tasks,
    Stack,
    RemovalPolicy,
    custom_resources as cr,
    CfnOutput,
    aws_lambda_nodejs as nodejs,
)
import aws_cdk.aws_secretsmanager as secretsmanager
import aws_cdk.aws_cloudfront as cloudfront
import aws_cdk.aws_iam as iam
import aws_cdk.aws_kms as kms
import time
import aws_cdk.aws_lambda as _lambda

from constructs import Construct
import json


class SecureTokenValidationStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create a CloudFront Key-Value Store
        kvs = cloudfront.KeyValueStore(self, "TechSummitKVS")

        kvs.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create a KMS key for Secrets Manager
        kms_key = kms.Key(
            self,
            "TechSummitKMSKey",
            description="KMS key for Secrets Manager",
            enabled=True,
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create a Secrets Manager secret with a dummy password
        kvs_secret = secretsmanager.Secret(
            self,
            "TechSummitKVSSecret",
            description="Secret for token password",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template=json.dumps({"tokenPassword": "dummy_password"}),
                generate_string_key="tokenPassword",
                exclude_punctuation=True,
            ),
            encryption_key=kms_key,
        )
        kvs_secret.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create an IAM role for the Lambda function
        lambda_role = iam.Role(
            self,
            "TechSummitLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "SecretsManagerReadWrite"
                ),
            ],
        )

        # Add the inline policy to the Lambda role
        lambda_role.add_to_principal_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "cloudfront-keyvaluestore:UpdateKeys",
                    "cloudfront-keyvaluestore:PutKey",
                    "cloudfront-keyvaluestore:DescribeKeyValueStore",
                    "kms:Decrypt",
                ],
                resources=[kvs.key_value_store_arn, kms_key.key_arn],
            )
        )
        lambda_function = _lambda.Function(
            self,
            "TechSummitMoveSecretToKVS",
            code=_lambda.Code.from_asset("lambda"),
            function_name="RotateKVSSecret",
            runtime=_lambda.Runtime.NODEJS_20_X,
            handler="kvs_schedule.handler",
            environment={
                "KVS_ARN": kvs.key_value_store_arn,
                "SECRET_ARN": kvs_secret.secret_arn,
            },
            role=lambda_role,
        )

        # Create an IAM role for the Lambda function
        origin_lambda_role = iam.Role(
            self,
            "TechSummitOriginLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "SecretsManagerReadWrite"
                ),
            ],
        )
        # Add the inline policy to the Lambda role
        origin_lambda_role.add_to_principal_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:CreateNetworkInterface",
                    "ec2:DeleteNetworkInterface",
                    "ec2:DescribeInstances",
                    "ec2:AttachNetworkInterface",
                    "kms:Decrypt",
                ],
                resources=["*"],
            )
        )
        vpc = ec2.Vpc(
            self,
            "TechSummitVPC",
            max_azs=1,
            cidr="10.0.0.0/16",
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC, name="Public", cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
                    name="Private",
                    cidr_mask=24,
                ),
            ],
        )

        vpc.apply_removal_policy(RemovalPolicy.DESTROY)

        handler = lambda_python.PythonFunction(
            self,
            "TechSummitOriginLambda",
            entry="lambda_python",  # this should point to the root level of your applicative code
            runtime=_lambda.Runtime.PYTHON_3_12,
            vpc=vpc,
            timeout=Duration.seconds(15),
            index="dummy_origin.py",  # relative path to your main Python file, from `entry`
            handler="lambda_handler",  # which function to call in the main Python file
            environment={
                "SECRET_NAME": kvs_secret.secret_name,
                "VALIDATION_TOKEN": "VALID",
            },
            role=origin_lambda_role,
        )

        alb_with_lambda = AlbToLambda(
            self,
            "TechSummitALB",
            existing_lambda_obj=handler,
            listener_props=alb.BaseApplicationListenerProps(
                protocol=alb.ApplicationProtocol.HTTP, port=80
            ),
            public_api=True,
        )

        alb_with_lambda.load_balancer.apply_removal_policy(RemovalPolicy.DESTROY)

        kvs_key = f'"{kvs.key_value_store_id}"'

        function_source = f"""
'use strict';
let webcrypto = require('webcrypto');
let crypto = require('crypto')
import cf from 'cloudfront';

async function decrypt(encryptedBase64, keyBase64, ivBase64) {{
                        // Convert base64 to Uint8Array
                
                        const keyBuffer = Uint8Array.from(atob(keyBase64), c => c.charCodeAt(0));
                        const ivBuffer = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
                        const encryptedBuffer = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
                
                        // Import the key
                        const key = await webcrypto.subtle.importKey(
                            'raw',
                            keyBuffer,
                            {{ name: 'AES-CBC' }},
                            false,
                            ['decrypt']
                        );

                        // Decrypt the data
                        const decryptedBuffer = await webcrypto.subtle.decrypt(
                            {{ name: 'AES-CBC', iv: ivBuffer }},
                            key,
                            encryptedBuffer
                        );

                        // Convert decrypted buffer to string
                        const decoder = new TextDecoder();
                        const decryptedText = decoder.decode(decryptedBuffer);
                       
                        return decryptedText;                    
            }}

async function handler(event) {{
                
                const kvsId = {kvs_key};
                const kvsHandle = cf.kvs(kvsId);
                const keyBase64 = await kvsHandle.get("aes-key", {{ format: "string"}});
                let headers = event.request.headers
                
                const encryptedBase64 =headers['encrypted_data'] ? headers['encrypted_data'].value : '';
                const ivBase64 = headers['iv'] ? headers['iv'].value : '';
                
                // If both headers are empty, forward the request to the origin
               
                if (!encryptedBase64 && !ivBase64) {{                
                    return event.request;
                }}

                    let result = await decrypt(encryptedBase64, keyBase64, ivBase64);
                    if (result==="VALID")
                    {{
                        //send the command to the origin to skip token decryption and validation
                        event.request.querystring = "validate=0";
                        event.request.headers['result'] = {{value:result}}
                           return event.request;
                    }}
                    else
                    {{
                        var response = {{
                                            statusCode: 401,
                                            statusDescription: 'Unauthorized',
                                            headers: {{
                                                'cache-control': {{ value: 'no-store' }}
                                            }}
                                        }}
                         event.response = response;
                         return event.response;
                    }}
                
            }}
        """
        clouf_front_function = cloudfront.Function(
            self,
            "TlvSummitCfFunction",
            code=cloudfront.FunctionCode.from_inline(function_source),
            runtime=cloudfront.FunctionRuntime.JS_2_0,
            key_value_store=kvs,
        )

        # cloudfront distribution that is connected to load balancer
        cloudfront_distribution = cloudfront.Distribution(
            self,
            "TechSummitCfDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.LoadBalancerV2Origin(
                    alb_with_lambda.load_balancer,
                    protocol_policy=cloudfront.OriginProtocolPolicy.MATCH_VIEWER,
                ),
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
                function_associations=[
                    cloudfront.FunctionAssociation(
                        function=clouf_front_function,
                        event_type=cloudfront.FunctionEventType.VIEWER_REQUEST,
                    )
                ],
            ),
        )
        cloudfront_distribution.apply_removal_policy(RemovalPolicy.DESTROY)

        cr_role = iam.Role(
            self,
            "TechSummitCrRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
        )
        cr_role.add_to_principal_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=["*"],
            )
        )

        cr.AwsCustomResource(
            self,
            "TvlSummitInvokeLambda",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": lambda_function.function_name,
                    "InvocationType": "Event",
                },
                physical_resource_id=cr.PhysicalResourceId.of(str(int(time.time()))),
            ),
            role=cr_role,
        )
        distribution_domain_name = cloudfront_distribution.distribution_domain_name
        handler.add_environment("DISTR_DOMAIN_NAME", distribution_domain_name)

        CfnOutput(self, "StartURL", value=f"http://{distribution_domain_name}")
