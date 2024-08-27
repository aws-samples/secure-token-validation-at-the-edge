#!/usr/bin/env python3
import os
from aws_solutions_constructs.aws_eventbridge_lambda import EventbridgeToLambda, EventbridgeToLambdaProps
from aws_cdk import (
    aws_lambda as _lambda,
    aws_events as events,
    Duration,
    Stack
)
import aws_cdk as cdk

from secure_token_validation.secure_token_validation_stack import SecureTokenValidationStack


app = cdk.App()
SecureTokenValidationStack(app, "SecureTokenValidationStack", env=cdk.Environment( region='us-east-1')
    # If you don't specify 'env', this stack will be environment-agnostic.
    # Account/Region-dependent features and context lookups will not work,
    # but a single synthesized template can be deployed anywhere.

    # Uncomment the next line to specialize this stack for the AWS Account
    # and Region that are implied by the current CLI configuration.

 

    # Uncomment the next line if you know exactly what Account and Region you
    # want to deploy the stack to. */

    

    # For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html
    )

app.synth()
