import aws_cdk as core
import aws_cdk.assertions as assertions

from secure_token_validation.secure_token_validation_stack import SecureTokenValidationStack

# example tests. To run these tests, uncomment this file along with the example
# resource in secure_token_validation/secure_token_validation_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = SecureTokenValidationStack(app, "secure-token-validation")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
