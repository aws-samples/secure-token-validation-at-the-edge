# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import boto3
import json
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import binascii
import os
import random
import time

# Create a Secrets Manager client
session = boto3.session.Session()
secret_client = session.client(service_name="secretsmanager")


def get_secret():
    secret_name = os.environ.get("SECRET_NAME")

    get_secret_value_response = secret_client.get_secret_value(SecretId=secret_name)
    secret = get_secret_value_response["SecretString"]
    password = json.loads(secret)["tokenPassword"]

    return password


def encrypt(data, key):
    # Convert to bytes
    encryption_key = key.encode("utf-8")

    iv = b"0123456789abcdef"  # Example IV; should be random in real use

    # Create cipher object and encrypt data
    cipher = Cipher(
        algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Padding the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the encrypted data and IV in base64
    encrypted_data_b64 = b64encode(encrypted_data).decode("utf-8")
    iv_b64 = b64encode(iv).decode("utf-8")

    return encrypted_data_b64, iv_b64


def build_response(encrypted_data_b64, iv_b64, http_status, body):
    return {
        "statusCode": http_status,
        "headers": {
            "Content-Type": "text/plain",
            "iv": iv_b64,
            "encrypted_data": encrypted_data_b64,
        },
        "isBase64Encoded": False,
        "body": body,
    }


# simulate some work
def do_work():
    # Randomly choose between 1 and 2 seconds
    wait_time = random.choice([1, 2])
    # Pause execution for the chosen time
    time.sleep(wait_time)


def decrypt(encrypted_data_b64, iv_b64, encryption_key_str):
    encrypted_data_bytes = b64decode(encrypted_data_b64)
    iv_bytes = b64decode(iv_b64)

    # Convert to bytes
    encryption_key = encryption_key_str.encode("utf-8")

    # Create a cipher object for decryption
    cipher_decrypt = Cipher(
        algorithms.AES(encryption_key), modes.CBC(iv_bytes), backend=default_backend()
    )
    decryptor = cipher_decrypt.decryptor()

    # Decrypt the data
    decrypted_padded_data = (
        decryptor.update(encrypted_data_bytes) + decryptor.finalize()
    )

    # Remove the padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Convert back to string
    decrypted_text = decrypted_data.decode("utf-8")

    return decrypted_text


def lambda_handler(event, context):
    # get the token from Secret Manager

    password = get_secret()

    validate_header = event.get("queryStringParameters", {}).get("validate")

    # no command provided. Encrypt validation token and send back as CURL command
    if not validate_header:
        # Encode the encrypted message and IV in base64
        encrypted_data_b64, iv_b64 = encrypt(
            os.environ.get("VALIDATION_TOKEN").encode("utf-8"), password
        )

        distribution_domain_name = os.environ.get("DISTR_DOMAIN_NAME")

        return build_response(
            encrypted_data_b64,
            iv_b64,
            200,
            f'curl -v -H "iv: {iv_b64}" -H "encrypted_data: {encrypted_data_b64}" "http://{distribution_domain_name}"',
        )

    # This is what happens if you don't use CLludFront function
    # Each request needs to be decrypted and validated
    # Once CloudFront function is implemented you can test this only by invoking ALB url
    elif validate_header == "1":
        iv = event["headers"]["iv"]
        encrypted_data = event["headers"]["encrypted_data"]
        decrypted_text = decrypt(encrypted_data, iv, password)

        if decrypted_text == os.environ.get("VALIDATION_TOKEN"):
            do_work()
            return build_response(encrypted_data, iv, 200, "The request is valid")

        else:
            return build_response(encrypted_data, iv, 400, "The request is not valid")

    # Skip token validation. The token should be already validated by CloudFront function.
    else:  # validate_header == "0":
        do_work()
        return build_response("None", "None", 200, "Work done!!")
