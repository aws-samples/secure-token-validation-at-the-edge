// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import "@aws-sdk/signature-v4-crt";
import { CloudFrontKeyValueStoreClient, PutKeyCommand, DescribeKeyValueStoreCommand } from "@aws-sdk/client-cloudfront-keyvaluestore"; 
import { GetSecretValueCommand, SecretsManagerClient} from "@aws-sdk/client-secrets-manager";

const cloudFrontKeyValueStoreClient = new CloudFrontKeyValueStoreClient();
const secretsManagerClient = new SecretsManagerClient();

const encryptToBase64 = (plainText) => {
  const bufferedText = Buffer.from(plainText);
  const base64Text = bufferedText.toString('base64');
  return base64Text;
};

async function getSecretValue(secretArn) {
  const data = await secretsManagerClient.send(new GetSecretValueCommand({ SecretId: secretArn }));
  return data.SecretString;
}

async function pushToKeyValueStore(kvsArn, key, secret) {
  let command = new DescribeKeyValueStoreCommand({ KvsARN: kvsArn });
  const { ETag } = await cloudFrontKeyValueStoreClient.send(command);
  
  command = new PutKeyCommand({ 
    KvsARN: kvsArn,
    Key: key,
    Value: secret,
    IfMatch: ETag,
  });

  await cloudFrontKeyValueStoreClient.send(command);
}

export const handler = async () => {
  const secretValue = await getSecretValue(process.env.SECRET_ARN);
  
  const secretObject = JSON.parse(secretValue);
  const secretKey = secretObject.tokenPassword;
  
  await pushToKeyValueStore(process.env.KVS_ARN, 'aes-key', encryptToBase64(secretKey));

  return { statusCode: 200, body: 'Secret value encrypted and pushed to Key-Value Store' };
};
