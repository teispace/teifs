"""Makes the suite's second user and writes the suite's configuration.

The suite's alt user stands for another AWS account: it may do only what a bucket's
policy or ACL grants it. TeiFS has one account per drive, so alt is an IAM user there
with no policies of its own, which is what another account's user is on someone else's
bucket. Its key goes into the configuration file only, never on a command line.

Usage: users.py TEMPLATE OUTPUT, with S3TESTS_PORT, S3TESTS_ACCESS_KEY and
S3TESTS_SECRET_KEY (the root user's) in the environment.
"""

import os
import sys

import boto3

ALT = "s3-tests-alt"


def main(template, output):
    port = os.environ["S3TESTS_PORT"]
    access_key = os.environ["S3TESTS_ACCESS_KEY"]
    secret_key = os.environ["S3TESTS_SECRET_KEY"]
    iam = boto3.client(
        "iam",
        endpoint_url=f"http://127.0.0.1:{port}",
        region_name="us-east-1",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )
    iam.create_user(UserName=ALT)
    # The suite's cleanup lists buckets as every user; the root user has deleted them
    # all by then.
    iam.put_user_policy(
        UserName=ALT,
        PolicyName="list-buckets",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Action":"s3:ListAllMyBuckets","Resource":"*"}]}',
    )
    alt = iam.create_access_key(UserName=ALT)["AccessKey"]
    config = open(template).read()
    for name, value in [
        ("@PORT@", port),
        ("@ACCESS_KEY@", access_key),
        ("@SECRET_KEY@", secret_key),
        ("@ALT_ACCESS_KEY@", alt["AccessKeyId"]),
        ("@ALT_SECRET_KEY@", alt["SecretAccessKey"]),
    ]:
        config = config.replace(name, value)
    with open(output, "w") as out:
        out.write(config)


if __name__ == "__main__":
    main(*sys.argv[1:])
