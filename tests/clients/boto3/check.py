"""boto3 against TeiFS: what applications do with it."""

import hashlib
import os
import urllib.error
import urllib.request

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config

bucket = os.environ["BUCKET"]
# Signature Version 4 for presigned links too, as AWS recommends: boto3 still makes
# Version 2 links by default, which TeiFS (like AWS for its newer buckets) refuses
# unless `--allow-sigv2`.
s3 = boto3.client(
    "s3",
    endpoint_url=os.environ["ENDPOINT"],
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)


def step(text):
    print("==", text, flush=True)


step("bucket")
s3.create_bucket(Bucket=bucket)
assert bucket in [b["Name"] for b in s3.list_buckets()["Buckets"]]

step("put, get, head with metadata and a checksum")
s3.put_object(
    Bucket=bucket,
    Key="small.txt",
    Body=open("small.txt", "rb"),
    Metadata={"owner": "boto3"},
    ChecksumAlgorithm="SHA256",
)
got = s3.get_object(Bucket=bucket, Key="small.txt")
assert got["Body"].read() == open("small.txt", "rb").read()
head = s3.head_object(Bucket=bucket, Key="small.txt", ChecksumMode="ENABLED")
assert head["Metadata"] == {"owner": "boto3"}
assert "ChecksumSHA256" in head

step("multipart upload through the transfer manager, and a ranged read")
config = TransferConfig(multipart_threshold=5 * 2**20, multipart_chunksize=5 * 2**20)
s3.upload_file("big.bin", bucket, "big.bin", Config=config)
s3.download_file(bucket, "big.bin", "big.back", Config=config)
digest = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
assert digest("big.bin") == digest("big.back")
part = s3.get_object(Bucket=bucket, Key="big.bin", Range="bytes=100-199")["Body"].read()
assert part == open("big.bin", "rb").read()[100:200]

step("copy, list with a paginator, delete many")
s3.copy_object(Bucket=bucket, Key="copy.txt", CopySource={"Bucket": bucket, "Key": "small.txt"})
for i in range(25):
    s3.put_object(Bucket=bucket, Key=f"many/{i:03}", Body=b"x")
pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="many/", PaginationConfig={"PageSize": 10})
keys = [o["Key"] for page in pages for o in page.get("Contents", [])]
assert keys == [f"many/{i:03}" for i in range(25)], keys
s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys]})

step("presigned GET and PUT")
url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "small.txt"}, ExpiresIn=60)
assert urllib.request.urlopen(url).read() == open("small.txt", "rb").read()
url = s3.generate_presigned_url("put_object", Params={"Bucket": bucket, "Key": "via-link"}, ExpiresIn=60)
urllib.request.urlopen(urllib.request.Request(url, data=b"linked", method="PUT")).read()
assert s3.get_object(Bucket=bucket, Key="via-link")["Body"].read() == b"linked"

step("a default (Version 2) presigned link is refused, saying why")
legacy = boto3.client("s3", endpoint_url=os.environ["ENDPOINT"], config=Config(s3={"addressing_style": "path"}))
url = legacy.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "small.txt"}, ExpiresIn=60)
assert "AWSAccessKeyId=" in url, url
try:
    urllib.request.urlopen(url)
    raise AssertionError("a Signature Version 2 link was accepted")
except urllib.error.HTTPError as err:
    assert err.code == 403 and b"Signature Version 2" in err.read(), err

step("conditional write")
try:
    s3.put_object(Bucket=bucket, Key="small.txt", Body=b"no", IfNoneMatch="*")
    raise AssertionError("an existing key was overwritten")
except s3.exceptions.ClientError as err:
    assert err.response["Error"]["Code"] == "PreconditionFailed", err

step("empty and remove the bucket")
for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
    for o in page.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=o["Key"])
s3.delete_bucket(Bucket=bucket)
print("ok")
