import json
import gzip
from io import BytesIO, TextIOWrapper

import boto3
from flask import current_app


def read_cloudtrail_from_s3():
    """
    Read CloudTrail log files from S3 and return a list of events.
    This assumes that AWS credentials and bucket/prefix are configured.
    """
    bucket = current_app.config.get("CLOUDTRAIL_S3_BUCKET")
    prefix = current_app.config.get("CLOUDTRAIL_S3_PREFIX", "")

    if not bucket:
        print("CLOUDTRAIL_S3_BUCKET not configured, returning empty list.")
        return []

    aws_access_key_id = current_app.config.get("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = current_app.config.get("AWS_SECRET_ACCESS_KEY")
    aws_region = current_app.config.get("AWS_DEFAULT_REGION", "us-east-1")

    # Create S3 client (uses explicit keys from config)
    s3 = boto3.client(
        "s3",
        region_name=aws_region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )

    events = []

    # List objects under the prefix
    paginator = s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

    for page in pages:
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json") and not key.endswith(".json.gz"):
                continue

            # Download the object
            response = s3.get_object(Bucket=bucket, Key=key)
            body = response["Body"].read()

            # CloudTrail files are often gzipped
            if key.endswith(".gz"):
                with gzip.GzipFile(fileobj=BytesIO(body)) as gz:
                    text = gz.read().decode("utf-8")
                    data = json.loads(text)
            else:
                data = json.loads(body.decode("utf-8"))

            if isinstance(data, dict) and "Records" in data:
                events.extend(data["Records"])

    return events
