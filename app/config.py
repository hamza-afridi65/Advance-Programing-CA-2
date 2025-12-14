import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Flask configuration class."""
    MONGO_URI = os.getenv("MONGO_URI")
    SECRET_KEY = os.getenv("SECRET_KEY", "devkey")

    # AWS + CloudTrail
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    CLOUDTRAIL_S3_BUCKET = os.getenv("CLOUDTRAIL_S3_BUCKET")
    CLOUDTRAIL_S3_PREFIX = os.getenv("CLOUDTRAIL_S3_PREFIX", "")

    # Login creds (local/dev)
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")