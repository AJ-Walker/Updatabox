import boto3
from config import S3_BUCKET, S3_KEY, S3_SECRET
from flask import session
from botocore.exceptions import ClientError
from models import User
from flask_login import current_user

def _get_s3_resource():
    if S3_KEY and S3_SECRET:
        return boto3.resource(
            's3',
            aws_access_key_id=S3_KEY,
            aws_secret_access_key=S3_SECRET
        )
    else:
        return boto3.resource('s3')


def get_bucket():
    # s3_resource = _get_s3_resource()
    s3_res = boto3.resource('s3')
    user = User.query.get_or_404(current_user.id)

    return s3_res.Bucket(user.bucket_name)

def get_bucket_v2():
    get_last_modified = lambda obj: int(obj['LastModified'].timestamp())
    user = User.query.get_or_404(current_user.id)

    s3 = boto3.client('s3')

    objs = s3.list_objects_v2(Bucket=user.bucket_name)['KeyCount']
    if objs != 0:
        objects = s3.list_objects_v2(Bucket=user.bucket_name)['Contents']
        return sorted(objects, key=get_last_modified, reverse=True)
    else:
        files = {}
        return files
    

def get_buckets_list():
    client = boto3.client('s3')
    return client.list_buckets().get('Buckets')

def create_s3_bucket(bucket_name):
    s3_res = boto3.resource('s3')
    try:
        rsp = s3_res.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={
        'LocationConstraint': 'your-availabilty-zone'})
    except ClientError as err:
        print(err)
        return False
    return True

