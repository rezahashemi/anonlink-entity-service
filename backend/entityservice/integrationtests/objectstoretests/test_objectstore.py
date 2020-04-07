import io
import json
import sys
from datetime import datetime

import boto3
import minio
import pytest
import requests
from minio import Minio

from minio.helpers import get_target_url, get_sha256_hexdigest, get_md5_base64digest

# Needs a patch
#from minio.signer import sign_v4

from urllib.parse import urlencode
#from minio.compat import urlencode

from entityservice.integrationtests.objectstoretests.miniopatch import sign_v4, parse_assume_role, assume_role
from entityservice.object_store import connect_to_object_store
from entityservice.settings import Config as config

restricted_upload_policy = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::uploads/2020/*"
      ],
      "Sid": "Upload-access-to-specific-bucket-only"
    }
  ]
} 
"""


class TestAssumeRole:

    def test_temp_credentials_minio(self):
        root_mc_client = connect_to_object_store()

        endpoint = 'minio:9000'
        restricted_mc_client = minio.Minio(
            endpoint,
            'newuser',
            'newuser123',
            region='us-east-1',
            secure=False
        )
        restricted_mc_client.set_app_info("anonlink-restricted", "development version")

        assert len(root_mc_client.list_buckets()) > 1
        with pytest.raises(minio.error.AccessDenied):
            restricted_mc_client.list_buckets()

        bucket_name = "uploads"

        # Should be able to put an object though
        restricted_mc_client.put_object(bucket_name, 'testobject', io.BytesIO(b'data'), length=4)

        temp_creds = assume_role(restricted_mc_client, Policy=restricted_upload_policy)

        newly_restricted_mc_client = Minio(endpoint, credentials=temp_creds, region='us-east-1', secure=False)
        with pytest.raises(minio.error.AccessDenied):
            newly_restricted_mc_client.list_buckets()

        # Note this put object worked with the earlier credentials
        # But should fail if we have applied the more restrictive policy
        with pytest.raises(minio.error.AccessDenied):
            newly_restricted_mc_client.put_object(bucket_name, 'testobject2', io.BytesIO(b'data'), length=4)

        # this path is allowed in the policy however
        newly_restricted_mc_client.put_object(bucket_name, '2020/testobject', io.BytesIO(b'data'), length=4)


    def test_create_temp_credentials_with_boto(self, upload_restricted_boto_session):

        sts_client = upload_restricted_boto_session.client('sts', endpoint_url="http://minio:9000")

        response = sts_client.assume_role(
            RoleArn="arn:xxx:xxx:xxx:xxxx",
            RoleSessionName="anything",
            Policy=restricted_upload_policy,
            DurationSeconds=3000,
        )
        assert 'Credentials' in response
        assert 'AccessKeyId' in response['Credentials']

