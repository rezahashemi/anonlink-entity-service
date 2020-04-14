import datetime
import sys
import json

import opentracing
from flask import request

import requests

import entityservice.database as db
from entityservice.miniopatch import assume_role
from entityservice.object_store import connect_to_upload_object_store
from entityservice.views import bind_log_and_span, precheck_upload_token
from entityservice.views.serialization import ObjectStoreCredentials


def _get_upload_policy(bucket_name="uploads", path="*"):

    restricted_upload_policy = {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": [
            "s3:PutObject"
          ],
          "Effect": "Allow",
          "Resource": [
            "arn:aws:s3:::{}/{}".format(bucket_name, path),
            "arn:aws:s3:::{}/{}/*".format(bucket_name, path),
          ],
          "Sid": "Upload-access-to-specific-bucket-only"
        }
      ]
    }

    return json.dumps(restricted_upload_policy)


def authorize_external_upload(project_id):

    headers = request.headers

    log, parent_span = bind_log_and_span(project_id)

    log.info("Authorizing external upload")
    token = precheck_upload_token(project_id, headers, parent_span)
    with db.DBConn() as conn:
        dp_id = db.get_dataprovider_id(conn, token)

    log.debug(f"Update token is valid")
    with opentracing.tracer.start_span('assume-role-request', child_of=parent_span) as span:
        client = connect_to_upload_object_store(trace=sys.stdout)
        client.set_app_info("anonlink", "development version")

        bucket_name = "uploads"
        # Note these credentials are very locked down - our upload client can't even check buckets exist
        credential_values, expiry = assume_role(client, Policy=_get_upload_policy(bucket_name, path=f"{project_id}/{dp_id}"))
        log.info("Created temporary object store credentials")
        log.debug(credential_values)
    credentials_json = ObjectStoreCredentials().dump(credential_values)

    # Convert datetime to ISO 8601 string
    credentials_json["Expiration"] = expiry.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

    return {
        "credentials": credentials_json,
        "upload": {
            # TODO changeme
            "endpoint": "localhost:9000",
            "bucket": bucket_name,
            "path": f"{project_id}/{dp_id}"
        }
    }
