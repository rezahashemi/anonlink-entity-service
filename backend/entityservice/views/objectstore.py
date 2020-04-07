import datetime
import sys
from flask import request

import requests

from minio.error import ResponseError
from minio.helpers import get_target_url, get_sha256_hexdigest, get_md5_base64digest
from minio.signer import sign_v4

from entityservice.object_store import create_bucket, connect_to_object_store
from entityservice.views import bind_log_and_span, precheck_upload_token


def authorize_external_upload(project_id):

    headers = request.headers

    log, parent_span = bind_log_and_span(project_id)

    log.info("Authorizing external upload")
    token = precheck_upload_token(project_id, headers, parent_span)
    log.info(f"Token is valid - {token}")

    client = connect_to_object_store()

    # TODO This should be done during a server init step not here
    bucket_name = "uploads"
    create_bucket(client, bucket_name)

    client.set_app_info("anonlink", "development version")
    client.trace_on(sys.stdout)

    query = {
        "Version": "2011-06-15",
        "Action": "AssumeRole",
    }
    headers = {
        'Content-Length': 0,
        'User-Agent': "Anonlink"
    }
    content = ""

    # Note using client._url_open fails. :-/


    # Construct target url.
    region = client._get_bucket_region(bucket_name)
    url = get_target_url(client._endpoint_url, bucket_name=bucket_name,
                         object_name=None, bucket_region=region,
                         query=query)

    # Get signature headers if any.
    content_sha256_hex = get_sha256_hexdigest(content)
    headers['Content-Md5'] = get_md5_base64digest(content)
    signed_headers = sign_v4("POST", url, region, headers, client._credentials, content_sha256=content_sha256_hex)

    response = client._http.urlopen("POST", url,
                                  body=content,
                                  headers=signed_headers,
                                  preload_content=True)

    data = response.data.decode('utf-8')

    log.info(data)

    return "hi"