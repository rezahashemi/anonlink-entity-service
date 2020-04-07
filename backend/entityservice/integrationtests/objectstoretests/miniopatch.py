from datetime import datetime
import hmac
import hashlib
import xml.etree.ElementTree
from urllib.parse import urlencode

from minio.credentials import Static, Credentials
from minio.fold_case_dict import FoldCaseDict
from minio.compat import urlsplit
from minio.helpers import get_sha256_hexdigest

from minio.signer import _UNSIGNED_PAYLOAD, _SIGN_V4_ALGORITHM, remove_default_port, get_signed_headers, \
    generate_canonical_request


def assume_role(mc, RoleArn=None, RoleSessionName=None, Policy=None, DurationSeconds=None):
    """
    Generate temporary credentials using AssumeRole STS API.

    https://github.com/minio/minio/blob/master/docs/sts/assume-role.md

    :param mc: Minio client
    :param RoleArn:
    :param RoleSessionName:
    :param Policy:
    :param DurationSeconds:
    :return: A :class:`Credentials` provider with the temporary credentials.
    """
    region = 'us-east-1'
    query = {
        "Action": "AssumeRole",
        "Version": "2011-06-15",
        "RoleArn": "arn:xxx:xxx:xxx:xxxx" if RoleArn is None else RoleArn,
        "RoleSessionName": "anything" if RoleSessionName is None else RoleSessionName,
    }

    # Add optional elements to the request
    if Policy is not None:
        query["Policy"] = Policy

    if DurationSeconds is not None:
        query["DurationSeconds"] = str(DurationSeconds)

    url = mc._endpoint_url + "/"
    content = urlencode(query)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'User-Agent': mc._user_agent
    }

    # Create signature headers
    content_sha256_hex = get_sha256_hexdigest(content)

    signed_headers = sign_v4("POST", url, region, headers,
                             mc._credentials,
                             content_sha256=content_sha256_hex,
                             request_datetime=datetime.utcnow(),
                             service='sts'
                             )

    response = mc._http.urlopen("POST", url, body=content, headers=signed_headers, preload_content=True)

    # Parse the XML Response - getting the credentials as a Minio Credentials provider
    return parse_assume_role(response.data)



def generate_signing_key(date, region, secret_key, service="s3"):
    """
    Generate signing key.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param secret_key: Secret access key.
    """
    formatted_date = date.strftime("%Y%m%d")

    key1_string = 'AWS4' + secret_key
    key1 = key1_string.encode('utf-8')
    key2 = hmac.new(key1, formatted_date.encode('utf-8'),
                    hashlib.sha256).digest()
    key3 = hmac.new(key2, region.encode('utf-8'), hashlib.sha256).digest()
    key4 = hmac.new(key3, service.encode('utf-8'), hashlib.sha256).digest()

    return hmac.new(key4, 'aws4_request'.encode('utf-8'),
                    hashlib.sha256).digest()


def generate_scope_string(date, region, service_name):
    """
    Generate scope string.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param service_name: Service for scope string, e.g., "s3".
    """
    formatted_date = date.strftime("%Y%m%d")
    scope = '/'.join([formatted_date,
                      region,
                      service_name,
                      'aws4_request'])
    return scope


def generate_credential_string(access_key, date, region, service):
    """
    Generate credential string.

    :param access_key: Server access key.
    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param service: Service to scope credentials to.
    """
    return access_key + '/' + generate_scope_string(date, region, service)


def generate_authorization_header(access_key, date, region,
                                  signed_headers, signature, service="s3"):
    """
    Generate authorization header.

    :param access_key: Server access key.
    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param signed_headers: Signed headers.
    :param signature: Calculated signature.
    :param service: Optional service to sign request for.
    """
    signed_headers_string = ';'.join(signed_headers)
    credential = generate_credential_string(access_key, date, region, service)
    auth_header = [_SIGN_V4_ALGORITHM, 'Credential=' + credential + ',',
                   'SignedHeaders=' + signed_headers_string + ',',
                   'Signature=' + signature]
    return ' '.join(auth_header)


def generate_string_to_sign(date, region, canonical_request, service):
    """
    Generate string to sign.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param canonical_request: Canonical request generated previously.
    :param service: Service to scope request for.
    """
    formatted_date_time = date.strftime("%Y%m%dT%H%M%SZ")

    canonical_request_hasher = hashlib.sha256()
    canonical_request_hasher.update(canonical_request.encode('utf-8'))
    canonical_request_sha256 = canonical_request_hasher.hexdigest()
    scope = generate_scope_string(date, region, service)

    return '\n'.join([_SIGN_V4_ALGORITHM,
                      formatted_date_time,
                      scope,
                      canonical_request_sha256])


def sign_v4(method, url, region, headers=None,
            credentials=None,
            content_sha256=None,
            request_datetime=None,
            service="s3"
            ):
    """
    Signature version 4.

    :param method: HTTP method used for signature.
    :param url: Final url which needs to be signed.
    :param region: Region should be set to bucket region.
    :param headers: Optional headers for the method.
    :param credentials: Optional Credentials object with your AWS s3 account info.
    :param content_sha256: Optional body sha256.
    :param request_datetime: Optional request date/time
    :param service: Optional service to sign request for (defaults to S3)
    """

    # If no access key or secret key is provided return headers.
    if not credentials.get().access_key or not credentials.get().secret_key:
        return headers

    if headers is None:
        headers = FoldCaseDict()

    if region is None:
        region = 'us-east-1'

    parsed_url = urlsplit(url)
    secure = parsed_url.scheme == 'https'
    if secure:
        content_sha256 = _UNSIGNED_PAYLOAD
    if content_sha256 is None:
        # with no payload, calculate sha256 for 0 length data.
        content_sha256 = get_sha256_hexdigest('')

    host = remove_default_port(parsed_url)
    headers['Host'] = host

    if request_datetime is None:
        request_datetime = datetime.utcnow()

    headers['X-Amz-Date'] = request_datetime.strftime("%Y%m%dT%H%M%SZ")
    headers['X-Amz-Content-Sha256'] = content_sha256
    if credentials.get().session_token is not None:
        headers['X-Amz-Security-Token'] = credentials.get().session_token

    headers_to_sign = headers

    signed_headers = get_signed_headers(headers_to_sign)
    canonical_req = generate_canonical_request(method,
                                               parsed_url,
                                               headers_to_sign,
                                               signed_headers,
                                               content_sha256)

    string_to_sign = generate_string_to_sign(request_datetime, region,
                                             canonical_req, service)
    signing_key = generate_signing_key(request_datetime, region, credentials.get().secret_key, service=service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    authorization_header = generate_authorization_header(credentials.get().access_key,
                                                         request_datetime,
                                                         region,
                                                         signed_headers,
                                                         signature,
                                                         service
                                                         )

    headers['Authorization'] = authorization_header
    return headers


def parse_assume_role(data):
    """
    Parser for assume role response.

    :param data: Response data for STS assume role.
    :return: A :class:`Credentials` credential provider instance with the temporary credentials.
    """
    ns = {
        'sts': 'https://sts.amazonaws.com/doc/2011-06-15/'
    }

    root = xml.etree.ElementTree.fromstring(data)
    credentials_elem = root.find("sts:AssumeRoleResult", ns).find("sts:Credentials", ns)

    access_key = credentials_elem.find("sts:AccessKeyId", ns).text
    secret_key = credentials_elem.find("sts:SecretAccessKey", ns).text
    session_token = credentials_elem.find("sts:SessionToken", ns).text

    return Credentials(provider=Static(access_key, secret_key, session_token))
