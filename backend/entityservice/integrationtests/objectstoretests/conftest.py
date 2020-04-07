import boto3
import pytest

from entityservice.settings import Config as config

@pytest.fixture(scope='session')
def upload_restricted_boto_session():
    """

    """

    session = boto3.Session(
        aws_access_key_id='newuser',
        aws_secret_access_key='newuser123',
        region_name='us-east-1'
    )

    return session
