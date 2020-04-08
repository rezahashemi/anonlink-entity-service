import boto3
import minio
import pytest

from entityservice.settings import Config as config


@pytest.fixture(scope='session')
def upload_restricted_boto_session():
    """
    Note this assumes that non-root object store credentials
    have been setup in the object store.
    """

    return boto3.Session(
        aws_access_key_id=config.UPLOAD_OBJECT_STORE_ACCESS_KEY,
        aws_secret_access_key=config.UPLOAD_OBJECT_STORE_SECRET_KEY,
        region_name='us-east-1'
    )


@pytest.fixture(scope='session')
def upload_restricted_minio_client():
    restricted_mc_client = minio.Minio(
        config.UPLOAD_OBJECT_STORE_SERVER,
        config.UPLOAD_OBJECT_STORE_ACCESS_KEY,
        config.UPLOAD_OBJECT_STORE_SECRET_KEY,
        region='us-east-1',
        secure=False
    )
    restricted_mc_client.set_app_info("anonlink-restricted", "testing client")
    return restricted_mc_client
