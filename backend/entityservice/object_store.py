import minio
from structlog import get_logger

from entityservice.settings import Config as config

logger = get_logger('objectstore')


def connect_to_object_store():
    mc = minio.Minio(
        config.MINIO_SERVER,
        config.MINIO_ACCESS_KEY,
        config.MINIO_SECRET_KEY,
        secure=False
    )
    logger.debug("Connected to minio")
    create_bucket(mc, config.MINIO_BUCKET)
    return mc


def create_bucket(minio_client, bucket):
    if not minio_client.bucket_exists(bucket):
        logger.info("Creating bucket {}".format(bucket))
        try:
            minio_client.make_bucket(bucket)
        except minio.error.BucketAlreadyOwnedByYou:
            logger.info("The bucket {} was already created.".format(bucket))
