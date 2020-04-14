import io

import minio
import pytest

from e2etests.config import url


def test_get_auth_credentials(requests, a_project):

    for dp_index in range(2):
        pid = a_project['project_id']
        res = requests.get(url + f"projects/{pid}/authorize-external-upload",
                           headers={'Authorization': a_project['update_tokens'][dp_index]})

        assert res.status_code == 200
        raw_json = res.json()
        assert "credentials" in raw_json
        credentials = raw_json['credentials']
        assert "upload" in raw_json

        bucket_name = raw_json['upload']['bucket']
        allowed_path = raw_json['upload']['path']

        for key in ['AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration']:
            assert key in credentials

        # Test we can create and use these credentials via a Minio client
        restricted_mc_client = minio.Minio(
            "localhost:9000",
            credentials['AccessKeyId'],
            credentials['SecretAccessKey'],
            credentials['SessionToken'],
            region='us-east-1',
            secure=False
        )

        with pytest.raises(minio.error.AccessDenied):
            restricted_mc_client.list_buckets()

        with pytest.raises(minio.error.AccessDenied):
            restricted_mc_client.put_object(bucket_name, 'testobject', io.BytesIO(b'data'), length=4)

        # Should be able to put an object in the approved path
        restricted_mc_client.put_object(bucket_name, allowed_path + '/blocks.json', io.BytesIO(b'data'), length=4)
        # Permission exists to put multiple files
        restricted_mc_client.put_object(bucket_name, allowed_path + '/encodings.bin', io.BytesIO(b'data'), length=4)

