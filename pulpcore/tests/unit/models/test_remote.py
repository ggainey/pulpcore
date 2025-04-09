import pytest
from uuid import uuid4
from cryptography.fernet import InvalidToken

from django.core.management import call_command
from django.db import connection

from pulpcore.app.models import Remote, Domain
from pulpcore.app.models.fields import _fernet, EncryptedTextField
from pulp_file.app.serializers import FileRemoteSerializer

TEST_KEY1 = b"hPCIFQV/upbvPRsEpgS7W32XdFA2EQgXnMtyNAekebQ="
TEST_KEY2 = b"6Xyv+QezAQ+4R870F5qsgKcngzmm46caDB2gyo9qnpc="


@pytest.fixture
def fake_fernet(tmp_path, settings):
    def _steps():
        yield
        key_file.write_bytes(TEST_KEY2 + b"\n" + TEST_KEY1)
        _fernet.cache_clear()
        yield
        key_file.write_bytes(TEST_KEY2)
        _fernet.cache_clear()
        yield
        key_file.write_bytes(TEST_KEY1)
        _fernet.cache_clear()
        yield

    key_file = tmp_path / "db_symmetric_key"
    key_file.write_bytes(TEST_KEY1)
    settings.DB_ENCRYPTION_KEY = str(key_file)
    _fernet.cache_clear()
    yield _steps()
    _fernet.cache_clear()


@pytest.mark.django_db
def test_encrypted_proxy_password(fake_fernet):
    remote = Remote.objects.create(name=uuid4(), proxy_password="test")
    assert Remote.objects.get(pk=remote.pk).proxy_password == "test"

    # check the database that proxy_password is encrypted
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT proxy_password FROM core_remote WHERE pulp_id = %s;", (str(remote.pulp_id),)
        )
        db_proxy_password = cursor.fetchone()[0]
    proxy_password = EncryptedTextField().from_db_value(db_proxy_password, None, connection)
    assert db_proxy_password != "test"
    assert proxy_password == "test"


@pytest.mark.django_db
def test_rotate_db_key(fake_fernet):
    remote = Remote.objects.create(name=uuid4(), proxy_password="test")
    domain = Domain.objects.create(name=uuid4(), storage_settings={"base_path": "/foo"})

    next(fake_fernet)  # new + old key

    call_command("rotate-db-key")

    next(fake_fernet)  # new key

    del remote.proxy_password
    assert remote.proxy_password == "test"
    del domain.storage_settings
    assert domain.storage_settings == {"base_path": "/foo"}

    next(fake_fernet)  # old key

    del remote.proxy_password
    with pytest.raises(InvalidToken):
        remote.proxy_password
    del domain.storage_settings
    with pytest.raises(InvalidToken):
        domain.storage_settings

GOOD_CERT = """
-----BEGIN CERTIFICATE-----
MIICoDCCAYgCCQC2c2uY34HNlzANBgkqhkiG9w0BAQUFADASMRAwDgYDVQQDDAdn
b3ZlZ2FuMB4XDTE5MDMxMzIxMDMzMFoXDTM4MDYxNjIxMDMzMFowEjEQMA4GA1UE
AwwHZ292ZWdhbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANEatWsZ
1iwGmTxD02dxMI4ci+Au4FzvmWLBWD07H5GGTVFwnqmNOKhP6DHs1EsMZevkUvaG
CRxZlPYhjNFLZr2c2FnoDZ5nBXlSW6sodXURbMfyT187nDeBXVYFuh4T2eNCatnm
t3vgdi+pWsF0LbOgpu7GJI2sh5K1imxyB77tJ7PFTDZCSohkK+A+0nDCnJqDUNXD
5CK8iaBciCbnzp3nRKuM2EmgXno9Repy/HYxIgB7ZodPwDvYNjMGfvs0s9mJIKmc
CKgkPXVO9y9gaRrrytICcPOs+YoU/PN4Ttg6wzxaWvJgw44vsR8wM/0i4HlXfBdl
9br+cgn8jukDOgECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAyNHV6NA+0GfUrvBq
AHXHNnBE3nzMhGPhF/0B/dO4o0n6pgGZyzRxaUaoo6+5oQnBf/2NmDyLWdalFWX7
D1WBaxkhK+FU922+qwQKhABlwMxGCnfZ8F+rlk4lNotm3fP4wHbnO1SGIDvvZFt/
mpMgkhwL4lShUFv57YylXr+D2vSFcAryKiVGk1X3sHMXlFAMLHUm3d97fJnmb1qQ
wC43BlJCBQF98wKtYNwTUG/9gblfk8lCB2DL1hwmPy3q9KbSDOdUK3HW6a75ZzCD
6mXc/Y0bJcwweDsywbPBYP13hYUcpw4htcU6hg6DsoAjLNkSrlY+GGo7htx+L9HH
IwtfRg==
-----END CERTIFICATE-----
"""

GOOD_CERT_WITH_COMMENT = """
saydas Intermédiaire CA
-----BEGIN CERTIFICATE-----
MIICoDCCAYgCCQC2c2uY34HNlzANBgkqhkiG9w0BAQUFADASMRAwDgYDVQQDDAdn
b3ZlZ2FuMB4XDTE5MDMxMzIxMDMzMFoXDTM4MDYxNjIxMDMzMFowEjEQMA4GA1UE
AwwHZ292ZWdhbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANEatWsZ
1iwGmTxD02dxMI4ci+Au4FzvmWLBWD07H5GGTVFwnqmNOKhP6DHs1EsMZevkUvaG
CRxZlPYhjNFLZr2c2FnoDZ5nBXlSW6sodXURbMfyT187nDeBXVYFuh4T2eNCatnm
t3vgdi+pWsF0LbOgpu7GJI2sh5K1imxyB77tJ7PFTDZCSohkK+A+0nDCnJqDUNXD
5CK8iaBciCbnzp3nRKuM2EmgXno9Repy/HYxIgB7ZodPwDvYNjMGfvs0s9mJIKmc
CKgkPXVO9y9gaRrrytICcPOs+YoU/PN4Ttg6wzxaWvJgw44vsR8wM/0i4HlXfBdl
9br+cgn8jukDOgECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAyNHV6NA+0GfUrvBq
AHXHNnBE3nzMhGPhF/0B/dO4o0n6pgGZyzRxaUaoo6+5oQnBf/2NmDyLWdalFWX7
D1WBaxkhK+FU922+qwQKhABlwMxGCnfZ8F+rlk4lNotm3fP4wHbnO1SGIDvvZFt/
mpMgkhwL4lShUFv57YylXr+D2vSFcAryKiVGk1X3sHMXlFAMLHUm3d97fJnmb1qQ
wC43BlJCBQF98wKtYNwTUG/9gblfk8lCB2DL1hwmPy3q9KbSDOdUK3HW6a75ZzCD
6mXc/Y0bJcwweDsywbPBYP13hYUcpw4htcU6hg6DsoAjLNkSrlY+GGo7htx+L9HH
IwtfRg==
-----END CERTIFICATE-----
"""

BAD_CERT = """
-----BEGIN CERTIFICATE-----\nBOGUS==\n-----END CERTIFICATE-----
"""


@pytest.mark.django_db
def test_certificate_clean():
    remote_keys = {"name": uuid4(), "url":"https://example.com", "ca_cert": GOOD_CERT}
    remote_serializer = FileRemoteSerializer(data=remote_keys)
    remote_serializer.is_valid(raise_exception=True)
    assert remote_serializer.validated_data["ca_cert"] == GOOD_CERT

    remote_keys["ca_cert"] = GOOD_CERT_WITH_COMMENT
    remote_serializer = FileRemoteSerializer(data=remote_keys)
    remote_serializer.is_valid(raise_exception=True)
    assert remote_serializer.validated_data["ca_cert"] == GOOD_CERT

    remote_keys["ca_cert"] = BAD_CERT
    remote_serializer = FileRemoteSerializer(data=remote_keys)
    remote_serializer.is_valid(raise_exception=True)
