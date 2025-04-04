import uuid

import pytest
import random
import string
import json
from pulpcore.client.pulpcore import ApiException

from pulpcore.tests.functional.utils import PulpTaskError


@pytest.mark.parallel
def test_crud_domains(pulpcore_bindings, monitor_task):
    """Perform basic CRUD operations on Domains."""
    # List domains, "default" domain should always be present
    domains = pulpcore_bindings.DomainsApi.list()
    assert domains.count >= 1

    # Create some domains
    body = {
        "name": str(uuid.uuid4()),
        "storage_class": "pulpcore.app.models.storage.FileSystem",
        "storage_settings": {"MEDIA_ROOT": ""},
    }
    domain = pulpcore_bindings.DomainsApi.create(body)
    assert domain.storage_class == body["storage_class"]
    assert domain.name == body["name"]
    valid_settings = {
        "location": "",
        "base_url": "",
        "directory_permissions_mode": None,
        "file_permissions_mode": 420,
        "hidden_fields": [],
    }
    assert domain.storage_settings == valid_settings

    # Update the domain
    update_body = {"storage_settings": {"location": "/testing/"}}
    response = pulpcore_bindings.DomainsApi.partial_update(domain.pulp_href, update_body)
    monitor_task(response.task)

    # Read updated domain
    domain = pulpcore_bindings.DomainsApi.read(domain.pulp_href)
    valid_settings["location"] = "/testing/"
    assert domain.storage_settings == valid_settings

    # Delete the domain
    response = pulpcore_bindings.DomainsApi.delete(domain.pulp_href)
    monitor_task(response.task)


@pytest.mark.parallel
def test_default_domain(pulpcore_bindings, pulp_settings):
    """Test properties around the default domain."""
    settings = pulp_settings
    domains = pulpcore_bindings.DomainsApi.list(name="default")
    assert domains.count == 1

    # Read the default domain, ensure storage is set to default
    default_domain = domains.results[0]
    assert default_domain.name == "default"
    assert default_domain.storage_class == settings.STORAGES["default"]["BACKEND"]
    assert default_domain.redirect_to_object_storage == settings.REDIRECT_TO_OBJECT_STORAGE
    assert default_domain.hide_guarded_distributions == settings.HIDE_GUARDED_DISTRIBUTIONS

    # Try to create another default domain
    body = {
        "name": "default",
        "storage_class": "pulpcore.app.models.storage.FileSystem",
        "storage_settings": {"MEDIA_ROOT": ""},
    }
    with pytest.raises(ApiException) as e:
        pulpcore_bindings.DomainsApi.create(body)

    assert e.value.status == 400
    assert json.loads(e.value.body) == {"name": ["This field must be unique."]}

    # Try to update the default domain
    update_body = {"name": "no-longer-default"}
    with pytest.raises(ApiException) as e:
        pulpcore_bindings.DomainsApi.partial_update(default_domain.pulp_href, update_body)

    assert e.value.status == 400
    assert json.loads(e.value.body) == ["Default domain can not be updated."]

    # Try to delete the default domain
    with pytest.raises(ApiException) as e:
        pulpcore_bindings.DomainsApi.delete(default_domain.pulp_href)

    assert e.value.status == 400
    assert json.loads(e.value.body) == ["Default domain can not be deleted."]


@pytest.mark.parallel
def test_active_domain_deletion(pulpcore_bindings, monitor_task, pulp_settings):
    """Test trying to delete a domain that is in use, has objects in it."""
    settings = pulp_settings
    if not settings.DOMAIN_ENABLED:
        pytest.skip("Domains not enabled")
    name = str(uuid.uuid4())
    body = {
        "name": name,
        "storage_class": "pulpcore.app.models.storage.FileSystem",
        "storage_settings": {"location": ""},
    }
    domain = pulpcore_bindings.DomainsApi.create(body)

    guard_body = {"name": name}
    guard = pulpcore_bindings.ContentguardsRbacApi.create(guard_body, pulp_domain=name)
    assert name in guard.pulp_href

    # Try to delete a domain with an object in it
    response = pulpcore_bindings.DomainsApi.delete(domain.pulp_href)
    with pytest.raises(PulpTaskError) as e:
        monitor_task(response.task)

    assert e.value.task.state == "failed"

    # Delete the content guard
    pulpcore_bindings.ContentguardsRbacApi.delete(guard.pulp_href)

    # Now succeed in deleting the domain
    response = pulpcore_bindings.DomainsApi.delete(domain.pulp_href)
    monitor_task(response.task)
    with pytest.raises(ApiException) as e:
        pulpcore_bindings.DomainsApi.read(domain.pulp_href)
    assert e.value.status == 404


@pytest.mark.parallel
def test_orphan_domain_deletion(
    pulpcore_bindings,
    file_bindings,
    gen_object_with_cleanup,
    monitor_task,
    tmp_path,
    pulp_settings,
):
    """Test trying to delete a domain that is in use, has objects in it."""
    settings = pulp_settings
    if not settings.DOMAIN_ENABLED:
        pytest.skip("Domains not enabled")
    body = {
        "name": str(uuid.uuid4()),
        "storage_class": "pulpcore.app.models.storage.FileSystem",
        "storage_settings": {"MEDIA_ROOT": "/var/lib/pulp/media/"},
    }
    domain = gen_object_with_cleanup(pulpcore_bindings.DomainsApi, body)

    repository = gen_object_with_cleanup(
        file_bindings.RepositoriesFileApi, {"name": str(uuid.uuid4())}, pulp_domain=domain.name
    )
    new_file = tmp_path / "new_file"
    new_file.write_text("Test file")
    monitor_task(
        file_bindings.ContentFilesApi.create(
            relative_path=str(uuid.uuid4()),
            file=str(new_file),
            pulp_domain=domain.name,
            repository=repository.pulp_href,
        ).task
    )

    # Try to delete a domain with the repository in it
    response = pulpcore_bindings.DomainsApi.delete(domain.pulp_href)
    with pytest.raises(PulpTaskError) as e:
        monitor_task(response.task)

    assert e.value.task.state == "failed"

    # Delete the repository
    file_bindings.RepositoriesFileApi.delete(repository.pulp_href)

    # Now succeed in deleting the domain
    response = pulpcore_bindings.DomainsApi.delete(domain.pulp_href)
    monitor_task(response.task)
    with pytest.raises(ApiException) as e:
        pulpcore_bindings.DomainsApi.read(domain.pulp_href)
    assert e.value.status == 404


@pytest.mark.parallel
def test_special_domain_creation(pulpcore_bindings, gen_object_with_cleanup, pulp_settings):
    """Test many possible domain creation scenarios."""
    settings = pulp_settings
    if not settings.DOMAIN_ENABLED:
        pytest.skip("Domains not enabled")
    # This test needs to account for which environment it is running in
    storage_types = {
        "pulpcore.app.models.storage.FileSystem",
        # "pulpcore.app.models.storage.PulpSFTPStorage",
        "storages.backends.s3boto3.S3Boto3Storage",
        "storages.backends.azure_storage.AzureStorage",
        # "storages.backends.gcloud.GoogleCloudStorage",
    }

    storage_settings = {
        "pulpcore.app.models.storage.FileSystem": {"media_root": ""},
        "pulpcore.app.models.storage.PulpSFTPStorage": {
            "SFTP_STORAGE_HOST": "sftp-storage-host",
            "SFTP_STORAGE_ROOT": "/storage/",
            "SFTP_STORAGE_PARAMS": {
                "username": "foo",
                "key_filename": "/etc/pulp/certs/storage_id_ed25519",
            },
        },
        "storages.backends.s3boto3.S3Boto3Storage": {
            "AWS_ACCESS_KEY_ID": "random",
            "AWS_SECRET_ACCESS_KEY": "random",
            "AWS_STORAGE_BUCKET_NAME": "pulp3",
            "AWS_DEFAULT_ACL": None,
            "AWS_S3_SIGNATURE_VERSION": "s3v4",
            "AWS_S3_ADDRESSING_STYLE": "path",
            "AWS_S3_REGION_NAME": "eu-central-1",
        },
        "storages.backends.azure_storage.AzureStorage": {
            "AZURE_ACCOUNT_NAME": "Account Name",
            "AZURE_CONTAINER": "Container name",
            "AZURE_ACCOUNT_KEY": "random_key",
            "AZURE_URL_EXPIRATION_SECS": 60,
            "AZURE_OVERWRITE_FILES": True,
            "AZURE_LOCATION": "azure/",
        },
        "storages.backends.gcloud.GoogleCloudStorage": {
            "GS_BUCKET_NAME": "pulp3",
            "GS_PROJECT_ID": "pulp",
            "GS_CUSTOM_ENDPOINT": "http://custom-endpoint",
        },
    }

    installed_backends = []
    domain_names = set()
    for backend in storage_types:
        body = {
            "name": str(uuid.uuid4()),
            "storage_class": backend,
            "storage_settings": storage_settings[backend],
        }
        if backend == "pulpcore.app.models.storage.PulpSFTPStorage":
            body["redirect_to_object_storage"] = False
        try:
            domain = gen_object_with_cleanup(pulpcore_bindings.DomainsApi, body)
        except ApiException as e:
            assert e.status == 400
            assert "Backend is not installed on Pulp." in e.body
        else:
            installed_backends.append(backend)
            domain_names.add(domain.name)
    # Try creating domains with correct settings
    for backend in installed_backends:
        body = {
            "name": str(uuid.uuid4()),
            "storage_class": backend,
            "storage_settings": storage_settings[backend],
        }
        domain = gen_object_with_cleanup(pulpcore_bindings.DomainsApi, body)
        domain_names.add(domain.name)

    # Try creating domains with incorrect settings
    for backend in installed_backends:
        random_backend = random.choice(tuple(storage_types - {backend}))
        body = {
            "name": str(uuid.uuid4()),
            "storage_class": backend,
            "storage_settings": storage_settings[random_backend],
        }
        with pytest.raises(ApiException) as e:
            gen_object_with_cleanup(pulpcore_bindings.DomainsApi, body)

        assert e.value.status == 400
        error_body = json.loads(e.value.body)
        assert "storage_settings" in error_body
        assert "Unexpected field" in error_body["storage_settings"].values()

    # Try creating domains with a name greater than max_length
    letters = string.ascii_lowercase
    name = "".join(random.choice(letters) for i in range(80))
    backend = installed_backends[0]
    body = {
        "name": name,
        "storage_class": backend,
        "storage_settings": storage_settings[backend],
    }
    with pytest.raises((ApiException, ValueError)) as e:
        gen_object_with_cleanup(pulpcore_bindings.DomainsApi, body)

    if isinstance(e.value, ApiException):
        assert e.value.status == 400
        assert "Ensure this field has no more than 50 characters." in e.value.body
    else:
        assert "String should have at most 50 characters" in str(e.value)

    # Check that all domains are "apart" of the default domain
    domains = pulpcore_bindings.DomainsApi.list()
    for domain in domains.results:
        assert "default/api/v3/" in domain.pulp_href
    # Check that operations on domains in another "domain" doesn't change href
    random_name = random.choice(tuple(domain_names - {"default"}))
    domains = pulpcore_bindings.DomainsApi.list(pulp_domain=random_name)
    for domain in domains.results:
        assert "default/api/v3/" in domain.pulp_href

    body = {
        "name": str(uuid.uuid4()),
        "storage_class": "pulpcore.app.models.storage.FileSystem",
        "storage_settings": {"MEDIA_ROOT": ""},
    }
    domain = gen_object_with_cleanup(pulpcore_bindings.DomainsApi, body, pulp_domain=random_name)
    assert "default/api/v3/" in domain.pulp_href
    assert random_name not in domain.pulp_href


@pytest.mark.parallel
def test_filter_domains_by_label(pulpcore_bindings, domain_factory):
    """Test filtering domains by label."""
    # Create domains with different labels
    domain_a = domain_factory(pulp_labels={"key_a": "label_a"})
    domain_b = domain_factory(pulp_labels={"key_b": "label_b"})

    # Filter by label key
    domains = pulpcore_bindings.DomainsApi.list(pulp_label_select="key_a").results
    assert len(domains) == 1
    assert domains[0].pulp_href == domain_a.pulp_href

    # Filter by label value
    domains = pulpcore_bindings.DomainsApi.list(pulp_label_select="key_b=label_b").results
    assert len(domains) == 1
    assert domains[0].pulp_href == domain_b.pulp_href

    # Filter by non-existent label
    domains = pulpcore_bindings.DomainsApi.list(pulp_label_select="key_c").results
    assert len(domains) == 0


@pytest.mark.parallel
def test_set_label_on_domain(pulpcore_bindings, domain_factory, gen_user):
    """Test setting a label on a domain."""
    domain = domain_factory()
    response = pulpcore_bindings.DomainsApi.set_label(
        domain.pulp_href, {"key": "abc", "value": "def"}
    )
    assert response.key == "abc"
    assert response.value == "def"

    user = gen_user(object_roles=[("core.domain_owner", domain.pulp_href)])
    with user:
        response = pulpcore_bindings.DomainsApi.unset_label(domain.pulp_href, {"key": "abc"})
        assert response.key == "abc"
        assert response.value == "def"
