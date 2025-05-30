"""Tests that perform actions over orphan files."""

import os
import pytest


def test_content_orphan_filter(
    file_bindings,
    file_content_unit_with_name_factory,
    file_repository_factory,
    monitor_task,
):
    content_unit = file_content_unit_with_name_factory("1.iso")

    # test orphan_for with different values
    content_units = file_bindings.ContentFilesApi.list(
        orphaned_for=0, pulp_href__in=[content_unit.pulp_href]
    )
    assert content_units.count == 1
    content_units = file_bindings.ContentFilesApi.list(
        orphaned_for=100, pulp_href__in=[content_unit.pulp_href]
    )
    assert content_units.count == 0

    # add our content unit to a repo
    repo = file_repository_factory()
    body = {"add_content_units": [content_unit.pulp_href]}
    task = file_bindings.RepositoriesFileApi.modify(repo.pulp_href, body).task
    monitor_task(task)
    content_units = file_bindings.ContentFilesApi.list(
        orphaned_for=0, pulp_href__in=[content_unit.pulp_href]
    )
    assert content_units.count == 0


def test_artifact_orphan_filter(
    pulpcore_bindings,
    file_bindings,
    random_artifact,
    monitor_task,
):
    # test orphan_for with different values
    artifacts = pulpcore_bindings.ArtifactsApi.list(
        orphaned_for=0, pulp_href__in=[random_artifact.pulp_href]
    )
    assert artifacts.count == 1
    artifacts = pulpcore_bindings.ArtifactsApi.list(
        orphaned_for=100, pulp_href__in=[random_artifact.pulp_href]
    )
    assert artifacts.count == 0

    # create a content unit with the artifact
    task = file_bindings.ContentFilesApi.create(
        artifact=random_artifact.pulp_href, relative_path="1.iso"
    ).task
    monitor_task(task)
    artifacts = pulpcore_bindings.ArtifactsApi.list(
        orphaned_for=0, pulp_href__in=[random_artifact.pulp_href]
    )
    assert artifacts.count == 0


def test_orphans_delete(
    pulpcore_bindings,
    file_bindings,
    random_artifact,
    file_random_content_unit,
    monitor_task,
    pulp_settings,
):
    settings = pulp_settings
    # Verify that the system contains the orphan content unit and the orphan artifact.
    content_unit = file_bindings.ContentFilesApi.read(file_random_content_unit.pulp_href)
    artifact = pulpcore_bindings.ArtifactsApi.read(random_artifact.pulp_href)

    if settings.STORAGES["default"]["BACKEND"] == "pulpcore.app.models.storage.FileSystem":
        # Verify that the artifacts are on disk
        relative_path = pulpcore_bindings.ArtifactsApi.read(content_unit.artifact).file
        artifact_path1 = os.path.join(pulp_settings.MEDIA_ROOT, relative_path)
        artifact_path2 = os.path.join(pulp_settings.MEDIA_ROOT, artifact.file)
        assert os.path.exists(artifact_path1) is True
        assert os.path.exists(artifact_path2) is True

    # Delete orphans using deprecated API
    monitor_task(pulpcore_bindings.OrphansApi.delete().task)

    # Assert that the content unit and artifact are gone
    if pulp_settings.ORPHAN_PROTECTION_TIME == 0:
        with pytest.raises(file_bindings.ApiException) as exc:
            file_bindings.ContentFilesApi.read(file_random_content_unit.pulp_href)
        assert exc.value.status == 404
        if settings.STORAGES["default"]["BACKEND"] == "pulpcore.app.models.storage.FileSystem":
            assert os.path.exists(artifact_path1) is False
            assert os.path.exists(artifact_path2) is False


def test_orphans_cleanup(
    pulpcore_bindings,
    file_bindings,
    random_artifact,
    file_random_content_unit,
    monitor_task,
    pulp_settings,
):
    settings = pulp_settings
    # Cleanup orphans with a nonzero orphan_protection_time
    monitor_task(pulpcore_bindings.OrphansCleanupApi.cleanup({"orphan_protection_time": 10}).task)

    # Verify that the system contains the orphan content unit and the orphan artifact.
    content_unit = file_bindings.ContentFilesApi.read(file_random_content_unit.pulp_href)
    artifact = pulpcore_bindings.ArtifactsApi.read(random_artifact.pulp_href)

    if settings.STORAGES["default"]["BACKEND"] == "pulpcore.app.models.storage.FileSystem":
        # Verify that the artifacts are on disk
        relative_path = pulpcore_bindings.ArtifactsApi.read(content_unit.artifact).file
        artifact_path1 = os.path.join(pulp_settings.MEDIA_ROOT, relative_path)
        artifact_path2 = os.path.join(pulp_settings.MEDIA_ROOT, artifact.file)
        assert os.path.exists(artifact_path1) is True
        assert os.path.exists(artifact_path2) is True

    # Cleanup orphans with a zero orphan_protection_time
    monitor_task(pulpcore_bindings.OrphansCleanupApi.cleanup({"orphan_protection_time": 0}).task)

    # Assert that the content unit and the artifact are gone
    with pytest.raises(file_bindings.ApiException) as exc:
        file_bindings.ContentFilesApi.read(file_random_content_unit.pulp_href)
    assert exc.value.status == 404
    if settings.STORAGES["default"]["BACKEND"] == "pulpcore.app.models.storage.FileSystem":
        assert os.path.exists(artifact_path1) is False
        assert os.path.exists(artifact_path2) is False


def test_cleanup_specific_orphans(
    pulpcore_bindings,
    file_bindings,
    file_content_unit_with_name_factory,
    monitor_task,
):
    content_unit_1 = file_content_unit_with_name_factory("1.iso")
    content_unit_2 = file_content_unit_with_name_factory("2.iso")
    cleanup_dict = {"content_hrefs": [content_unit_1.pulp_href], "orphan_protection_time": 0}
    monitor_task(pulpcore_bindings.OrphansCleanupApi.cleanup(cleanup_dict).task)

    # Assert that content_unit_2 is gone and content_unit_1 is present
    with pytest.raises(file_bindings.ApiException) as exc:
        file_bindings.ContentFilesApi.read(content_unit_1.pulp_href)
    assert exc.value.status == 404
    assert file_bindings.ContentFilesApi.read(content_unit_2.pulp_href).pulp_href

    # Test whether the `content_hrefs` param raises a ValidationError with [] as the value
    content_hrefs_dict = {"content_hrefs": []}
    with pytest.raises(pulpcore_bindings.ApiException) as exc:
        pulpcore_bindings.OrphansCleanupApi.cleanup(content_hrefs_dict)
    assert exc.value.status == 400

    # Test whether the `content_hrefs` param raises a ValidationError with and invalid href"""
    content_hrefs_dict = {"content_hrefs": ["/not/a/valid/content/href"]}
    with pytest.raises(pulpcore_bindings.ApiException) as exc:
        pulpcore_bindings.OrphansCleanupApi.cleanup(content_hrefs_dict)
    assert exc.value.status == 400
