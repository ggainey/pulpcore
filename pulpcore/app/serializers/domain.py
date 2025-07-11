from gettext import gettext as _
import json

from django.conf import settings
from django.core.files.storage import import_string
from django.core.exceptions import ImproperlyConfigured
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from pulpcore.app.models import Domain
from pulpcore.app.serializers import (
    IdentityField,
    ModelSerializer,
    HiddenFieldsMixin,
    pulp_labels_validator,
)


BACKEND_CHOICES = (
    ("pulpcore.app.models.storage.FileSystem", "Use local filesystem as storage"),
    # ("pulpcore.app.models.storage.PulpSFTPStorage", "Use SFTP server as storage"),
    ("storages.backends.s3boto3.S3Boto3Storage", "Use Amazon S3 as storage"),
    ("storages.backends.azure_storage.AzureStorage", "Use Azure Blob as storage"),
    # ("storages.backends.gcloud.GoogleCloudStorage", "Use Google Cloud as storage"),
)

DEFAULT_CONTENT_TYPES = [
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "image/svg+xml",
]


class BaseSettingsClass(HiddenFieldsMixin, serializers.Serializer):
    """A Base Serializer class for different Storage Backend Settings."""

    STORAGE_CLASS = None
    SETTING_MAPPING = None

    def to_representation(self, instance):
        """Handle getting settings values for default domain case."""
        # Should I convert back the saved settings to their Setting names for to_representation?
        if getattr(self.context.get("domain", None), "name", None) == "default":
            for setting_name, field in self.SETTING_MAPPING.items():
                value = getattr(settings, setting_name, None) or settings.STORAGES["default"].get(
                    "OPTIONS", {}
                ).get(field)
                if value:
                    instance[field] = value
        return super().to_representation(instance)

    def to_internal_value(self, data):
        """Translate incoming data from storage setting name to storage init arg."""
        init_keys = set(self.SETTING_MAPPING.values())
        unknown_fields = set()
        fields_to_pop = set()
        update_dict = {}

        for key, value in data.items():
            if key.lower() in self.SETTING_MAPPING:
                update_dict[self.SETTING_MAPPING[key.lower()]] = value
                fields_to_pop.add(key)
            elif key not in init_keys:
                unknown_fields.add(key)

        if unknown_fields:
            unknown_fields = {field: _("Unexpected field") for field in unknown_fields}
            raise serializers.ValidationError(unknown_fields)

        for key in fields_to_pop:
            data.pop(key)

        data.update(update_dict)
        return super().to_internal_value(data)

    def create(self, validated_data):
        """
        Create a storage instance based on the stored settings.

        Subclasses can override this to instantiate objects needed for creation.
        """
        storage_class = import_string(self.STORAGE_CLASS)
        return storage_class(**validated_data)


class FileSystemSettingsSerializer(BaseSettingsClass):
    """A Serializer for FileSystem storage settings."""

    STORAGE_CLASS = "pulpcore.app.models.storage.FileSystem"
    SETTING_MAPPING = {
        "media_root": "location",
        "media_url": "base_url",
        "file_upload_permissions": "file_permissions_mode",
        "file_upload_directory_permissions": "directory_permissions_mode",
    }

    # Maybe add a validator to prevent putting the media root anywhere
    location = serializers.CharField(required=True, allow_blank=True)
    base_url = serializers.CharField(allow_blank=True, default="")
    file_permissions_mode = serializers.IntegerField(default=0o644)
    directory_permissions_mode = serializers.IntegerField(allow_null=True, default=None)


class SFTPSettingsSerializer(BaseSettingsClass):
    """A Serializer for SFTP storage settings."""

    STORAGE_CLASS = "pulpcore.app.models.storage.PulpSFTPStorage"
    SETTING_MAPPING = {
        "sftp_storage_host": "host",
        "sftp_storage_params": "params",
        "sftp_storage_interactive": "interactive",
        "sftp_storage_file_mode": "file_mode",
        "sftp_storage_dir_mode": "dir_mode",
        "sftp_storage_uid": "uid",
        "sftp_storage_gid": "gid",
        "sftp_known_host_file": "known_host_file",
        "sftp_storage_root": "root_path",
        "media_url": "base_url",
        "sftp_base_url": "base_url",
    }

    host = serializers.CharField(required=True)
    root_path = serializers.CharField(required=True)
    params = serializers.DictField(default={}, write_only=True)
    file_mode = serializers.IntegerField(allow_null=True, default=None)
    dir_mode = serializers.IntegerField(allow_null=True, default=None)
    uid = serializers.CharField(allow_null=True, default=None)
    gid = serializers.CharField(allow_null=True, default=None)
    base_url = serializers.CharField(allow_null=True, default=None)
    interactive = serializers.HiddenField(default=False)
    known_host_file = serializers.HiddenField(default=None)


class TransferConfigSerializer(serializers.Serializer):
    """A Serializer for the boto3.S3 Transfer Config object."""

    multipart_threshold = serializers.IntegerField(default=8388608)  # 8 * 1MB
    max_concurrency = serializers.IntegerField(default=10)
    multipart_chunksize = serializers.IntegerField(default=8388608)
    num_download_attempts = serializers.IntegerField(default=5)
    max_io_queue = serializers.IntegerField(default=100)
    io_chunksize = serializers.IntegerField(default=262144)  # 256 * 1KB
    use_threads = serializers.BooleanField(default=True)
    max_bandwidth = serializers.IntegerField(allow_null=True, default=None)
    preferred_transfer_client = serializers.ChoiceField(choices=("auto", "classic"), default="auto")

    def create(self, validated_data):
        """Return a boto3.S3.transfer.TransferConfig object."""
        from boto3.s3.transfer import TransferConfig

        return TransferConfig(**validated_data)


class AmazonS3SettingsSerializer(BaseSettingsClass):
    """A Serializer for Amazon S3 storage settings."""

    STORAGE_CLASS = "storages.backends.s3boto3.S3Boto3Storage"
    SETTING_MAPPING = {
        "aws_s3_access_key_id": "access_key",
        "aws_access_key_id": "access_key",
        "aws_s3_secret_access_key": "secret_key",
        "aws_secret_access_key": "secret_key",
        "aws_session_token": "security_token",
        "aws_security_token": "security_token",
        "aws_s3_session_profile": "session_profile",
        "aws_s3_file_overwrite": "file_overwrite",
        "aws_s3_object_parameters": "object_parameters",
        "aws_storage_bucket_name": "bucket_name",
        "aws_querystring_auth": "querystring_auth",
        "aws_querystring_expire": "querystring_expire",
        "aws_s3_signature_version": "signature_version",
        "aws_location": "location",
        "aws_s3_custom_domain": "custom_domain",
        "aws_cloudfront_key_id": "cloudfront_key_id",
        "aws_cloudfront_key": "cloudfront_key",
        "aws_s3_addressing_style": "addressing_style",
        "aws_s3_file_name_charset": "file_name_charset",
        "aws_is_gzipped": "gzip",
        "gzip_content_types": "gzip_content_types",
        "aws_s3_url_protocol": "url_protocol",
        "aws_s3_endpoint_url": "endpoint_url",
        "aws_s3_proxies": "proxies",
        "aws_s3_region_name": "region_name",
        "aws_s3_use_ssl": "use_ssl",
        "aws_s3_verify": "verify",
        "aws_s3_max_memory_size": "max_memory_size",
        "aws_default_acl": "default_acl",
        "aws_s3_use_threads": "use_threads",
        "aws_s3_transfer_config": "transfer_config",
        "aws_s3_client_config": "client_config",
    }

    access_key = serializers.CharField(required=True, write_only=True)
    secret_key = serializers.CharField(allow_null=True, default=None, write_only=True)
    security_token = serializers.CharField(allow_null=True, default=None, write_only=True)
    session_profile = serializers.HiddenField(default=False)
    file_overwrite = serializers.BooleanField(default=True)
    object_parameters = serializers.DictField(default={})
    bucket_name = serializers.CharField(required=True)
    querystring_auth = serializers.BooleanField(default=True)
    querystring_expire = serializers.IntegerField(default=3600)
    signature_version = serializers.CharField(allow_null=True, default=None)
    location = serializers.CharField(allow_blank=True, default="")
    custom_domain = serializers.CharField(allow_null=True, default=None)
    cloudfront_key_id = serializers.CharField(allow_null=True, default=None)
    cloudfront_key = serializers.CharField(allow_null=True, default=None, write_only=True)
    addressing_style = serializers.CharField(allow_null=True, default=None)
    file_name_charset = serializers.CharField(default="utf-8")
    gzip = serializers.BooleanField(default=False)
    gzip_content_types = serializers.ListField(
        child=serializers.CharField(), default=DEFAULT_CONTENT_TYPES
    )
    url_protocol = serializers.CharField(default="https:")
    endpoint_url = serializers.CharField(allow_null=True, default=None)
    proxies = serializers.DictField(allow_null=True, default=None)
    region_name = serializers.CharField(allow_null=True, default=None)
    use_ssl = serializers.BooleanField(default=True)
    verify = serializers.BooleanField(allow_null=True, default=None)
    max_memory_size = serializers.IntegerField(default=0)
    default_acl = serializers.CharField(allow_null=True, default=None)
    use_threads = serializers.BooleanField(default=True)
    transfer_config = TransferConfigSerializer(allow_null=True, default=None)
    # TODO: Add a botocore.Config serializer to allow specifying this field from json
    client_config = serializers.HiddenField(default=None)

    def validate_verify(self, value):
        """Verify can **only** be None or False. None=verify ssl."""
        if value:
            value = None
        return value

    def validate(self, data):
        """Verify that secret_key or security_token is set."""
        data = super().validate(data)
        if not (data.get("secret_key") or data.get("security_token")):
            raise serializers.ValidationError(
                _("One of 'secret_key' or 'security_token' must be set.")
            )
        return data

    def create(self, validated_data):
        """Special handling for TransferConfig if set."""
        if transfer_config := validated_data.get("transfer_config"):
            transfer = self.fields["transfer_config"].create(transfer_config)
            validated_data["transfer_config"] = transfer
        return super().create(validated_data)


class AzureSettingsSerializer(BaseSettingsClass):
    """A Serializer for Azure storage settings."""

    STORAGE_CLASS = "storages.backends.azure_storage.AzureStorage"
    SETTING_MAPPING = {
        "azure_account_name": "account_name",
        "azure_account_key": "account_key",
        "azure_object_parameters": "object_parameters",
        "azure_container": "azure_container",
        "azure_ssl": "azure_ssl",
        "azure_upload_max_conn": "upload_max_conn",
        "azure_connection_timeout_secs": "timeout",
        "azure_blob_max_memory_size": "max_memory_size",
        "azure_url_expiration_secs": "expiration_secs",
        "azure_overwrite_files": "overwrite_files",
        "azure_location": "location",
        "azure_cache_control": "cache_control",
        "azure_sas_token": "sas_token",
        "azure_endpoint_suffix": "endpoint_suffix",
        "azure_custom_domain": "custom_domain",
        "azure_connection_string": "connection_string",
        "azure_token_credential": "token_credential",
        "azure_api_version": "api_version",
    }

    account_name = serializers.CharField(required=True, write_only=True)
    account_key = serializers.CharField(required=True, write_only=True)
    object_parameters = serializers.DictField(default={})
    azure_container = serializers.CharField(required=True)
    azure_ssl = serializers.BooleanField(default=True)
    upload_max_conn = serializers.IntegerField(default=2)
    timeout = serializers.IntegerField(default=20)
    max_memory_size = serializers.IntegerField(default=2 * 1024 * 1024)
    expiration_secs = serializers.IntegerField(allow_null=True, default=None)
    overwrite_files = serializers.BooleanField(default=True)  # This should always be True for Pulp
    location = serializers.CharField(allow_blank=True, default="")
    cache_control = serializers.CharField(allow_null=True, default=None)
    sas_token = serializers.CharField(allow_null=True, default=None)
    endpoint_suffix = serializers.CharField(default="core.windows.net")
    custom_domain = serializers.CharField(allow_null=True, default=None)
    connection_string = serializers.CharField(allow_null=True, default=None)
    token_credential = serializers.CharField(allow_null=True, default=None)
    api_version = serializers.CharField(allow_null=True, default=None)


class GoogleSettingsSerializer(BaseSettingsClass):
    """A Serializer for Google storage settings."""

    STORAGE_CLASS = "storages.backends.gcloud.GoogleCloudStorage"
    SETTING_MAPPING = {
        "gs_project_id": "project_id",
        # "gs_credentials": "credentials",
        "gs_bucket_name": "bucket_name",
        "gs_custom_endpoint": "custom_endpoint",
        "gs_location": "location",
        "gs_default_acl": "default_acl",
        "gs_querystring_auth": "querystring_auth",
        "gs_expiration": "expiration",
        "gs_is_gzipped": "gzip",
        "gzip_content_types": "gzip_content_types",
        "gs_file_overwrite": "file_overwrite",
        "gs_object_parameters": "object_parameters",
        "gs_max_memory_size": "max_memory_size",
        "gs_blob_chunk_size": "blob_chunk_size",
    }

    bucket_name = serializers.CharField(required=True)
    project_id = serializers.CharField(required=True)
    # credentials = fields.JSONDictField(write_only=True)  # Need better upstream support
    custom_endpoint = serializers.CharField(allow_null=True, default=None)
    location = serializers.CharField(allow_blank=True, default="")
    default_acl = serializers.CharField(allow_null=True, default=None)
    querystring_auth = serializers.BooleanField(default=True)
    expiration = serializers.IntegerField(default=86400, max_value=604800)
    gzip = serializers.BooleanField(default=False)
    gzip_content_types = serializers.ListField(
        child=serializers.CharField(), default=DEFAULT_CONTENT_TYPES
    )
    file_overwrite = serializers.BooleanField(default=True)  # This should always be True
    object_parameters = serializers.DictField(default={})
    max_memory_size = serializers.IntegerField(default=0)
    blob_chunk_size = serializers.IntegerField(allow_null=True, default=None)


@extend_schema_field(OpenApiTypes.OBJECT)
class StorageSettingsSerializer(serializers.Serializer):
    """Serializer for converting a Domain's storage settings."""

    STORAGE_MAPPING = {
        "pulpcore.app.models.storage.FileSystem": FileSystemSettingsSerializer,
        "pulpcore.app.models.storage.PulpSFTPStorage": SFTPSettingsSerializer,
        "storages.backends.s3.S3Storage": AmazonS3SettingsSerializer,
        "storages.backends.s3boto3.S3Boto3Storage": AmazonS3SettingsSerializer,
        "storages.backends.azure_storage.AzureStorage": AzureSettingsSerializer,
        "storages.backends.gcloud.GoogleCloudStorage": GoogleSettingsSerializer,
    }

    def to_representation(self, instance):
        """Return the correct serializer based on the Domain's storage class."""
        serializer_class = self.STORAGE_MAPPING[instance.storage_class]
        serializer = serializer_class(
            instance=instance.storage_settings, context={"domain": instance}
        )
        return serializer.data

    def to_internal_value(self, data):
        """Appropriately convert the incoming data based on the Domain's storage class."""
        # Handle Creating & Updating
        storage_settings = self.root.initial_data.get("storage_settings", {})
        if not isinstance(storage_settings, dict):
            if isinstance(storage_settings, str):
                try:
                    storage_settings = json.loads(storage_settings)
                except json.JSONDecodeError:
                    raise serializers.ValidationError("Improper JSON string passed in")
            else:
                raise serializers.ValidationError("Storage settings should be a JSON object.")

        if self.root.instance:
            # Use passed in values, if not present fallback onto current values of instance
            storage_class = self.root.initial_data.get(
                "storage_class", self.root.instance.storage_class
            )
            if storage_class == self.root.instance.storage_class:
                storage_settings = {**self.root.instance.storage_settings, **storage_settings}
        else:
            storage_class = self.root.initial_data["storage_class"]

        ret = {}
        if serializer_class := self.STORAGE_MAPPING.get(storage_class):
            serializer = serializer_class(data=storage_settings)
            serializer.is_valid(raise_exception=True)
            ret.update(serializer.validated_data)
        # Hack to get correct data for DomainSerializer since this field uses source="*"
        return {"storage_settings": ret}

    def create_storage(self):
        """Instantiate a storage class based on the Domain's storage class."""
        if self.root.instance:
            storage_class = self.root.instance.storage_class
            storage_settings = self.root.instance.storage_settings
        else:
            storage_class = self.root.initial_data["storage_class"]
            storage_settings = self.root.initial_data["storage_settings"]
        serializer_class = self.STORAGE_MAPPING[storage_class]
        serializer = serializer_class(data=storage_settings)
        serializer.is_valid(raise_exception=True)
        return serializer.create(serializer.validated_data)


class BackendSettingsValidator:
    """Mixin to handle validating `storage_class` and `storage_settings`."""

    @staticmethod
    def _validate_storage_backend(storage_class, storage_settings):
        """Ensure that the backend can be used."""
        try:
            backend = import_string(storage_class)
        except (ImportError, ImproperlyConfigured):
            raise serializers.ValidationError(
                detail={"storage_class": _("Backend is not installed on Pulp.")}
            )

        try:
            backend(**storage_settings)
        except ImproperlyConfigured as e:
            raise serializers.ValidationError(
                detail={
                    "storage_settings": _("Backend settings contain incorrect values: {}".format(e))
                }
            )

    def create_storage(self):
        return self.fields["storage_settings"].create_storage()


class DomainSerializer(BackendSettingsValidator, ModelSerializer):
    """Serializer for Domain."""

    pulp_href = IdentityField(view_name="domains-detail")
    name = serializers.SlugField(
        max_length=50,
        help_text=_("A name for this domain."),
        validators=[UniqueValidator(queryset=Domain.objects.all())],
    )
    description = serializers.CharField(
        help_text=_("An optional description."), required=False, allow_null=True
    )
    pulp_labels = serializers.HStoreField(required=False, validators=[pulp_labels_validator])
    storage_class = serializers.ChoiceField(
        help_text=_("Backend storage class for domain."),
        choices=BACKEND_CHOICES,
    )
    storage_settings = StorageSettingsSerializer(
        source="*", help_text=_("Settings for storage class.")
    )
    redirect_to_object_storage = serializers.BooleanField(
        help_text=_("Boolean to have the content app redirect to object storage."),
        default=True,
    )
    hide_guarded_distributions = serializers.BooleanField(
        help_text=_("Boolean to hide distributions with a content guard in the content app."),
        default=False,
    )

    def validate_name(self, value):
        """Ensure name is not 'api' or 'content'."""
        if value.lower() in ("api", "content"):
            raise serializers.ValidationError(_("Name can not be 'api' or 'content'."))
        return value

    def validate(self, data):
        """Ensure that Domain settings are valid."""
        # Validate for update gets called before ViewSet default check
        if self.instance and self.instance.name == "default":
            return data

        storage_class = data.get("storage_class") or self.instance.storage_class
        storage_settings = data.get("storage_settings") or self.instance.storage_settings
        self._validate_storage_backend(storage_class, storage_settings)

        redirect = data.get("redirect_to_object_storage", True)
        if self.instance and "redirect_to_object_storage" not in data:
            redirect = self.instance.redirect_to_object_storage

        if redirect and storage_class == "pulpcore.app.models.storage.PulpSFTPStorage":
            raise serializers.ValidationError(
                detail={
                    "redirect_to_object_storage": _(
                        "This field does not support being used with the SFTP backend."
                    )
                }
            )
        return data

    class Meta:
        model = Domain
        fields = ModelSerializer.Meta.fields + (
            "name",
            "description",
            "pulp_labels",
            "storage_class",
            "storage_settings",
            "redirect_to_object_storage",
            "hide_guarded_distributions",
        )


class DomainBackendMigratorSerializer(BackendSettingsValidator, serializers.Serializer):
    """Special serializer for performing a storage backend migration on a Domain."""

    storage_class = serializers.ChoiceField(
        help_text=_("The new backend storage class to migrate to."),
        choices=BACKEND_CHOICES,
    )
    storage_settings = StorageSettingsSerializer(
        source="*", help_text=_("The settings for the new storage class to migrate to.")
    )

    def validate(self, data):
        """Validate new backend settings."""
        storage_class = data["storage_class"]
        storage_settings = data["storage_settings"]
        self._validate_storage_backend(storage_class, storage_settings)
        return data
