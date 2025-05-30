import os
from cryptography.x509 import load_pem_x509_certificate
from gettext import gettext as _
from urllib.parse import urlparse

from rest_framework import fields, serializers
from rest_framework_nested.serializers import NestedHyperlinkedModelSerializer

from pulpcore.app import models, settings
from pulpcore.app.util import get_prn
from pulpcore.app.serializers import (
    DetailIdentityField,
    DetailRelatedField,
    DomainUniqueValidator,
    LatestVersionField,
    ModelSerializer,
    RepositoryVersionIdentityField,
    RepositoryVersionRelatedField,
    RepositoryVersionsIdentityFromRepositoryField,
    ValidateFieldsMixin,
    HiddenFieldsMixin,
    pulp_labels_validator,
)
from pulpcore.app.util import extract_pk, raise_for_unknown_content_units


class RepositorySerializer(ModelSerializer):
    pulp_href = DetailIdentityField(view_name_pattern=r"repositories(-.*/.*)-detail")
    pulp_labels = serializers.HStoreField(required=False, validators=[pulp_labels_validator])
    versions_href = RepositoryVersionsIdentityFromRepositoryField()
    latest_version_href = LatestVersionField()
    name = serializers.CharField(
        help_text=_("A unique name for this repository."),
        validators=[DomainUniqueValidator(queryset=models.Repository.objects.all())],
    )
    description = serializers.CharField(
        help_text=_("An optional description."), required=False, allow_null=True
    )
    retain_repo_versions = serializers.IntegerField(
        help_text=_(
            "Retain X versions of the repository. Default is null which retains all versions."
        ),
        allow_null=True,
        required=False,
        min_value=1,
    )
    remote = DetailRelatedField(
        help_text=_("An optional remote to use by default when syncing."),
        view_name_pattern=r"remotes(-.*/.*)-detail",
        queryset=models.Remote.objects.all(),
        required=False,
        allow_null=True,
    )

    def validate_remote(self, value):
        if value and type(value) not in self.Meta.model.REMOTE_TYPES:
            raise serializers.ValidationError(
                detail=_("Type for Remote '{}' does not match Repository.").format(value.name)
            )

        return value

    class Meta:
        model = models.Repository
        fields = ModelSerializer.Meta.fields + (
            "versions_href",
            "pulp_labels",
            "latest_version_href",
            "name",
            "description",
            "retain_repo_versions",
            "remote",
        )


def validate_certificate(which_cert, value):
    """
    Validate and return *just* the certs and not any commentary that came along with them.

    Args:
        which_cert: The attribute-name whose cert we're validating (only used for error-message).
        value: The string being proposed as a certificate-containing PEM.

    Raises:
        ValidationError: When the provided value has no or an invalid certificate.

    Returns:
        The pem-string with *just* the validated BEGIN/END CERTIFICATE segments.
    """
    if value:
        try:
            # Find any/all CERTIFICATE entries in the proposed PEM and let crypto validate them.
            # NOTE: crypto/39 includes load_certificates(), which will let us remove this whole
            # loop. But we want to fix the current problem on older supported branches that
            # allow 38, so we do it ourselves for now
            certs = list()
            a_cert = ""
            for line in value.split("\n"):
                if "-----BEGIN CERTIFICATE-----" in line or a_cert:
                    a_cert += line + "\n"
                if "-----END CERTIFICATE-----" in line:
                    load_pem_x509_certificate(bytes(a_cert, "ASCII"))
                    certs.append(a_cert.strip())
                    a_cert = ""
            if not certs:
                raise serializers.ValidationError(
                    "No {} specified in string {}".format(which_cert, value)
                )
            return "\n".join(certs) + "\n"
        except ValueError as e:
            raise serializers.ValidationError(
                "Invalid {} specified, error '{}'".format(which_cert, e.args)
            )


class RemoteSerializer(ModelSerializer, HiddenFieldsMixin):
    """
    Every remote defined by a plugin should have a Remote serializer that inherits from this
    class. Please import from `pulpcore.plugin.serializers` rather than from this module directly.
    """

    pulp_href = DetailIdentityField(view_name_pattern=r"remotes(-.*/.*)-detail")
    pulp_labels = serializers.HStoreField(required=False, validators=[pulp_labels_validator])
    name = serializers.CharField(
        help_text=_("A unique name for this remote."),
        validators=[DomainUniqueValidator(queryset=models.Remote.objects.all())],
    )
    url = serializers.CharField(help_text="The URL of an external content source.")
    ca_cert = serializers.CharField(
        help_text="A PEM encoded CA certificate used to validate the server "
        "certificate presented by the remote server.",
        required=False,
        allow_null=True,
    )
    client_cert = serializers.CharField(
        help_text="A PEM encoded client certificate used for authentication.",
        required=False,
        allow_null=True,
    )
    client_key = serializers.CharField(
        help_text="A PEM encoded private key used for authentication.",
        required=False,
        allow_null=True,
        write_only=True,
    )
    tls_validation = serializers.BooleanField(
        help_text="If True, TLS peer validation must be performed.", required=False
    )
    proxy_url = serializers.CharField(
        help_text="The proxy URL. Format: scheme://host:port",
        required=False,
        allow_null=True,
    )
    proxy_username = serializers.CharField(
        help_text="The username to authenticte to the proxy.",
        required=False,
        allow_null=True,
        write_only=True,
    )
    proxy_password = serializers.CharField(
        help_text=_(
            "The password to authenticate to the proxy. Extra leading and trailing whitespace "
            "characters are not trimmed."
        ),
        required=False,
        allow_null=True,
        write_only=True,
        trim_whitespace=False,
        style={"input_type": "password"},
    )
    username = serializers.CharField(
        help_text="The username to be used for authentication when syncing.",
        required=False,
        allow_null=True,
        write_only=True,
    )
    password = serializers.CharField(
        help_text=_(
            "The password to be used for authentication when syncing. Extra leading and trailing "
            "whitespace characters are not trimmed."
        ),
        required=False,
        allow_null=True,
        write_only=True,
        trim_whitespace=False,
        style={"input_type": "password"},
    )
    pulp_last_updated = serializers.DateTimeField(
        help_text="Timestamp of the most recent update of the remote.", read_only=True
    )
    download_concurrency = serializers.IntegerField(
        help_text=(
            "Total number of simultaneous connections. If not set then the default "
            "value will be used."
        ),
        allow_null=True,
        required=False,
        min_value=1,
    )
    max_retries = serializers.IntegerField(
        help_text=(
            "Maximum number of retry attempts after a download failure. If not set then the "
            "default value (3) will be used."
        ),
        required=False,
        allow_null=True,
    )
    policy = serializers.ChoiceField(
        help_text="The policy to use when downloading content.",
        choices=(
            (models.Remote.IMMEDIATE, "When syncing, download all metadata and content now."),
        ),
        default=models.Remote.IMMEDIATE,
    )

    total_timeout = serializers.FloatField(
        allow_null=True,
        required=False,
        help_text=(
            "aiohttp.ClientTimeout.total (q.v.) for download-connections. The default is null, "
            "which will cause the default from the aiohttp library to be used."
        ),
        min_value=0.0,
    )
    connect_timeout = serializers.FloatField(
        allow_null=True,
        required=False,
        help_text=(
            "aiohttp.ClientTimeout.connect (q.v.) for download-connections. The default is null, "
            "which will cause the default from the aiohttp library to be used."
        ),
        min_value=0.0,
    )
    sock_connect_timeout = serializers.FloatField(
        allow_null=True,
        required=False,
        help_text=(
            "aiohttp.ClientTimeout.sock_connect (q.v.) for download-connections. The default is "
            "null, which will cause the default from the aiohttp library to be used."
        ),
        min_value=0.0,
    )
    sock_read_timeout = serializers.FloatField(
        allow_null=True,
        required=False,
        help_text=(
            "aiohttp.ClientTimeout.sock_read (q.v.) for download-connections. The default is "
            "null, which will cause the default from the aiohttp library to be used."
        ),
        min_value=0.0,
    )
    headers = serializers.ListField(
        child=serializers.DictField(),
        help_text=_("Headers for aiohttp.Clientsession"),
        required=False,
    )
    rate_limit = serializers.IntegerField(
        help_text=_("Limits requests per second for each concurrent downloader"),
        allow_null=True,
        required=False,
    )

    def validate_url(self, url):
        """
        Check if the 'url' is a ``file://`` path, and if so, ensure it's an ALLOWED_IMPORT_PATH.

        The ALLOWED_IMPORT_PATH is specified as a Pulp setting.

        Args:
            url: The user-provided value for 'url' to be validated.

        Raises:
            ValidationError: When the url starts with `file://`, but is not a subfolder of a path in
                the ALLOWED_IMPORT_PATH setting.

        Returns:
            The validated value.
        """
        parsed_url = urlparse(url)
        if parsed_url.username or parsed_url.password:
            raise serializers.ValidationError(
                _(
                    "The remote url contains username or password. Please use remote username or "
                    "password instead."
                )
            )

        if not url.lower().startswith("file://"):
            return url

        user_path = url[7:]
        if not os.path.isabs(user_path):
            raise serializers.ValidationError(
                _("The path '{}' needs to be an absolute pathname.").format(user_path)
            )

        user_provided_realpath = os.path.realpath(user_path)

        for allowed_path in settings.ALLOWED_IMPORT_PATHS:
            if user_provided_realpath.startswith(allowed_path):
                return url

        raise serializers.ValidationError(
            _("The path '{}' does not start with any of the allowed import paths").format(user_path)
        )

    def validate_proxy_url(self, value):
        """
        Check, that the proxy_url does not contain credentials.
        """
        if value and "@" in value:
            raise serializers.ValidationError(_("proxy_url must not contain credentials"))
        return value

    def validate_ca_cert(self, value):
        return validate_certificate("ca_cert", value)

    def validate_client_cert(self, value):
        return validate_certificate("client_cert", value)

    def validate(self, data):
        """
        Check, that proxy credentials are only provided completely and if a proxy is configured.
        """
        data = super().validate(data)

        proxy_url = self.instance.proxy_url if self.partial else None
        proxy_url = data.get("proxy_url", proxy_url)
        proxy_username = self.instance.proxy_username if self.partial else None
        proxy_username = data.get("proxy_username", proxy_username)
        proxy_password = self.instance.proxy_password if self.partial else None
        proxy_password = data.get("proxy_password", proxy_password)

        if (proxy_username or proxy_password) and not proxy_url:
            raise serializers.ValidationError(
                _("proxy credentials cannot be specified without a proxy")
            )

        if bool(proxy_username) is not bool(proxy_password):
            raise serializers.ValidationError(
                _("proxy username and password can only be specified together")
            )

        return data

    class Meta:
        abstract = True
        model = models.Remote
        fields = ModelSerializer.Meta.fields + (
            "name",
            "url",
            "ca_cert",
            "client_cert",
            "client_key",
            "tls_validation",
            "proxy_url",
            "proxy_username",
            "proxy_password",
            "username",
            "password",
            "pulp_labels",
            "pulp_last_updated",
            "download_concurrency",
            "max_retries",
            "policy",
            "total_timeout",
            "connect_timeout",
            "sock_connect_timeout",
            "sock_read_timeout",
            "headers",
            "rate_limit",
            "hidden_fields",
        )


class GenericRemoteSerializer(RemoteSerializer):
    policy = serializers.ChoiceField(
        help_text="The policy to use when downloading content.",
        choices=models.Remote.POLICY_CHOICES,
        default=models.Remote.IMMEDIATE,
    )


class RepositorySyncURLSerializer(ValidateFieldsMixin, serializers.Serializer):
    remote = DetailRelatedField(
        required=False,
        view_name_pattern=r"remotes(-.*/.*)-detail",
        queryset=models.Remote.objects.all(),
        help_text=_("A remote to sync from. This will override a remote set on repository."),
    )

    mirror = fields.BooleanField(
        required=False,
        default=False,
        help_text=_(
            "If ``True``, synchronization will remove all content that is not present in "
            "the remote repository. If ``False``, sync will be additive only."
        ),
    )

    def validate(self, data):
        data = super().validate(data)
        repository = None
        if "repository_pk" in self.context:
            repository = models.Repository.objects.get(pk=self.context["repository_pk"])
        remote = data.get("remote", None) or getattr(repository, "remote", None)

        if not remote:
            raise serializers.ValidationError(
                {"remote": _("This field is required since a remote is not set on the repository.")}
            )
        if repository and type(remote.cast()) not in repository.cast().REMOTE_TYPES:
            raise serializers.ValidationError(
                {
                    "remote": _("Type for Remote '{}' does not match Repository '{}'.").format(
                        get_prn(remote), get_prn(repository)
                    )
                }
            )
        self.check_cross_domains({"repository": repository, "remote": remote})
        return data


class ContentSummarySerializer(serializers.Serializer):
    """
    Serializer for the RepositoryVersion content summary
    """

    def to_representation(self, obj):
        """
        The summary of contained content.

        Returns:
            dict: The dictionary has the following format.::

                {
                    'added': {<pulp_type>: {'count': <count>, 'href': <href>},
                    'removed': {<pulp_type>: {'count': <count>, 'href': <href>},
                    'present': {<pulp_type>: {'count': <count>, 'href': <href>},
                }

        """
        to_return = {"added": {}, "removed": {}, "present": {}}
        request = self.context.get("request")
        for count_detail in obj.counts.all():
            count_type = count_detail.get_count_type_display()
            item_dict = {
                "count": count_detail.count,
                "href": count_detail.get_content_href(request=request),
            }
            to_return[count_type][count_detail.content_type] = item_dict

        return to_return

    def to_internal_value(self, data):
        """
        Setting the internal value.
        """
        return {
            self.added: data["added"],
            self.removed: data["removed"],
            self.present: data["present"],
        }

    added = serializers.DictField(child=serializers.DictField())

    removed = serializers.DictField(child=serializers.DictField())

    present = serializers.DictField(child=serializers.DictField())


class RepositoryVersionSerializer(ModelSerializer, NestedHyperlinkedModelSerializer):
    pulp_href = RepositoryVersionIdentityField()
    number = serializers.IntegerField(read_only=True)
    repository = DetailRelatedField(
        view_name_pattern=r"repositories(-.*/.*)?-detail",
        read_only=True,
    )
    base_version = RepositoryVersionRelatedField(
        required=False,
        help_text=_(
            "A repository version whose content was used as the initial set of content "
            "for this repository version"
        ),
    )
    content_summary = ContentSummarySerializer(
        help_text=_(
            "Various count summaries of the content in the version and the HREF to view them."
        ),
        source="*",
        read_only=True,
    )

    class Meta:
        model = models.RepositoryVersion
        fields = ModelSerializer.Meta.fields + (
            "pulp_href",
            "number",
            "repository",
            "base_version",
            "content_summary",
        )


class RepositoryAddRemoveContentSerializer(ModelSerializer, NestedHyperlinkedModelSerializer):
    add_content_units = serializers.ListField(
        help_text=_(
            "A list of content units to add to a new repository version. This content is "
            "added after remove_content_units are removed."
        ),
        child=serializers.CharField(error_messages={"invalid": "Not a valid URI of a resource."}),
        required=False,
    )
    remove_content_units = serializers.ListField(
        help_text=_(
            "A list of content units to remove from the latest repository version. "
            "You may also specify '*' as an entry to remove all content. This content is "
            "removed before add_content_units are added."
        ),
        child=serializers.CharField(error_messages={"invalid": "Not a valid URI of a resource."}),
        required=False,
    )
    base_version = RepositoryVersionRelatedField(
        required=False,
        help_text=_(
            "A repository version whose content will be used as the initial set of content "
            "for the new repository version"
        ),
    )

    def validate_add_content_units(self, value):
        add_content_units = {}

        for url in value:
            add_content_units[extract_pk(url)] = url

        content_units_pks = set(add_content_units.keys())
        existing_content_units = models.Content.objects.filter(pk__in=content_units_pks)
        existing_content_units.touch()

        raise_for_unknown_content_units(existing_content_units, add_content_units)

        return list(add_content_units.keys())

    def validate_remove_content_units(self, value):
        remove_content_units = {}

        if "*" in value:
            if len(value) > 1:
                raise serializers.ValidationError("Cannot supply content units and '*'.")
            else:
                return ["*"]
        else:
            for url in value:
                remove_content_units[extract_pk(url)] = url
            content_units_pks = set(remove_content_units.keys())
            existing_content_units = models.Content.objects.filter(pk__in=content_units_pks)
            raise_for_unknown_content_units(existing_content_units, remove_content_units)
            return list(remove_content_units.keys())

    class Meta:
        model = models.RepositoryVersion
        fields = ["add_content_units", "remove_content_units", "base_version"]
