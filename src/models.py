# pylint: disable=no-self-argument, arguments-differ
import json
from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import Union, Any, Optional
from datetime import datetime, timezone
from uuid import UUID
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

from pydantic import (
    BaseModel,
    Field,
    HttpUrl,
    AnyHttpUrl,
    validator,
    conint,
    PositiveInt,
    PositiveFloat,
    IPvAnyAddress,
)
from boto3.dynamodb.conditions import Key

import internals
import services.aws


class DAL(metaclass=ABCMeta):
    @abstractmethod
    def exists(self, **kwargs) -> bool:
        raise NotImplementedError

    @abstractmethod
    def load(self, **kwargs) -> bool:
        raise NotImplementedError

    @abstractmethod
    def save(self, **kwargs) -> bool:
        raise NotImplementedError

    @abstractmethod
    def delete(self, **kwargs) -> bool:
        raise NotImplementedError


class OutputType(str, Enum):
    JSON = "json"
    CONSOLE = "console"


class OutputWhen(str, Enum):
    FINAL = "final"
    PER_HOST = "per_host"
    PER_CERTIFICATE = "per_certificate"


class CertificateType(str, Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    LEAF = "leaf"
    CLIENT = "client"


class ValidationLevel(str, Enum):
    DOMAIN_VALIDATION = "Domain Validation (DV)"
    ORGANIZATION_VALIDATION = "Organization Validation (OV)"
    EXTENDED_VALIDATION = "Extended Validation (EV)"


class PublicKeyType(str, Enum):
    RSA = "RSA"
    DSA = "DSA"
    EC = "EC"
    DH = "DH"


class ReportType(str, Enum):
    HOST = "host"
    CERTIFICATE = "certificate"
    REPORT = "report"
    EVALUATIONS = "evaluations"


class ReferenceType(str, Enum):
    WEBSITE = "website"
    JSON = "json"


class ComplianceName(str, Enum):
    PCI_DSS = "PCI DSS"
    NIST_SP800_131A = "NIST SP800-131A"
    FIPS_140_2 = "FIPS 140-2"


class ThreatIntelSource(str, Enum):
    CHARLES_HALEY = "CharlesHaley"
    DATAPLANE = "DataPlane"
    TALOS_INTELLIGENCE = "TalosIntelligence"
    DARKLIST = "Darklist"
    PROOFPOINT = "ProofPoint"


class MfaSetting(str, Enum):
    ENROLL = "enroll"
    OPT_OUT = "opt_out"


class ScanRecordType(str, Enum):
    INTERNAL = "Internal"
    MONITORING = "Managed Monitoring"
    ONDEMAND = "Managed On-demand"
    SELF_MANAGED = "Customer-managed"
    SUBDOMAINS = "Subdomains"


class ScanRecordCategory(str, Enum):
    ASM = "Attack Surface Monitoring"
    RECONNAISSANCE = "Reconnaissance"
    OSINT = "Public Data Sources"
    INTEGRATION_DATA = "Third Party Integration"


class GraphLabelRanges(str, Enum):
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"


class GraphLabel(str, Enum):
    PCIDSS3 = "PCI DSS v3.2.1"
    PCIDSS4 = "PCI DSS v4.0"
    NISTSP800_131A_STRICT = "NIST SP800-131A (strict mode)"
    NISTSP800_131A_TRANSITION = "NIST SP800-131A (transition mode)"
    FIPS1402 = "FIPS 140-2 Annex A"


class Quota(str, Enum):
    USED = "used"
    TOTAL = "total"
    PERIOD = "period"


class ObservedSource(str, Enum):
    TRIVIAL_SCANNER = "Trivial Scanner"
    OSINT = "Open Source Intelligence"


class WebhookEvent(str, Enum):
    HOSTED_MONITORING = "hosted_monitoring"
    HOSTED_SCANNER = "hosted_scanner"
    SELF_HOSTED_UPLOADS = "self_hosted_uploads"
    EARLY_WARNING_EMAIL = "early_warning_email"
    EARLY_WARNING_DOMAIN = "early_warning_domain"
    EARLY_WARNING_IP = "early_warning_ip"
    NEW_FINDINGS_CERTIFICATES = "new_findings_certificates"
    NEW_FINDINGS_DOMAINS = "new_findings_domains"
    CLIENT_STATUS = "client_status"
    CLIENT_ACTIVITY = "client_activity"
    SCANNER_CONFIGURATIONS = "scanner_configurations"
    REPORT_CREATED = "report_created"
    REPORT_DELETED = "report_deleted"
    ACCOUNT_ACTIVITY = "account_activity"
    MEMBER_ACTIVITY = "member_activity"


class DataPlaneCategory(str, Enum):
    SSH_CLIENT = "sshclient"
    SSH_PW_AUTH = "sshpwauth"
    DNS_RECURSIVE_QUERIES = "dnsrd"
    VNC_REMOTE_FRAME_BUFFER = "vncrfb"


class WebauthnEnrollType(str, Enum):
    PUBLIC_KEY = "public-key"


class AccountRegistration(BaseModel):
    name: str
    display: Optional[str]
    primary_email: Optional[str]


class Billing(BaseModel):
    product_name: str
    is_trial: bool = Field(default=False)
    description: Optional[str]
    display_amount: str = Field(default="free")
    display_period: Optional[str]
    next_due: Optional[int]
    has_invoice: bool = Field(default=False)


class AccountNotifications(BaseModel):
    scan_completed: Optional[bool] = Field(default=False)
    monitor_completed: Optional[bool] = Field(default=False)
    self_hosted_uploads: Optional[bool] = Field(default=False)
    early_warning: Optional[bool] = Field(default=False)
    new_findings_certificates: Optional[bool] = Field(default=False)
    new_findings_domains: Optional[bool] = Field(default=False)


class Webhooks(BaseModel):
    endpoint: AnyHttpUrl = Field(default=None)
    signing_secret: Optional[str]
    hosted_monitoring: Optional[bool] = Field(default=False)
    hosted_scanner: Optional[bool] = Field(default=False)
    self_hosted_uploads: Optional[bool] = Field(default=False)
    early_warning_email: Optional[bool] = Field(default=False)
    early_warning_domain: Optional[bool] = Field(default=False)
    early_warning_ip: Optional[bool] = Field(default=False)
    new_findings_certificates: Optional[bool] = Field(default=False)
    new_findings_domains: Optional[bool] = Field(default=False)
    client_status: Optional[bool] = Field(default=False)
    client_activity: Optional[bool] = Field(default=False)
    scanner_configurations: Optional[bool] = Field(default=False)
    report_created: Optional[bool] = Field(default=False)
    report_deleted: Optional[bool] = Field(default=False)
    account_activity: Optional[bool] = Field(default=False)
    member_activity: Optional[bool] = Field(default=False)


class MemberAccount(AccountRegistration, DAL):
    billing_email: Optional[str]
    billing_client_id: Optional[str]
    api_key: Optional[str]
    ip_addr: Optional[IPvAnyAddress]
    user_agent: Optional[str]
    timestamp: Optional[int]
    mfa: MfaSetting = Field(default=MfaSetting.ENROLL)
    billing: Union[Billing, None] = Field(default=None)
    notifications: Optional[AccountNotifications] = Field(
        default=AccountNotifications()
    )
    webhooks: Optional[list[Webhooks]] = Field(default=[])

    def exists(
        self,
        account_name: Union[str, None] = None,
        billing_client_id: Union[str, None] = None,
    ) -> bool:
        return self.load(account_name, billing_client_id)

    def load(
        self,
        account_name: Union[str, None] = None,
        billing_client_id: Union[str, None] = None,
    ) -> bool:
        if account_name:
            self.name = account_name
        if not self.name:
            return False
        if billing_client_id:
            self.billing_client_id = billing_client_id
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing account object: {object_key}")
            return False
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return False
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing account data for object: {object_key}")
            return False
        super().__init__(**data)
        return True

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD,
        )

    def delete(self) -> Union[bool, None]:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.delete_s3(object_key)


class ClientInfo(BaseModel):
    operating_system: Optional[str]
    operating_system_release: Optional[str]
    operating_system_version: Optional[str]
    architecture: Optional[str]


class Client(BaseModel, DAL):
    account_name: Optional[str]
    client_info: Optional[ClientInfo]
    name: str
    cli_version: Optional[str]
    access_token: Optional[str]
    ip_addr: Optional[IPvAnyAddress]
    user_agent: Optional[str]
    timestamp: Optional[int]
    active: Optional[bool] = Field(default=False)

    def exists(
        self,
        account_name: Union[str, None] = None,
        client_name: Union[str, None] = None,
    ) -> bool:
        return self.load(account_name, client_name) is not None

    def load(
        self,
        account_name: Union[str, None] = None,
        client_name: Union[str, None] = None,
    ) -> Union["Client", None]:
        if client_name:
            self.name = client_name
        if account_name:
            self.account_name = account_name

        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/client-tokens/{self.name}.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing account object: {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing account data for object: {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/client-tokens/{self.name}.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD,
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/client-tokens/{self.name}.json"
        return services.aws.delete_s3(object_key)


class ConfigDefaults(BaseModel):
    use_sni: bool
    cafiles: Optional[str]
    tmp_path_prefix: str = Field(default="/tmp")
    http_path: str = Field(default="/")
    checkpoint: Optional[bool]


class ConfigOutput(BaseModel):
    type: OutputType
    use_icons: Optional[bool]
    when: OutputWhen = Field(default=OutputWhen.FINAL)
    path: Optional[str]


class ConfigTarget(BaseModel):
    hostname: str
    port: PositiveInt = Field(default=443)
    client_certificate: Optional[str]
    http_request_paths: list[str] = Field(default=["/"])


class CLIConfig(BaseModel):
    account_name: Optional[str] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Optional[str] = Field(
        default=None, description="Machine name where trivialscan CLI execcutes"
    )
    project_name: Optional[str] = Field(
        default=None, description="Trivial Scanner project assignment for the report"
    )
    defaults: ConfigDefaults
    outputs: list[ConfigOutput]
    targets: list[ConfigTarget]


class Flags(BaseModel):
    hide_progress_bars: Optional[bool]
    synchronous_only: Optional[bool]
    hide_banner: Optional[bool]
    track_changes: Optional[bool]
    previous_report: Optional[str]
    quiet: Optional[bool]


class HostTLSProtocol(BaseModel):
    negotiated: str
    preferred: str
    offered: list[str]


class HostTLSCipher(BaseModel):
    forward_anonymity: Optional[bool] = Field(default=False)
    offered: list[str]
    offered_rfc: Optional[list[str]]
    negotiated: str
    negotiated_bits: PositiveInt
    negotiated_rfc: Optional[str]


class HostTLSClient(BaseModel):
    certificate_mtls_expected: Optional[bool] = Field(default=False)
    certificate_trusted: Optional[bool] = Field(default=False)
    certificate_match: Optional[bool] = Field(default=False)
    expected_client_subjects: list[str] = Field(default=[])


class HostTLSSessionResumption(BaseModel):
    cache_mode: str
    tickets: bool
    ticket_hint: bool


class HostTLS(BaseModel):
    certificates: list[str] = Field(default=[])
    client: HostTLSClient
    cipher: HostTLSCipher
    protocol: HostTLSProtocol
    session_resumption: HostTLSSessionResumption


class HostHTTP(BaseModel):
    title: Optional[str]
    status_code: Optional[conint(ge=100, le=599)]  # type: ignore
    headers: Optional[dict[str, str]]
    body_hash: Optional[str]
    request_url: Optional[str]


class HostTransport(BaseModel):
    error: Optional[tuple[str, str]]
    hostname: str = Field(title="Domain Name")
    port: PositiveInt = Field(default=443)
    sni_support: Optional[bool]
    peer_address: Optional[IPvAnyAddress]
    certificate_mtls_expected: Optional[bool] = Field(default=False)


class ThreatIntel(BaseModel):
    id: UUID
    account_name: str
    source: ThreatIntelSource
    feed_identifier: Any
    feed_date: datetime
    feed_data: Any
    matching_data: Optional[Any]

    class Config:
        validate_assignment = True

    @validator("feed_date")
    def set_feed_date(cls, feed_date: datetime):
        return feed_date.replace(tzinfo=timezone.utc)


class EarlyWarningAlert(ThreatIntel):
    summary: str
    description: str
    abuse: str
    reference_url: Optional[HttpUrl]


class Host(BaseModel, DAL):
    last_updated: Optional[datetime]
    transport: HostTransport
    tls: Optional[HostTLS]
    http: Optional[list[HostHTTP]]
    monitoring_enabled: Optional[bool] = Field(default=False)
    threat_intel: Optional[list[ThreatIntel]] = Field(default=[])

    class Config:
        validate_assignment = True

    @validator("last_updated")
    def set_last_updated(cls, last_updated: datetime):
        return last_updated.replace(tzinfo=timezone.utc) if last_updated else None

    def exists(
        self,
        hostname: Union[str, None] = None,
        port: Union[int, None] = 443,
        peer_address: Union[str, None] = None,
        last_updated: Union[datetime, None] = None,
    ) -> bool:
        return self.load(hostname, port, peer_address, last_updated)

    def load(
        self,
        hostname: Union[str, None] = None,
        port: Union[int, None] = 443,
        peer_address: Union[str, None] = None,
        last_updated: Union[datetime, None] = None,
    ) -> bool:
        if last_updated:
            self.last_updated = last_updated
        if hostname:
            self.transport = HostTransport(
                hostname=hostname, port=port, peer_address=peer_address
            )  # type: ignore

        prefix_key = (
            f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}"
        )
        if self.transport.peer_address and self.last_updated:
            scan_date = self.last_updated.strftime("%Y%m%d")
            object_key = f"{prefix_key}/{self.transport.peer_address}/{scan_date}.json"
        else:
            object_key = f"{prefix_key}/latest.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing Host {object_key}")
            return False
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return False
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Host {object_key}")
            return False
        super().__init__(**data)
        return True

    def save(self) -> bool:
        data = self.dict()
        scan_date = self.last_updated.strftime("%Y%m%d")  # type: ignore
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        if not services.aws.store_s3(object_key, json.dumps(data, default=str)):
            return False
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/latest.json"
        return services.aws.store_s3(object_key, json.dumps(data, default=str))

    def delete(self) -> bool:
        scan_date = self.last_updated.strftime("%Y%m%d")  # type: ignore
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        return services.aws.delete_s3(object_key)


class Certificate(BaseModel, DAL):
    authority_key_identifier: Optional[str]
    expired: Optional[bool]
    expiry_status: Optional[str]
    extensions: Optional[list] = Field(default=[])
    external_refs: Optional[dict[str, Optional[AnyHttpUrl]]] = Field(default={})
    is_self_signed: Optional[bool]
    issuer: Optional[str]
    known_compromised: Optional[bool]
    md5_fingerprint: Optional[str]
    not_after: Optional[datetime]
    not_before: Optional[datetime]
    public_key_curve: Optional[str]
    public_key_exponent: Optional[PositiveInt]
    public_key_modulus: Optional[PositiveInt]
    public_key_size: Optional[PositiveInt]
    public_key_type: Optional[PublicKeyType]
    revocation_crl_urls: Optional[list[AnyHttpUrl]] = Field(default=[])
    san: Optional[list[str]] = Field(default=[])
    serial_number: Optional[str]
    serial_number_decimal: Optional[Any]
    serial_number_hex: Optional[str]
    sha1_fingerprint: str
    sha256_fingerprint: Optional[str]
    signature_algorithm: Optional[str]
    spki_fingerprint: Optional[str]
    subject: Optional[str]
    subject_key_identifier: Optional[str]
    validation_level: Optional[ValidationLevel]
    validation_oid: Optional[str]
    version: Optional[Any] = Field(default=None)
    type: Optional[CertificateType]

    class Config:
        validate_assignment = True

    @validator("not_after")
    def set_not_after(cls, not_after: datetime):
        return not_after.replace(tzinfo=timezone.utc) if not_after else None

    @validator("not_before")
    def set_not_before(cls, not_before: datetime):
        return not_before.replace(tzinfo=timezone.utc) if not_before else None

    def exists(self, sha1_fingerprint: Union[str, None] = None) -> bool:
        return self.load(sha1_fingerprint)

    def load(self, sha1_fingerprint: Union[str, None] = None) -> bool:
        if sha1_fingerprint:
            self.sha1_fingerprint = sha1_fingerprint

        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing Certificate {object_key}")
            return False
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return False
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Certificate {object_key}")
            return False
        super().__init__(**data)
        return True

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        return services.aws.store_s3(object_key, json.dumps(self.dict(), default=str))

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        return services.aws.delete_s3(object_key)


class ComplianceItem(BaseModel):
    requirement: Optional[str]
    title: Optional[str]
    description: Optional[str]


class ComplianceGroup(BaseModel):
    compliance: Optional[ComplianceName]
    version: Optional[str]
    items: Optional[list[ComplianceItem]] = Field(default=[])


class ThreatItem(BaseModel):
    standard: str
    version: str
    tactic: Optional[str]
    tactic_id: Optional[str]
    tactic_url: Optional[AnyHttpUrl]
    tactic_description: Optional[str]
    technique: Optional[str]
    technique_id: Optional[str]
    technique_url: Optional[AnyHttpUrl]
    technique_description: Optional[str]
    mitigation: Optional[str]
    mitigation_id: Optional[str]
    mitigation_url: Optional[AnyHttpUrl]
    mitigation_description: Optional[str]
    sub_technique: Optional[str]
    sub_technique_id: Optional[str]
    sub_technique_url: Optional[AnyHttpUrl]
    sub_technique_description: Optional[str]
    data_source: Optional[str]
    data_source_id: Optional[str]
    data_source_url: Optional[AnyHttpUrl]
    data_source_description: Optional[str]


class ReferenceItem(BaseModel):
    name: str
    url: AnyHttpUrl
    type: Optional[ReferenceType] = Field(default=ReferenceType.WEBSITE)


class DefaultInfo(BaseModel):
    generator: str = Field(default="trivialscan")
    version: Optional[str] = Field(default=None, description="trivialscan CLI version")
    account_name: Optional[str] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Optional[str] = Field(
        default=None, description="Machine name where trivialscan CLI executes"
    )


class ReportSummary(DefaultInfo):
    class Config:
        validate_assignment = True

    report_id: str
    project_name: Optional[str]
    targets: list[Host] = Field(default=[])
    date: Optional[datetime]
    execution_duration_seconds: Optional[PositiveFloat]
    score: int = Field(default=0)
    results: Optional[dict[str, int]]
    certificates: Optional[list[Certificate]] = Field(default=[])
    results_uri: Optional[str]
    flags: Optional[Flags]
    config: Optional[CLIConfig]
    client: Optional[ClientInfo]
    type: Optional[ScanRecordType]
    category: Optional[ScanRecordCategory]
    is_passive: Optional[bool] = Field(default=True)

    @validator("date")
    def set_date(cls, date: datetime):
        return date.replace(tzinfo=timezone.utc) if date else None


class EvaluationItem(DefaultInfo):
    class Config:
        validate_assignment = True

    report_id: str
    rule_id: int
    group_id: int
    key: str
    name: str
    group: str
    observed_at: Optional[datetime]
    result_value: Union[bool, str, None]
    result_label: str
    result_text: str
    result_level: Optional[str]
    score: int = Field(default=0)
    description: Optional[str]
    recommendation: Optional[str]
    metadata: dict[str, Any] = Field(default={})
    cve: Optional[list[str]] = Field(default=[])
    cvss2: Union[str, Any] = Field(default=None)
    cvss3: Union[str, Any] = Field(default=None)
    references: Optional[list[ReferenceItem]] = Field(default=[])
    compliance: Optional[list[ComplianceGroup]] = Field(default=[])
    threats: Optional[list[ThreatItem]] = Field(default=[])
    transport: Optional[HostTransport]
    certificate: Optional[Certificate]

    @validator("observed_at")
    def set_observed_at(cls, observed_at: datetime):
        return observed_at.replace(tzinfo=timezone.utc) if observed_at else None

    @validator("references")
    def set_references(cls, references):
        return references if isinstance(references, list) else []

    @validator("cvss2")
    def set_cvss2(cls, cvss2):
        return cvss2 if isinstance(cvss2, str) else None

    @validator("cvss3")
    def set_cvss3(cls, cvss3):
        return cvss3 if isinstance(cvss3, str) else None


class FullReport(ReportSummary, DAL):
    evaluations: Optional[list[EvaluationItem]] = Field(default=[])

    def exists(
        self, report_id: Union[str, None] = None, account_name: Union[str, None] = None
    ) -> bool:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.object_exists(object_key)

    def load(
        self, report_id: Union[str, None] = None, account_name: Union[str, None] = None
    ) -> bool:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name

        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing FullReport {object_key}")
            return False
        if data := json.loads(raw):
            super().__init__(**data)
        return True

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.delete_s3(object_key)

class AccountQuotas(BaseModel):
    unlimited_monitoring: bool
    unlimited_scans: bool
    monitoring: dict[Quota, Any]
    ondemand: dict[Quota, Any]
    seen_hosts: list[str]
    monitoring_hosts: list[str]


class MonitorHostname(BaseModel):
    hostname: str
    ports: Optional[list[int]] = Field(default=[443])
    timestamp: int
    enabled: bool = Field(default=False)
    path_names: Optional[list[str]] = Field(default=["/"])


class ObservedIdentifier(BaseModel):
    id: UUID
    account_name: str
    source: ObservedSource
    source_data: Any
    address: Union[IPv4Address, IPv6Address, IPv4Network, IPv6Network]
    date: datetime


class ScannerRecord(BaseModel, DAL):
    account_name: str
    monitored_targets: list[MonitorHostname] = Field(default=[])
    history: list[ReportSummary] = Field(default=[])
    ews: list[ThreatIntel] = Field(default=[])
    observed_identifiers: list[ObservedIdentifier] = Field(default=[])

    @property
    def object_key(self):
        if not self.account_name:
            raise AttributeError
        return f"{internals.APP_ENV}/accounts/{self.account_name}/scanner-record.json"

    def exists(self, account_name: Union[str, None] = None) -> bool:
        if account_name:
            self.account_name = account_name
        return services.aws.object_exists(self.object_key) is True

    def load(
        self,
        account_name: Union[str, None] = None,
        load_history: bool = False,
        load_ews: bool = False,
        load_identifiers: bool = False,
    ) -> bool:
        if account_name:
            self.account_name = account_name
        raw = services.aws.get_s3(path_key=self.object_key)
        if not raw:
            internals.logger.warning(f"Missing Queue {self.object_key}")
            return False
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return False
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Queue {self.object_key}")
            return False
        super().__init__(**data)
        if load_history:
            self.history = [
                ReportSummary(
                    **services.aws.get_dynamodb(  # type: ignore
                        table_name=services.aws.Tables.REPORT_HISTORY,
                        item_key={"report_id": item["report_id"]},
                    )
                )
                for item in services.aws.query_dynamodb(
                    table_name=services.aws.Tables.REPORT_HISTORY,
                    IndexName="account_name-index",
                    KeyConditionExpression=Key("account_name").eq(self.account_name),
                )
            ]
        if load_ews:
            self.ews = [
                ThreatIntel(
                    **services.aws.get_dynamodb(  # type: ignore
                        table_name=services.aws.Tables.EARLY_WARNING_SERVICE,
                        item_key={"id": item["id"]},
                    )
                )
                for item in services.aws.query_dynamodb(
                    table_name=services.aws.Tables.EARLY_WARNING_SERVICE,
                    IndexName="account_name-index",
                    KeyConditionExpression=Key("account_name").eq(self.account_name),
                )
            ]
        if load_identifiers:
            self.observed_identifiers = [
                ObservedIdentifier(
                    **services.aws.get_dynamodb(  # type: ignore
                        table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                        item_key={"id": item["id"]},
                    )
                )
                for item in services.aws.query_dynamodb(
                    table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                    IndexName="account_name-index",
                    KeyConditionExpression=Key("account_name").eq(self.account_name),
                )
            ]

        return True

    def save(self) -> bool:
        for report in self.history:
            services.aws.put_dynamodb(
                table_name=services.aws.Tables.REPORT_HISTORY, item=report.dict()
            )
        for ews in self.ews:
            services.aws.put_dynamodb(
                table_name=services.aws.Tables.EARLY_WARNING_SERVICE, item=ews.dict()
            )
        for identifier in self.observed_identifiers:
            services.aws.put_dynamodb(
                table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                item=identifier.dict(),
            )
        data = self.dict()
        del data["history"]
        del data["ews"]
        del data["observed_identifiers"]
        return services.aws.store_s3(self.object_key, json.dumps(data, default=str))

    def delete(self) -> bool:
        for report in self.history:
            services.aws.delete_dynamodb(
                table_name=services.aws.Tables.REPORT_HISTORY,
                item_key={"report_id": report.report_id},
            )
        for ews in self.ews:
            services.aws.delete_dynamodb(
                table_name=services.aws.Tables.EARLY_WARNING_SERVICE,
                item_key={"id": str(ews.id)},
            )
        for identifier in self.observed_identifiers:
            services.aws.delete_dynamodb(
                table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                item_key={"id": str(identifier.id)},
            )
        return services.aws.delete_s3(self.object_key)


class WebhookPayload(BaseModel):
    event_id: UUID
    event_name: WebhookEvent
    timestamp: datetime
    payload: dict

    class Config:
        validate_assignment = True

    @validator("timestamp")
    def set_timestamp(cls, timestamp: datetime):
        return timestamp.replace(tzinfo=timezone.utc) if timestamp else None


class ComplianceChartItem(BaseModel):
    name: str
    num: int
    timestamp: int


class DashboardCompliance(BaseModel):
    label: GraphLabel
    ranges: list[GraphLabelRanges]
    data: dict[GraphLabelRanges, list[ComplianceChartItem]]


class FindingStatus(str, Enum):
    DISCOVERED = 'discovered' # last_seen
    TRIAGED = 'triaged'
    WONT_FIX = 'wont_fix' # closed
    DEFERRED = 'deferred'
    REMEDIATED = 'remediated'


class FindingOccurrence(BaseModel):
    report_ids: Optional[list[str]] = Field(default=[])
    hostname: str
    port: int
    last_seen: Optional[datetime]
    certificate_sha1: Optional[str]
    status: Optional[FindingStatus] = Field(default=FindingStatus.DISCOVERED)
    triaged_at: Optional[datetime] = Field(default=None)
    deferred_to: Optional[datetime] = Field(default=None)
    closed_at: Optional[datetime] = Field(default=None)
    remediated_at: Optional[datetime] = Field(default=None)
    false_positive_reason: Optional[str] = Field(default='')

class Finding(BaseModel, DAL):
    finding_id: UUID
    account_name: str
    observed_at: Optional[datetime]
    occurrences: list[FindingOccurrence] = Field(default=[])
    rule_id: int
    group_id: int
    key: str
    group: str
    name: str
    cvss2: Union[str, Any] = Field(default=None)
    cvss3: Union[str, Any] = Field(default=None)
    customer_cvss3: Optional[str] = Field(default=None)
    is_vulnerable: bool = Field(default=False)
    is_warning: bool = Field(default=False)

    def exists(
        self,
        finding_id: Union[str, None] = None,
    ) -> bool:
        return self.load(finding_id)

    def load(
        self,
        finding_id: Union[str, None] = None,
    ) -> bool:
        if finding_id:
            self.finding_id = finding_id
        response = services.aws.get_dynamodb(table_name=services.aws.Tables.FINDINGS, item_key={'finding_id': str(self.finding_id)})
        if not response:
            internals.logger.warning(f"Missing finding data for finding_id: {self.finding_id}")
            return False
        super().__init__(**response)
        return True

    def save(self) -> bool:
        return services.aws.put_dynamodb(table_name=services.aws.Tables.FINDINGS, item=self.dict())

    def delete(self) -> bool:
        return services.aws.delete_dynamodb(table_name=services.aws.Tables.FINDINGS, item_key={'finding_id': str(self.finding_id)})
