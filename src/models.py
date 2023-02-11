import json
from datetime import datetime, timezone
from enum import Enum
from typing import Union, Any, Optional
from abc import ABCMeta, abstractmethod

from pydantic import (
    BaseModel,
    Field,
    AnyHttpUrl,
    validator,
    conint,
    PositiveInt,
    PositiveFloat,
    IPvAnyAddress,
)

import internals
import services.aws

class DAL(metaclass=ABCMeta):
    @abstractmethod
    def load(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def save(self) -> bool:
        raise NotImplementedError


class DefaultInfo(BaseModel):
    generator: str = Field(default="trivialscan")
    version: Union[str, None] = Field(
        default=None, description="trivialscan CLI version"
    )
    account_name: Union[str, None] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Union[str, None] = Field(
        default=None, description="Machine name where trivialscan CLI execcutes"
    )


class ConfigDefaults(BaseModel):
    use_sni: bool
    cafiles: Union[str, None] = Field(default=None)
    tmp_path_prefix: str = Field(default="/tmp")
    http_path: str = Field(default="/")
    checkpoint: Optional[bool]


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


class ClientInfo(BaseModel):
    operating_system: Optional[str]
    operating_system_release: Optional[str]
    operating_system_version: Optional[str]
    architecture: Optional[str]


class ConfigOutput(BaseModel):
    type: OutputType
    use_icons: Union[bool, None]
    when: OutputWhen = Field(default=OutputWhen.FINAL)
    path: Union[str, None] = Field(default=None)


class ConfigTarget(BaseModel):
    hostname: str
    port: PositiveInt = Field(default=443)
    client_certificate: Union[str, None] = Field(default=None)
    http_request_paths: list[str] = Field(default=["/"])


class Config(BaseModel):
    account_name: Union[str, None] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Union[str, None] = Field(
        default=None, description="Machine name where trivialscan CLI execcutes"
    )
    project_name: Union[str, None] = Field(
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
    previous_report: Union[str, None]
    quiet: Optional[bool]


class HostTLSProtocol(BaseModel):
    negotiated: str
    preferred: str
    offered: list[str]


class HostTLSCipher(BaseModel):
    forward_anonymity: Union[bool, None] = Field(default=False)
    offered: list[str]
    offered_rfc: list[str]
    negotiated: str
    negotiated_bits: PositiveInt
    negotiated_rfc: str


class HostTLSClient(BaseModel):
    certificate_mtls_expected: Union[bool, None] = Field(default=False)
    certificate_trusted: Union[bool, None] = Field(default=False)
    certificate_match: Union[bool, None] = Field(default=False)
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
    certificate_mtls_expected: Union[bool, None] = Field(default=False)


class ThreatIntelSource(str, Enum):
    CHARLES_HALEY = "CharlesHaley"
    DATAPLANE = "DataPlane"
    TALOS_INTELLIGENCE = "TalosIntelligence"
    DARKLIST = "Darklist"


class ThreatIntel(BaseModel):
    source: ThreatIntelSource
    feed_identifier: Any
    feed_date: datetime

    @validator("feed_date")
    def set_feed_date(cls, feed_date: datetime):
        return feed_date.replace(tzinfo=timezone.utc)


class Host(BaseModel, DAL):
    last_updated: Optional[datetime]
    transport: HostTransport
    tls: Optional[HostTLS]
    http: Optional[list[HostHTTP]]
    monitoring_enabled: Optional[bool] = Field(default=False)
    threat_intel: Optional[list[ThreatIntel]] = Field(default=[])

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
        return self.load(hostname, port, peer_address, last_updated) is not None

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
            self.transport = HostTransport(hostname=hostname, port=port, peer_address=peer_address)  # type: ignore

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
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Host {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        data = self.dict()
        scan_date = self.last_updated.strftime("%Y%m%d")  # type: ignore
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        if not services.aws.store_s3(object_key, json.dumps(data, default=str)):
            return False
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/latest.json"
        # preserve threat_intel
        original = json.loads(services.aws.get_s3(object_key))
        data.setdefault("threat_intel", [])
        threat_intel: list = data["threat_intel"]
        threat_intel.extend(original.get("threat_intel", []))
        data["threat_intel"] = list(set(threat_intel))
        return services.aws.store_s3(object_key, json.dumps(data, default=str))


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

    @validator("not_after")
    def set_not_after(cls, not_after: datetime):
        return not_after.replace(tzinfo=timezone.utc) if not_after else None

    @validator("not_before")
    def set_not_before(cls, not_before: datetime):
        return not_before.replace(tzinfo=timezone.utc) if not_before else None

    def exists(self, sha1_fingerprint: Union[str, None] = None) -> bool:
        return self.load(sha1_fingerprint)

    def load(
        self, sha1_fingerprint: Union[str, None] = None
    ) -> bool:
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


class ComplianceItem(BaseModel):
    requirement: Union[str, None] = Field(default=None)
    title: Union[str, None] = Field(default=None)
    description: Union[str, None] = Field(default=None)


class ComplianceName(str, Enum):
    PCI_DSS = "PCI DSS"
    NIST_SP800_131A = "NIST SP800-131A"
    FIPS_140_2 = "FIPS 140-2"


class ComplianceGroup(BaseModel):
    compliance: Optional[ComplianceName]
    version: Optional[str]
    items: Union[list[ComplianceItem], None] = Field(default=[])


class ThreatItem(BaseModel):
    standard: str
    version: str
    tactic_id: Union[str, None] = Field(default=None)
    tactic_url: Union[AnyHttpUrl, None] = Field(default=None)
    tactic: Union[str, None] = Field(default=None)
    description: Union[str, None] = Field(default=None)
    technique_id: Union[str, None] = Field(default=None)
    technique_url: Union[AnyHttpUrl, None] = Field(default=None)
    technique: Union[str, None] = Field(default=None)
    technique_description: Union[str, None] = Field(default=None)
    sub_technique_id: Union[str, None] = Field(default=None)
    sub_technique_url: Union[AnyHttpUrl, None] = Field(default=None)
    sub_technique: Union[str, None] = Field(default=None)
    sub_technique_description: Union[str, None] = Field(default=None)
    data_source_id: Union[str, None] = Field(default=None)
    data_source_url: Union[AnyHttpUrl, None] = Field(default=None)
    data_source: Union[str, None] = Field(default=None)


class ReferenceItem(BaseModel):
    name: str
    url: Union[AnyHttpUrl, None]


class ScanRecordType(str, Enum):
    MONITORING = "Managed Monitoring"
    ONDEMAND = "Managed On-demand"
    SELF_MANAGED = "Customer-managed"


class ScanRecordCategory(str, Enum):
    ASM = "Attack Surface Monitoring"
    RECONNAISSANCE = "Reconnaissance"
    OSINT = "Public Data Sources"
    INTEGRATION_DATA = "Third Party Integration"


class ReportSummary(DefaultInfo):
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
    config: Optional[Config]
    client: Optional[ClientInfo]
    type: Optional[ScanRecordType]
    category: Optional[ScanRecordCategory]
    is_passive: Optional[bool] = Field(default=True)

    class Config:
        validate_assignment = True

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
    observed_at: Union[datetime, None] = Field(default=None)
    result_value: Union[bool, str, None]
    result_label: str
    result_text: str
    result_level: Union[str, None] = Field(default=None)
    score: int = Field(default=0)
    description: Optional[str]
    metadata: dict[str, Any] = Field(default={})
    cve: Union[list[str], None] = Field(default=[])
    cvss2: Union[str, Any] = Field(default=None)
    cvss3: Union[str, Any] = Field(default=None)
    references: Union[list[ReferenceItem], None] = Field(default=[])
    compliance: Union[list[ComplianceGroup], None] = Field(default=[])
    threats: Union[list[ThreatItem], None] = Field(default=[])
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
        object_key = self._extracted_from_load_4(report_id, account_name)
        return services.aws.object_exists(object_key)

    def load(
        self, report_id: Union[str, None] = None, account_name: Union[str, None] = None
    ) -> Union["FullReport", None]:
        object_key = self._extracted_from_load_4(report_id, account_name)
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing FullReport {object_key}")
            return
        if data := json.loads(raw):
            super().__init__(**data)
        return self

    # TODO Rename this here and in `exists` and `load`
    def _extracted_from_load_4(self, report_id, account_name):
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name
        return f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.delete_s3(object_key)


class ComplianceChartItem(BaseModel):
    name: str
    num: int
    timestamp: int


class DashboardCompliance(BaseModel):
    label: GraphLabel
    ranges: list[GraphLabelRanges]
    data: dict[GraphLabelRanges, list[ComplianceChartItem]]
