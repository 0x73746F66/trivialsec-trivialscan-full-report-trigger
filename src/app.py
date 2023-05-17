# pylint disable=invalid-name
import json
from uuid import uuid5, UUID
from typing import Optional, Union
from datetime import datetime, timezone

from lumigo_tracer import lumigo_tracer
from pydantic import BaseModel, validator

import internals
import models
import services.aws
import services.webhook
import services.sendgrid


class Digest(BaseModel):
    class Config:
        validate_assignment = True
    name: str
    key: str
    group: str
    group_id: str
    rule_id: str
    result_value: Union[bool, str, None]
    result_label: str
    result_level: Optional[models.ResultLevel]
    is_critical: bool
    occurrence_id: UUID
    report_ids: str
    hostname: str
    port: int
    last_seen: datetime
    certificate_sha1: str
    certificate_subject: str
    status: models.FindingStatus

    @validator("last_seen")
    def set_last_seen(cls, last_seen: datetime):  # pylint: disable=no-self-argument
        return last_seen.replace(tzinfo=timezone.utc) if last_seen else None


def prepare_event(event) -> tuple[models.MemberAccount, models.FullReport]:
    if event.get("source"):
        internals.trace_tag({
            "source": event["source"],
            "resources": ",".join([
                e.split(":")[-1] for e in event["resources"]
            ]) or "manual",
        })
    trigger_object: str = event["Records"][0]["s3"]["object"]["key"]
    internals.logger.info(f"Triggered by {trigger_object}")
    internals.logger.debug(f"raw {event}")
    if not trigger_object.startswith(internals.APP_ENV):
        raise internals.InvalidTriggerEvent(f"Wrong APP_ENV, expected {internals.APP_ENV}")
    if not trigger_object.startswith(f"{internals.APP_ENV}/accounts/"):
        raise internals.InvalidTriggerEvent(f"Bad prefix for account {trigger_object}")
    if not trigger_object.endswith("full-report.json"):
        raise internals.InvalidTriggerEvent(f"Bad suffix for FullReport {trigger_object}")

    _, _, account_name, *_ = trigger_object.split("/")
    account = models.MemberAccount(name=account_name)
    if not account.load():
        raise internals.InvalidTriggerEvent(f"Failed to load account {account_name}")

    prefix_key = f"{internals.APP_ENV}/accounts/{account.name}/results/"
    report_id = trigger_object.replace(prefix_key, "").replace("/full-report.json", "")
    report = models.FullReport(
        account_name=account.name,
        report_id=report_id,
    )
    if not report.load():
        raise internals.InvalidTriggerEvent(f"Failed to load report {report_id} for account_name {account.name}")
    return account, report


def process_report(account: models.MemberAccount, report: models.FullReport) -> list[Digest]:
    digest = []
    for evaluation in report.evaluations:
        finding_id = uuid5(internals.NAMESPACE, f"{account.name}{evaluation.group}{evaluation.key}")
        if evaluation.group == 'certificate' and evaluation.certificate.sha1_fingerprint:
            occurrence_id = uuid5(internals.NAMESPACE, f"{account.name}{evaluation.group}{evaluation.key}{evaluation.certificate.sha1_fingerprint}")
            webhook_event = models.WebhookEvent.NEW_FINDINGS_CERTIFICATES

        elif evaluation.transport.hostname:
            occurrence_id = uuid5(internals.NAMESPACE, f"{account.name}{evaluation.group}{evaluation.key}{evaluation.transport.hostname}{evaluation.transport.port}")
            webhook_event = models.WebhookEvent.NEW_FINDINGS_DOMAINS

        else:
            internals.logger.error(f"Invalid EvaluationItem {evaluation}")
            continue

        finding = models.Finding(
            finding_id=finding_id,
            **evaluation.dict()
        )
        new_finding = False
        if not finding.load():
            new_finding = True
            internals.logger.info(f"New {finding_id} {account.name} {evaluation.transport.hostname}:{evaluation.transport.port} {finding.name}")
        skip_occurrence = new_finding and evaluation.result_level == "pass"
        matched = False
        now_remediated = False
        now_regressed = False
        occurrences = []
        for occurrence in finding.occurrences.copy():
            if occurrence_id != occurrence.occurrence_id:
                occurrences.append(occurrence)
                continue

            matched = True
            occurrence.last_seen = datetime.now(tz=timezone.utc)
            occurrence.report_ids.append(report.report_id)
            occurrence.report_ids = list({
                _report_id
                for _report_id in occurrence.report_ids.copy()
                if models.FullReport(report_id=_report_id, account_name=account.name).exists()
            })
            if evaluation.result_level == "pass" and occurrence.status == models.FindingStatus.REMEDIATED:
                skip_occurrence = True

            elif evaluation.result_level == "pass": # and occurrence.status != models.FindingStatus.REMEDIATED
                occurrence.status = models.FindingStatus.REMEDIATED
                occurrence.remediated_at = datetime.now(tz=timezone.utc)
                now_remediated = True

            elif occurrence.status == models.FindingStatus.REMEDIATED: # and evaluation.result_level != "pass"
                occurrence.status = models.FindingStatus.REGRESSION
                occurrence.regressed_at = datetime.now(tz=timezone.utc)
                now_regressed = True
                if (account.notifications.new_findings_domains and webhook_event == models.WebhookEvent.NEW_FINDINGS_DOMAINS) or (account.notifications.new_findings_certificates and webhook_event == models.WebhookEvent.NEW_FINDINGS_CERTIFICATES):
                    digest.append(Digest(
                        name=evaluation.name,
                        key=evaluation.key,
                        group=evaluation.group,
                        group_id=evaluation.group_id,
                        rule_id=evaluation.rule_id,
                        result_value=evaluation.result_value,
                        result_label=evaluation.result_label,
                        result_level=evaluation.result_level,
                        is_critical=(
                            evaluation.result_label.lower() in ["compromised", "vulnerable", "revoked", "expired"]
                            or evaluation.result_label.lower().startswith("compromised")
                        ),
                        occurrence_id=occurrence.occurrence_id,
                        report_ids=occurrence.report_ids,
                        hostname=occurrence.hostname,
                        port=occurrence.port,
                        last_seen=occurrence.last_seen,
                        certificate_sha1=occurrence.certificate_sha1,
                        certificate_subject=occurrence.certificate_subject,
                        status=occurrence.status,
                    ))
            occurrences.append(occurrence)

        if skip_occurrence:
            internals.logger.debug(f"SKIP {evaluation.name}")
            continue

        if matched:
            finding.occurrences = occurrences
        else:
            occurrence = models.FindingOccurrence(
                occurrence_id=occurrence_id,
                hostname=evaluation.transport.hostname,
                port=evaluation.transport.port,
                last_seen = datetime.now(tz=timezone.utc),
            )
            if evaluation.certificate:
                occurrence.certificate_sha1 = evaluation.certificate.sha1_fingerprint
                occurrence.certificate_subject = evaluation.certificate.subject
            occurrence.report_ids = [report.report_id]
            finding.occurrences.append(occurrence)
            if new_finding and (account.notifications.new_findings_domains and webhook_event == models.WebhookEvent.NEW_FINDINGS_DOMAINS) or (account.notifications.new_findings_certificates and webhook_event == models.WebhookEvent.NEW_FINDINGS_CERTIFICATES):
                digest.append(Digest(
                    name=evaluation.name,
                    key=evaluation.key,
                    group=evaluation.group,
                    group_id=evaluation.group_id,
                    rule_id=evaluation.rule_id,
                    result_value=evaluation.result_value,
                    result_label=evaluation.result_label,
                    result_level=evaluation.result_level,
                    is_critical=(
                        evaluation.result_label.lower() in ["compromised", "vulnerable", "revoked", "expired"]
                        or evaluation.result_label.lower().startswith("compromised")
                    ),
                    occurrence_id=occurrence.occurrence_id,
                    report_ids=occurrence.report_ids,
                    hostname=occurrence.hostname,
                    port=occurrence.port,
                    last_seen=occurrence.last_seen,
                    certificate_sha1=occurrence.certificate_sha1,
                    certificate_subject=occurrence.certificate_subject,
                    status=occurrence.status,
                ))

        if not finding.save():
            internals.logger.warning(f"Failed to save finding_id {finding_id}")
            continue

        if new_finding or now_remediated or now_regressed:
            services.webhook.send(
                event_name=webhook_event,
                account=account,
                data=finding.dict(),
            )


def main(event):
    account, report = prepare_event(event)
    if digest := process_report(account, report):
        internals.logger.info("Emailing findings digest")
        sendgrid = services.sendgrid.send_email(
            subject="New Findings",
            recipient=account.primary_email,
            template="findings_digest",
            data={
                'findings': digest,
                'results_uri': report.results_uri,
                'score': report.score,
                'pass_result': report.results.get('pass', 0),
                'info_result': report.results.get('info', 0),
                'warn_result': report.results.get('warn', 0),
                'fail_result': report.results.get('fail', 0),
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()  # pylint: disable=protected-access
            )
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
            else:
                internals.trace_tag({
                    'sg_msg_id': sendgrid.headers.get("X-Message-Id"),
                    'findings': str(len(digest)),
                })
    return True


@lumigo_tracer(
    token=services.aws.get_ssm(f'/{internals.APP_ENV}/{internals.APP_NAME}/Lumigo/token', WithDecryption=True),
    should_report=internals.APP_ENV == "Prod",
    skip_collecting_http_body=True,
    verbose=internals.APP_ENV != "Prod"
)
def handler(event, context):  # pylint: disable=unused-argument
    try:
        return main(event)
    except Exception as err:
        internals.always_log(err)
    return False
