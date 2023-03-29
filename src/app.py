# pylint disable=invalid-name
import json
from uuid import uuid5
from datetime import datetime, timezone

import internals
import models
import services.aws
import services.webhook
import services.sendgrid


def handler(event, context):
    trigger_object: str = event["Records"][0]["s3"]["object"]["key"]
    internals.logger.info(f"Triggered by {trigger_object}")
    internals.logger.debug(f"raw {event}")
    if not trigger_object.startswith(internals.APP_ENV):
        internals.logger.critical(f"Wrong APP_ENV, expected {internals.APP_ENV}")
        return
    if not trigger_object.startswith(f"{internals.APP_ENV}/accounts/"):
        internals.logger.critical("Bad path")
        return
    if not trigger_object.endswith("full-report.json"):
        return

    _, _, account_name, *_ = trigger_object.split("/")
    account = models.MemberAccount(name=account_name)
    if not account.load():
        internals.logger.warning(f"Failed to load account {account_name}")
        return

    prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/results/"
    report_id = trigger_object.replace(prefix_key, "").replace("/full-report.json", "")
    report = models.FullReport(
        account_name=account_name,
        report_id=report_id,
    )
    if not report.load():
        internals.logger.warning(f"Failed to load account_name {account_name} report {report_id}")
        return

    digest = []
    for evaluation in report.evaluations:
        finding_id = uuid5(internals.NAMESPACE, f"{account_name}{evaluation.group}{evaluation.key}")
        if evaluation.certificate:
            occurrence_id = uuid5(internals.NAMESPACE, f"{account_name}{evaluation.group}{evaluation.key}{evaluation.certificate.sha1_fingerprint}")
            webhook_event = models.WebhookEvent.NEW_FINDINGS_CERTIFICATES

        elif evaluation.transport.hostname:
            occurrence_id = uuid5(internals.NAMESPACE, f"{account_name}{evaluation.group}{evaluation.key}{evaluation.transport.hostname}{evaluation.transport.port}")
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

        skip_occurrence = new_finding and evaluation.result_level == "pass"
        matched = False
        now_remediated = False
        now_regressed = False
        for occurrence in finding.occurrences:
            if occurrence_id and occurrence.occurrence_id or evaluation.certificate and occurrence.certificate_sha1 == evaluation.certificate.sha1_fingerprint or (occurrence.hostname == evaluation.transport.hostname and occurrence.port == evaluation.transport.port):
                matched = True
                occurrence.last_seen = datetime.now(tz=timezone.utc)
                occurrence.report_ids.append(report.report_id)
                occurrence.occurrence_id = occurrence_id
                occurrence.report_ids = list({
                    _report_id
                    for _report_id in occurrence.report_ids
                    if services.aws.object_exists(f"{internals.APP_ENV}/accounts/{account_name}/results/{_report_id}/full-report.json")
                })
                if evaluation.result_level == "pass" and occurrence.status == models.FindingStatus.REMEDIATED:
                    skip_occurrence = True
                    continue
                elif evaluation.result_level == "pass": # and occurrence.status != models.FindingStatus.REMEDIATED
                    occurrence.status = models.FindingStatus.REMEDIATED
                    occurrence.remediated_at = datetime.now(tz=timezone.utc)
                    now_remediated = True

                elif occurrence.status == models.FindingStatus.REMEDIATED: # and evaluation.result_level != "pass"
                    occurrence.status = models.FindingStatus.REGRESSION
                    occurrence.regressed_at = datetime.now(tz=timezone.utc)
                    now_regressed = True

                if (account.notifications.new_findings_domains and webhook_event == models.WebhookEvent.NEW_FINDINGS_DOMAINS) or (account.notifications.new_findings_certificates and webhook_event == models.WebhookEvent.NEW_FINDINGS_CERTIFICATES):
                    digest.append({
                        'name': evaluation.name,
                        'key': evaluation.key,
                        'group': evaluation.group,
                        'group_id': evaluation.group_id,
                        'rule_id': evaluation.rule_id,
                        'result_value': evaluation.result_value,
                        'result_label': evaluation.result_label,
                        'result_level': evaluation.result_level,
                        'is_critical': (
                            evaluation.result_label.lower() in ["compromised", "vulnerable", "revoked", "expired"]
                            or evaluation.result_label.lower().startswith("compromised")
                        ),
                        'occurrence_id': str(occurrence.occurrence_id),
                        'report_ids': occurrence.report_ids,
                        'hostname': occurrence.hostname,
                        'port': occurrence.port,
                        'last_seen': occurrence.last_seen.isoformat(),
                        'certificate_sha1': occurrence.certificate_sha1,
                        'status': occurrence.status.value,
                    })
                break

        if skip_occurrence:
            internals.logger.debug(f"SKIP {evaluation.name}")
            continue

        if not matched:
            occurrence = models.FindingOccurrence(
                occurrence_id=occurrence_id,
                hostname=evaluation.transport.hostname,
                port=evaluation.transport.port,
                last_seen = datetime.now(tz=timezone.utc),
            )
            if evaluation.certificate:
                occurrence.certificate_sha1 = evaluation.certificate.sha1_fingerprint
            occurrence.report_ids = [report.report_id]
            finding.occurrences.append(occurrence)
            if (account.notifications.new_findings_domains and webhook_event == models.WebhookEvent.NEW_FINDINGS_DOMAINS) or (account.notifications.new_findings_certificates and webhook_event == models.WebhookEvent.NEW_FINDINGS_CERTIFICATES):
                digest.append({
                    'name': evaluation.name,
                    'key': evaluation.key,
                    'group': evaluation.group,
                    'group_id': evaluation.group_id,
                    'rule_id': evaluation.rule_id,
                    'result_value': evaluation.result_value,
                    'result_label': evaluation.result_label,
                    'result_level': evaluation.result_level,
                    'is_critical': (
                        evaluation.result_label.lower() in ["compromised", "vulnerable", "revoked", "expired"]
                        or evaluation.result_label.lower().startswith("compromised")
                    ),
                    'occurrence_id': str(occurrence.occurrence_id),
                    'report_ids': occurrence.report_ids,
                    'hostname': occurrence.hostname,
                    'port': occurrence.port,
                    'last_seen': occurrence.last_seen.isoformat(),
                    'certificate_sha1': occurrence.certificate_sha1,
                    'status': occurrence.status.value,
                })

        if not finding.save():
            internals.logger.warning(f"Failed to save finding_id {finding_id}")
            continue
        if new_finding or now_remediated or now_regressed:
            services.webhook.send(
                event_name=webhook_event,
                account=account,
                data=finding.dict(),
            )

    if digest:
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
