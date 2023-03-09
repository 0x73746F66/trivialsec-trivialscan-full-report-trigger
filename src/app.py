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
    prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/results/"
    _process_issues(account_name=account_name, report_id=trigger_object.replace(prefix_key, "").replace("/full-report.json", ""))

    reports = []
    summaries = []
    object_paths = []
    try:
        object_paths = services.aws.list_s3(prefix_key=prefix_key)

    except RuntimeError as err:
        internals.logger.exception(err)
        return

    for object_key in object_paths:
        if not object_key.endswith("full-report.json"):
            continue
        report_id = object_key.replace(prefix_key, "").replace("/full-report.json", "")
        report = models.FullReport(
            account_name=account_name,
            report_id=report_id,
        )
        if not report.load():
            internals.logger.warning(f"Failed to load account_name {account_name} report_id {report_id}")
            continue
        reports.append(report)
        summaries.append(models.ReportSummary(**report.dict()))

    _graphing_data(account_name, reports)
    _findings_data(account_name, reports)
    _certificate_issues(account_name, reports)


def _process_issues(account_name: str, report_id: str):
    report = models.FullReport(
        account_name=account_name,
        report_id=report_id,
    )
    if not report.load():
        internals.logger.warning(f"Failed to load account_name {account_name} report {report_id}")
        return
    account = models.MemberAccount(name=account_name)
    if not account.load():
        internals.logger.warning(f"Failed to load account {account_name} report_id {report_id}")
        return

    digest = []
    for evaluation in report.evaluations:
        if evaluation.certificate:
            finding_id = uuid5(internals.NAMESPACE, f"{account_name}{evaluation.group}{evaluation.key}{evaluation.certificate.sha1_fingerprint}")
            webhook_event = models.WebhookEvent.NEW_FINDINGS_CERTIFICATES

        elif evaluation.transport.hostname:
            finding_id = uuid5(internals.NAMESPACE, f"{account_name}{evaluation.group}{evaluation.key}{evaluation.transport.hostname}{evaluation.transport.port}")
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
            if evaluation.certificate and occurrence.certificate_sha1 == evaluation.certificate.sha1_fingerprint:
                occurrence.last_seen = datetime.now(tz=timezone.utc)
                occurrence.report_ids.append(report.report_id)
                matched = True

            if occurrence.hostname == evaluation.transport.hostname and occurrence.port == evaluation.transport.port:
                occurrence.last_seen = datetime.now(tz=timezone.utc)
                occurrence.report_ids.append(report.report_id)
                matched = True

            if matched:
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
                            **occurrence.dict()
                        })
                break

        if skip_occurrence:
            internals.logger.debug(f"SKIP {evaluation.name}")
            continue

        if not matched:
            occurrence = models.FindingOccurrence(
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
                    **occurrence.dict()
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


def _certificate_issues(account_name: str, reports: list[models.FullReport]):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a list of certificate issues filtered to include only the highest risk
    and ordered by last seen
    """
    full_data: list[models.EvaluationItem] = []
    for report in reports:
        for item in report.evaluations or []:
            if (
                item.result_level == "pass"
                or not item.certificate
                or item.group != "certificate"
            ):
                continue
            if not item.observed_at:
                item.observed_at = report.date
            if item.cvss2:
                item.references.append(models.ReferenceItem(name=f"CVSSv2 {item.cvss2}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=({item.cvss2})"))  # type: ignore
            if item.cvss3:
                item.references.append(models.ReferenceItem(name=f"CVSSv3.1 {item.cvss3}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?version=3.1&vector={item.cvss3}"))  # type: ignore
            if item.cve:
                for cve in item.cve:
                    item.references.append(models.ReferenceItem(name=cve, url=f"https://nvd.nist.gov/vuln/detail/{cve}"))  # type: ignore
            full_data.append(item)

    priority_data: list[models.EvaluationItem] = sorted(full_data, key=lambda x: x.score)  # type: ignore
    uniq_data: list[models.EvaluationItem] = []
    seen = set()
    for item in priority_data:
        if item.key.startswith("trust_android_"):
            continue

        key = "trust" if item.key.startswith("trust_") else item.key
        target = f"{item.certificate.sha1_fingerprint}{key}"  # type: ignore
        if target not in seen:
            uniq_data.append(item)
        seen.add(target)

    try:
        services.aws.store_s3(
            path_key=f"{internals.APP_ENV}/accounts/{account_name}/computed/dashboard-certificates.json",
            value=json.dumps([data.dict() for data in uniq_data], default=str),
        )

    except RuntimeError as err:
        internals.logger.exception(err)


def _findings_data(account_name: str, reports: list[models.FullReport]):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a list of host findings filtered to include only the highest risk issues
    and ordered by last seen
    """
    full_data: list[models.EvaluationItem] = []
    for report in reports:
        for item in report.evaluations or []:
            if (
                item.result_level == "pass"
                or not item.transport
                or item.group == "certificate"
            ):
                continue
            if not item.observed_at:
                item.observed_at = report.date
            if item.cvss2:
                item.references.append(models.ReferenceItem(name=f"CVSSv2 {item.cvss2}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=({item.cvss2})"))  # type: ignore
            if item.cvss3:
                item.references.append(models.ReferenceItem(name=f"CVSSv3.1 {item.cvss3}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?version=3.1&vector={item.cvss3}"))  # type: ignore
            if item.cve:
                for cve in item.cve:
                    item.references.append(models.ReferenceItem(name=cve, url=f"https://nvd.nist.gov/vuln/detail/{cve}"))  # type: ignore
            full_data.append(item)

    priority_data: list[models.EvaluationItem] = sorted(full_data, key=lambda x: x.score)  # type: ignore
    uniq_data: list[models.EvaluationItem] = []
    seen = set()
    for item in priority_data:
        target = f"{item.transport.hostname}{item.transport.port}{item.transport.peer_address}{item.key}"  # type: ignore
        if target not in seen:
            uniq_data.append(item)
        seen.add(target)

    try:
        services.aws.store_s3(
            path_key=f"{internals.APP_ENV}/accounts/{account_name}/computed/dashboard-findings.json",
            value=json.dumps([data.dict() for data in uniq_data], default=str),
        )

    except RuntimeError as err:
        internals.logger.exception(err)


def _graphing_data(account_name: str, reports: list[models.FullReport]):
    charts = []
    results = []
    chart_data = {
        models.GraphLabel.PCIDSS3: {"week": [], "month": [], "year": []},
        models.GraphLabel.PCIDSS4: {"week": [], "month": [], "year": []},
        models.GraphLabel.NISTSP800_131A_STRICT: {
            "week": [],
            "month": [],
            "year": [],
        },
        models.GraphLabel.NISTSP800_131A_TRANSITION: {
            "week": [],
            "month": [],
            "year": [],
        },
        models.GraphLabel.FIPS1402: {"week": [], "month": [], "year": []},
    }
    _data = {"week": 0, "month": 0, "year": 0}
    for report in reports:
        group_name, range_group, timestamp = internals.date_label(report.date)
        cur_results = {"group_name": group_name, "timestamp": timestamp}
        for item in report.evaluations:
            if item.result_level == "pass":
                continue
            for compliance in item.compliance:
                if compliance.version == "3.2.1":
                    if compliance.compliance == models.ComplianceName.PCI_DSS:
                        cur_results.setdefault(
                            models.GraphLabel.PCIDSS3, _data.copy()
                        )
                        cur_results[models.GraphLabel.PCIDSS3][range_group] += 1
                elif compliance.version == "4.0":
                    if compliance.compliance == models.ComplianceName.PCI_DSS:
                        cur_results.setdefault(
                            models.GraphLabel.PCIDSS4, _data.copy()
                        )
                        cur_results[models.GraphLabel.PCIDSS4][range_group] += 1
                elif compliance.version == "strict mode":
                    if compliance.compliance == models.ComplianceName.NIST_SP800_131A:
                        cur_results.setdefault(
                            models.GraphLabel.NISTSP800_131A_STRICT, _data.copy()
                        )
                        cur_results[models.GraphLabel.NISTSP800_131A_STRICT][
                            range_group
                        ] += 1
                elif compliance.version == "transition mode":
                    if compliance.compliance == models.ComplianceName.NIST_SP800_131A:
                        cur_results.setdefault(
                            models.GraphLabel.NISTSP800_131A_TRANSITION, _data.copy()
                        )
                        cur_results[models.GraphLabel.NISTSP800_131A_TRANSITION][
                            range_group
                        ] += 1
                if (
                    compliance.compliance == models.ComplianceName.FIPS_140_2
                    and compliance.version == "Annex A"
                ):
                    cur_results.setdefault(models.GraphLabel.FIPS1402, _data.copy())
                    cur_results[models.GraphLabel.FIPS1402][range_group] += 1
        results.append(cur_results)

    agg_sums = {}
    for c in chart_data:
        agg_sums.setdefault(c, {})
        for r in ["week", "month", "year"]:
            agg_sums[c].setdefault(r, {})
            for _result in results:
                if c not in _result or r not in _result[c]:
                    continue
                key = (_result["group_name"], _result["timestamp"])
                agg_sums[c][r].setdefault(key, [])
                agg_sums[c][r][key].append(_result[c][r])
    for c, g in agg_sums.items():
        for r, d in g.items():
            for group_key, sum_arr in d.items():
                group_name, timestamp = group_key
                if sum(sum_arr) > 0:
                    chart_data[c][r].append(
                        models.ComplianceChartItem(
                            name=group_name,
                            num=sum(sum_arr),
                            timestamp=timestamp,
                        )
                    )
    for c, d in chart_data.items():
        ranges = {r for r in ["week", "month", "year"] if d[r]}
        charts.append(
            models.DashboardCompliance(label=c, ranges=list(ranges), data=d)
        )

    try:
        services.aws.store_s3(
            path_key=f"{internals.APP_ENV}/accounts/{account_name}/computed/dashboard-compliance.json",
            value=json.dumps([chart.dict() for chart in charts], default=str),
        )

    except RuntimeError as err:
        internals.logger.exception(err)
