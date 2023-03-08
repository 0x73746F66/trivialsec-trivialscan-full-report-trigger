import json

import internals
import models
import services.aws


def handler(event, context):
    trigger_object: str = event["Records"][0]["s3"]["object"]["key"]
    internals.logger.info(f"Triggered by {trigger_object}")
    if not trigger_object.startswith(internals.APP_ENV):
        internals.logger.critical(f"Wrong APP_ENV, expected {internals.APP_ENV}")
        return
    if not trigger_object.startswith(f"{internals.APP_ENV}/accounts/"):
        internals.logger.critical("Bad path")
        return
    if not trigger_object.endswith("full-report.json"):
        return

    _, _, account_name, *_ = trigger_object.split("/")
    # _process_issues(account_name, trigger_object)

    reports = []
    summaries = []
    object_paths = []
    prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/results/"
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


def _process_issues(account_name: str, trigger_object: str):
    pass

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

        key = item.key if not item.key.startswith("trust_") else "trust"
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
                if compliance.compliance == models.ComplianceName.PCI_DSS:
                    if compliance.version == "3.2.1":
                        cur_results.setdefault(
                            models.GraphLabel.PCIDSS3, _data.copy()
                        )
                        cur_results[models.GraphLabel.PCIDSS3][range_group] += 1
                    if compliance.version == "4.0":
                        cur_results.setdefault(
                            models.GraphLabel.PCIDSS4, _data.copy()
                        )
                        cur_results[models.GraphLabel.PCIDSS4][range_group] += 1
                if compliance.compliance == models.ComplianceName.NIST_SP800_131A:
                    if compliance.version == "strict mode":
                        cur_results.setdefault(
                            models.GraphLabel.NISTSP800_131A_STRICT, _data.copy()
                        )
                        cur_results[models.GraphLabel.NISTSP800_131A_STRICT][
                            range_group
                        ] += 1
                    if compliance.version == "transition mode":
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
    for c, _ in chart_data.items():
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
        ranges = set()
        for r in ["week", "month", "year"]:
            if d[r]:
                ranges.add(r)

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
