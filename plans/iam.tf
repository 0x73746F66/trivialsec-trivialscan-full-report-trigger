data "aws_iam_policy_document" "dashboard_compliance_graphs_assume_role_policy" {
  statement {
    sid = "${var.app_env}DashboardComplianceGraphsAssumeRole"
    actions    = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "dashboard_compliance_graphs_iam_policy" {
  statement {
    sid = "${var.app_env}DashboardComplianceGraphsLogging"
    actions   = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${local.aws_default_region}:${local.aws_master_account_id}:log-group:/aws/lambda/${local.function_name}:*"
    ]
  }
  statement {
    sid = "${var.app_env}DashboardComplianceGraphsObjList"
    actions   = [
      "s3:Head*",
      "s3:List*",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}",
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}/*",
    ]
  }
  statement {
    sid = "${var.app_env}DashboardComplianceGraphsObjAccess"
    actions   = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket[0]}/${var.app_env}/*",
    ]
  }
}
resource "aws_iam_role" "dashboard_compliance_graphs_role" {
  name               = "${lower(var.app_env)}_dashboard_compliance_graphs_lambda_role"
  assume_role_policy = data.aws_iam_policy_document.dashboard_compliance_graphs_assume_role_policy.json
  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_iam_policy" "dashboard_compliance_graphs_policy" {
  name        = "${lower(var.app_env)}_dashboard_compliance_graphs_lambda_policy"
  path        = "/"
  policy      = data.aws_iam_policy_document.dashboard_compliance_graphs_iam_policy.json
}
resource "aws_iam_role_policy_attachment" "policy_attach" {
  role       = aws_iam_role.dashboard_compliance_graphs_role.name
  policy_arn = aws_iam_policy.dashboard_compliance_graphs_policy.arn
}
