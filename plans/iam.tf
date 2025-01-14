data "aws_iam_policy_document" "full_report_trigger_assume_role_policy" {
  statement {
    sid     = "${var.app_env}FullReportTriggerAssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "full_report_trigger_iam_policy" {
  statement {
    sid = "${var.app_env}FullReportTriggerLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${local.aws_default_region}:${local.aws_master_account_id}:log-group:/aws/lambda/${local.function_name}:*"
    ]
  }
  statement {
    sid = "${var.app_env}FullReportTriggerObjList"
    actions = [
      "s3:Head*",
      "s3:List*",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}",
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}/*",
    ]
  }
  statement {
    sid = "${var.app_env}FullReportTriggerObjAccess"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}/${var.app_env}/*",
    ]
  }
  statement {
    sid = "${var.app_env}FullReportTriggerSecrets"
    actions = [
      "ssm:GetParameter",
    ]
    resources = [
      "arn:aws:ssm:${local.aws_default_region}:${local.aws_master_account_id}:parameter/${var.app_env}/${var.app_name}/*",
    ]
  }
  statement {
    sid = "${var.app_env}FullReportTriggerDynamoDB"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_findings",
    ]
  }
  statement {
    sid = "${var.app_env}FullReportTriggerDynamoDBQuery"
    actions = [
      "dynamodb:Query"
    ]
    resources = [
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_findings/*",
    ]
  }
}
resource "aws_iam_role" "full_report_trigger_role" {
  name               = "${lower(var.app_env)}_full_report_trigger_lambda_role"
  assume_role_policy = data.aws_iam_policy_document.full_report_trigger_assume_role_policy.json
  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_iam_policy" "full_report_trigger_policy" {
  name   = "${lower(var.app_env)}_full_report_trigger_lambda_policy"
  path   = "/"
  policy = data.aws_iam_policy_document.full_report_trigger_iam_policy.json
}
resource "aws_iam_role_policy_attachment" "policy_attach" {
  role       = aws_iam_role.full_report_trigger_role.name
  policy_arn = aws_iam_policy.full_report_trigger_policy.arn
}
