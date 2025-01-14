resource "aws_lambda_function" "full_report_trigger" {
  s3_bucket = aws_s3_object.file_upload.bucket
  s3_key    = aws_s3_object.file_upload.key
  # kms_key_arn = "" If this configuration is not provided when environment variables are in use, AWS Lambda uses a default service key
  source_code_hash = filebase64sha256("${abspath(path.module)}/${local.source_file}")
  function_name    = local.function_name
  role             = aws_iam_role.full_report_trigger_role.arn
  handler          = "app.handler"
  runtime          = local.python_version
  timeout          = local.timeout
  memory_size      = local.memory_size
  layers           = local.enable_dynatrace ? ["arn:aws:lambda:ap-southeast-2:725887861453:layer:Dynatrace_OneAgent_1_261_5_20230309-143152_python:1"] : []

  environment {
    variables = local.enable_dynatrace == "Prod" ? {
      APP_ENV                              = var.app_env
      APP_NAME                             = var.app_name
      LOG_LEVEL                            = var.log_level
      STORE_BUCKET                         = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket
      AWS_LAMBDA_EXEC_WRAPPER              = "/opt/dynatrace"
      DT_TENANT                            = "xuf85063"
      DT_CLUSTER_ID                        = "-1273248646"
      DT_CONNECTION_BASE_URL               = "https://xuf85063.live.dynatrace.com"
      DT_CONNECTION_AUTH_TOKEN             = var.dynatrace_token
      DT_OPEN_TELEMETRY_ENABLE_INTEGRATION = "true"
      } : {
      APP_ENV      = var.app_env
      APP_NAME     = var.app_name
      LOG_LEVEL    = var.log_level
      STORE_BUCKET = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket
    }
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_iam_role_policy_attachment.policy_attach
  ]
  tags = local.tags
}
resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "${var.app_env}AllowExecutionFromS3BucketFullReportTrigger"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.full_report_trigger.arn
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}"
}

resource "aws_cloudwatch_log_group" "full_report_trigger_logs" {
  skip_destroy      = var.app_env == "Prod"
  name              = "/aws/lambda/${aws_lambda_function.full_report_trigger.function_name}"
  retention_in_days = local.retention_in_days
}

resource "aws_s3_object" "file_upload" {
  bucket       = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket
  key          = "lambda-functions/${local.function_name}.zip"
  source       = "${abspath(path.module)}/${local.source_file}"
  content_type = "application/octet-stream"
  etag         = filemd5("${abspath(path.module)}/${local.source_file}")
}
