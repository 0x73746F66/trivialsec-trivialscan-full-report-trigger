resource "aws_lambda_function" "report_graphs" {
  filename      = "${abspath(path.module)}/${local.source_file}"
  source_code_hash = filebase64sha256("${abspath(path.module)}/${local.source_file}")
  function_name = local.function_name
  role          = aws_iam_role.report_graphs_role.arn
  handler       = "app.handler"
  runtime       = local.python_version
  timeout       = 900

  environment {
    variables = {
      APP_ENV = var.app_env
      APP_NAME = var.app_name
      LOG_LEVEL = var.log_level
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
  statement_id  = "${var.app_env}AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.report_graphs.arn
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}"
}
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket
  lambda_function {
    lambda_function_arn = aws_lambda_function.report_graphs.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "${var.app_env}/accounts/"
    filter_suffix       = ".json"
  }
  depends_on = [aws_lambda_permission.allow_bucket]
}
