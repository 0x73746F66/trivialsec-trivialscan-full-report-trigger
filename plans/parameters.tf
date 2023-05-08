resource "aws_ssm_parameter" "sendgrid_api_key" {
  name      = "/${var.app_env}/${var.app_name}/Sendgrid/api-key"
  type      = "SecureString"
  value     = var.sendgrid_api_key
  tags      = local.tags
  overwrite = true
}
resource "aws_ssm_parameter" "lumigo_token" {
  name      = "/${var.app_env}/${var.app_name}/Lumigo/token"
  type      = "SecureString"
  value     = var.lumigo_token
  tags      = local.tags
  overwrite = true
}
