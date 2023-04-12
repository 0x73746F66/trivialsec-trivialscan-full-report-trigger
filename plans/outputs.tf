output "full_report_trigger_arn" {
  value = aws_lambda_function.full_report_trigger.arn
}
output "full_report_trigger_role" {
  value = aws_iam_role.full_report_trigger_role.name
}
output "full_report_trigger_role_arn" {
  value = aws_iam_role.full_report_trigger_role.arn
}
output "full_report_trigger_policy_arn" {
  value = aws_iam_policy.full_report_trigger_policy.arn
}
