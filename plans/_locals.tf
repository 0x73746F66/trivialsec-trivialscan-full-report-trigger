locals {
  aws_master_account_id = 984310022655
  aws_default_region    = "ap-southeast-2"
  python_version        = "python3.10"
  source_file           = "${lower(var.app_env)}-${var.app_name}.zip"
  function_name         = "${lower(var.app_env)}-trivialscan-full-report-trigger"
  tags = {
    ProjectName      = "trivialscan"
    ProjectLeadEmail = "chris@trivialsec.com"
    CostCenter       = var.app_env != "Prod" ? "randd" : "opex"
    SecurityTags     = "customer-data"
    AutomationTool   = "Terraform"
    LUMIGO_TAG       = var.app_env == "Prod" ? "Production" : "Development"
  }
  timeout           = 60
  memory_size       = 1024
  retention_in_days = var.app_env == "Prod" ? 30 : 7
  enable_dynatrace  = false # var.app_env == "Prod"
}
