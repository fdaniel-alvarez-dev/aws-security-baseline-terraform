# ──────────────────────────────────────────────────────────────
# AWS Security Baseline — Full Deployment Example
# Author: Freddy Alvarez (falvarezpinto@gmail.com)
#
# Deploys a complete security baseline for a new or existing
# AWS account. I've used this exact pattern (with minor tweaks)
# across telecom infrastructure serving 1M+ users.
#
# Usage:
#   cp terraform.tfvars.example terraform.tfvars
#   terraform init && terraform plan && terraform apply
# ──────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state (strongly recommended for teams)
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "security-baseline/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "security-baseline"
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "platform-engineering"
    }
  }
}

# ──────────────────────────────────────────────────────────────
# Variables
# ──────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "security-baseline"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

variable "enable_guardduty" {
  description = "Enable GuardDuty threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub with CIS benchmarks"
  type        = bool
  default     = true
}

variable "enable_config_rules" {
  description = "Enable AWS Config compliance rules"
  type        = bool
  default     = true
}

# ──────────────────────────────────────────────────────────────
# Data sources
# ──────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

locals {
  account_id = data.aws_caller_identity.current.account_id
  azs        = slice(data.aws_availability_zones.available.names, 0, 3)

  # Subnet CIDR calculation — I learned the hard way that /24 per
  # subnet burns through address space fast in large environments.
  # /20 gives us 4,094 IPs per subnet, which handled Tigo's scale fine.
  public_subnets   = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnets  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 3)]
  isolated_subnets = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 6)]
}

# ──────────────────────────────────────────────────────────────
# Module: Secure VPC
# ──────────────────────────────────────────────────────────────

module "vpc" {
  source = "../../modules/vpc-secure"

  project_name     = var.project_name
  environment      = var.environment
  vpc_cidr         = var.vpc_cidr
  azs              = local.azs
  public_subnets   = local.public_subnets
  private_subnets  = local.private_subnets
  isolated_subnets = local.isolated_subnets

  enable_flow_logs     = true
  flow_log_retention   = 90
  enable_vpc_endpoints = true

  # NAT Gateway — single for dev/staging, HA for prod
  nat_gateway_mode = var.environment == "prod" ? "ha" : "single"
}

# ──────────────────────────────────────────────────────────────
# Module: CloudTrail (multi-region)
# ──────────────────────────────────────────────────────────────

module "cloudtrail" {
  source = "../../modules/cloudtrail"

  project_name        = var.project_name
  environment         = var.environment
  enable_log_validation = true
  is_multi_region     = true
  retention_days      = 365

  # KMS encryption for trail logs — non-negotiable in production
  kms_key_arn = module.kms.trail_key_arn
}

# ──────────────────────────────────────────────────────────────
# Module: KMS Key Rotation
# ──────────────────────────────────────────────────────────────

module "kms" {
  source = "../../modules/kms-key-rotation"

  project_name = var.project_name
  environment  = var.environment

  keys = {
    trail = {
      description         = "CloudTrail log encryption"
      enable_key_rotation = true
      policy_principals   = ["cloudtrail.amazonaws.com"]
    }
    secrets = {
      description         = "Secrets Manager encryption"
      enable_key_rotation = true
      policy_principals   = ["secretsmanager.amazonaws.com"]
    }
    ebs = {
      description         = "EBS volume encryption"
      enable_key_rotation = true
      policy_principals   = ["ec2.amazonaws.com"]
    }
  }
}

# ──────────────────────────────────────────────────────────────
# Module: IAM Baseline
# ──────────────────────────────────────────────────────────────

module "iam_baseline" {
  source = "../../modules/iam-baseline"

  project_name = var.project_name
  environment  = var.environment

  password_policy = {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    max_age_days                     = 90
    password_reuse_prevention        = 12
    allow_users_to_change_password   = true
  }

  # Break-glass admin role — only usable with MFA + CloudTrail audit
  enable_break_glass_role = true
  break_glass_mfa_required = true
}

# ──────────────────────────────────────────────────────────────
# Module: GuardDuty
# ──────────────────────────────────────────────────────────────

module "guardduty" {
  source = "../../modules/guardduty"
  count  = var.enable_guardduty ? 1 : 0

  project_name = var.project_name
  environment  = var.environment
  alert_email  = var.alert_email

  # Enable all protection plans
  enable_s3_protection      = true
  enable_eks_protection     = true
  enable_malware_protection = true

  # Publish findings to S3 for SIEM integration
  publish_to_s3    = true
  findings_bucket  = "${var.project_name}-guardduty-findings-${local.account_id}"
  publishing_frequency = "FIFTEEN_MINUTES"
}

# ──────────────────────────────────────────────────────────────
# Module: Security Hub
# ──────────────────────────────────────────────────────────────

module "security_hub" {
  source = "../../modules/security-hub"
  count  = var.enable_security_hub ? 1 : 0

  project_name = var.project_name
  environment  = var.environment

  # Standards to enable
  enable_cis_benchmark           = true
  enable_aws_foundational        = true
  enable_pci_dss                 = false  # Enable if handling payment data

  # Aggregate from GuardDuty
  enable_guardduty_integration = var.enable_guardduty
}

# ──────────────────────────────────────────────────────────────
# Module: AWS Config Rules
# ──────────────────────────────────────────────────────────────

module "config_rules" {
  source = "../../modules/config-rules"
  count  = var.enable_config_rules ? 1 : 0

  project_name = var.project_name
  environment  = var.environment

  # These are the rules I always enable first — they catch
  # the most common misconfigurations I've seen in production
  rules = {
    s3_bucket_public_read  = { source = "S3_BUCKET_PUBLIC_READ_PROHIBITED" }
    s3_bucket_ssl          = { source = "S3_BUCKET_SSL_REQUESTS_ONLY" }
    encrypted_volumes      = { source = "ENCRYPTED_VOLUMES" }
    rds_public_access      = { source = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK" }
    root_mfa               = { source = "ROOT_ACCOUNT_MFA_ENABLED" }
    iam_password_policy    = { source = "IAM_PASSWORD_POLICY" }
    vpc_flow_logs          = { source = "VPC_FLOW_LOGS_ENABLED" }
    cloudtrail_enabled     = { source = "CLOUD_TRAIL_ENABLED" }
    guardduty_enabled      = { source = "GUARDDUTY_ENABLED_CENTRALIZED" }
    ebs_encryption_default = { source = "EC2_EBS_ENCRYPTION_BY_DEFAULT" }
  }
}

# ──────────────────────────────────────────────────────────────
# SNS Topic for Security Alerts
# ──────────────────────────────────────────────────────────────

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-security-alerts"
  kms_master_key_id = module.kms.secrets_key_arn

  tags = {
    Name = "${var.project_name}-security-alerts"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ──────────────────────────────────────────────────────────────
# Outputs
# ──────────────────────────────────────────────────────────────

output "vpc_id" {
  description = "ID of the secure VPC"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (for workloads)"
  value       = module.vpc.private_subnet_ids
}

output "isolated_subnet_ids" {
  description = "Isolated subnet IDs (for databases)"
  value       = module.vpc.isolated_subnet_ids
}

output "security_alerts_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "cloudtrail_bucket" {
  description = "S3 bucket for CloudTrail logs"
  value       = module.cloudtrail.log_bucket_name
}

output "kms_key_arns" {
  description = "KMS key ARNs"
  value = {
    trail   = module.kms.trail_key_arn
    secrets = module.kms.secrets_key_arn
    ebs     = module.kms.ebs_key_arn
  }
}
