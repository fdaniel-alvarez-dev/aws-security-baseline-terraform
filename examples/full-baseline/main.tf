# ──────────────────────────────────────────────────────────────
# AWS Security Baseline — Full Deployment Example
# Author: Freddy Alvarez (falvarezpinto@gmail.com)
#
# Deploys a solid security foundation for a new or existing
# AWS account. I've used this exact pattern (with minor tweaks)
# across large-scale production environments serving 1M+ users.
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
  # /20 gives us 4,094 IPs per subnet, which handled Northwind Telecom's scale fine.
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
  flow_log_retention   = 365
  enable_vpc_endpoints = true

  # NAT Gateway — single for dev/staging, HA for prod
  nat_gateway_mode = var.environment == "prod" ? "ha" : "single"
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
  publish_to_s3        = true
  findings_bucket      = "${var.project_name}-guardduty-findings-${local.account_id}"
  publishing_frequency = "FIFTEEN_MINUTES"
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

output "guardduty_alerts_topic_arn" {
  description = "SNS topic ARN for GuardDuty alerts"
  value       = var.enable_guardduty ? module.guardduty[0].alerts_topic_arn : null
}

output "guardduty_findings_bucket" {
  description = "S3 bucket where GuardDuty findings are published"
  value       = var.enable_guardduty ? module.guardduty[0].findings_bucket : null
}
