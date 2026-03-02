# ──────────────────────────────────────────────────────────────
# Module: guardduty
# Threat detection with automated alerting
# ──────────────────────────────────────────────────────────────

variable "project_name" { type = string }
variable "environment" { type = string }
variable "alert_email" { type = string }

variable "enable_s3_protection" {
  type    = bool
  default = true
}

variable "enable_eks_protection" {
  type    = bool
  default = true
}

variable "enable_malware_protection" {
  type    = bool
  default = true
}

variable "publish_to_s3" {
  type    = bool
  default = true
}

variable "findings_bucket" {
  type    = string
  default = ""
}

variable "publishing_frequency" {
  type    = string
  default = "FIFTEEN_MINUTES"
}

variable "sns_kms_master_key_id" {
  description = "Optional KMS key ARN/ID for encrypting the GuardDuty alerts SNS topic (defaults to a module-managed CMK)"
  type        = string
  default     = ""
}

variable "s3_kms_master_key_id" {
  description = "Optional KMS key ARN/ID for encrypting the GuardDuty findings S3 bucket (defaults to a module-managed CMK)"
  type        = string
  default     = ""
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_kms_key" "guardduty" {
  description         = "KMS CMK for GuardDuty findings and alerting"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableAccountRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSnsUseOfKey"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${var.project_name}-${var.environment}-guardduty-alerts"
          }
        }
      },
      {
        Sid    = "AllowS3UseOfKey"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "guardduty" {
  name          = "alias/${var.project_name}-${var.environment}-guardduty"
  target_key_id = aws_kms_key.guardduty.key_id
}

locals {
  sns_kms_master_key_id = var.sns_kms_master_key_id != "" ? var.sns_kms_master_key_id : aws_kms_key.guardduty.arn
  s3_kms_master_key_id  = var.s3_kms_master_key_id != "" ? var.s3_kms_master_key_id : aws_kms_key.guardduty.arn
}

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = var.publishing_frequency

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_eks_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = { Name = "${var.project_name}-${var.environment}-guardduty" }
}

# ── S3 Bucket for Findings ───────────────────────────────────

resource "aws_s3_bucket" "findings" {
  count  = var.publish_to_s3 ? 1 : 0
  bucket = var.findings_bucket

  tags = { Name = "${var.project_name}-${var.environment}-guardduty-findings" }
}

resource "aws_s3_bucket_versioning" "findings" {
  count  = var.publish_to_s3 ? 1 : 0
  bucket = aws_s3_bucket.findings[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  count  = var.publish_to_s3 ? 1 : 0
  bucket = aws_s3_bucket.findings[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.s3_kms_master_key_id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  count                   = var.publish_to_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.findings[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "findings" {
  count  = var.publish_to_s3 ? 1 : 0
  bucket = aws_s3_bucket.findings[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowGuardDutyPut"
        Effect    = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.findings[0].arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "AllowGuardDutyGetBucketLocation"
        Effect    = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:GetBucketLocation"
        Resource  = aws_s3_bucket.findings[0].arn
      }
    ]
  })
}

# ── SNS Alert on High-Severity Findings ──────────────────────

resource "aws_sns_topic" "guardduty_alerts" {
  name              = "${var.project_name}-${var.environment}-guardduty-alerts"
  kms_master_key_id = local.sns_kms_master_key_id
  tags              = { Name = "${var.project_name}-guardduty-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule: alert on HIGH and CRITICAL findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project_name}-guardduty-high-findings"
  description = "Trigger on GuardDuty HIGH/CRITICAL findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })

  tags = { Name = "${var.project_name}-guardduty-high-findings" }
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "guardduty-to-sns"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      title       = "$.detail.title"
      description = "$.detail.description"
      region      = "$.detail.region"
      account     = "$.detail.accountId"
      type        = "$.detail.type"
    }
    input_template = "\"[SECURITY ALERT] GuardDuty finding in account <account> (<region>): <title> — Severity: <severity> — Type: <type>\""
  }
}

resource "aws_sns_topic_policy" "guardduty_alerts" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}

# ── Outputs ──────────────────────────────────────────────────

output "detector_id" { value = aws_guardduty_detector.main.id }
output "findings_bucket" { value = var.publish_to_s3 ? aws_s3_bucket.findings[0].id : null }
output "alerts_topic_arn" { value = aws_sns_topic.guardduty_alerts.arn }
