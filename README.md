# aws-security-baseline-terraform

**Production-grade AWS security baseline modules I've refined over 10+ years of securing infrastructure for 1M+ users.**

![Terraform](https://img.shields.io/badge/Terraform-≥1.5-purple?logo=terraform)
![AWS](https://img.shields.io/badge/AWS-Security-orange?logo=amazonaws)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Why this exists

I've been securing cloud infrastructure since before "cloud security" was a job title. After two decades in telecom and enterprise environments — maintaining 99.9% uptime while hardening systems serving over a million users — I got tired of rebuilding the same security foundations for every new AWS account.

This repo is the distilled result: a set of opinionated, battle-tested Terraform modules that deploy a complete security baseline in under 15 minutes. Every module comes from real production experience, not theory.

## What's inside

```
.
├── modules/
│   ├── vpc-secure/          # VPC with flow logs, private subnets, NACLs
│   ├── guardduty/           # GuardDuty with SNS alerting + S3 publishing
│   ├── security-hub/        # Security Hub with CIS + AWS Foundational benchmarks
│   ├── iam-baseline/        # Password policy, MFA enforcement, least-privilege roles
│   ├── cloudtrail/          # Multi-region trail with encryption + log validation
│   ├── kms-key-rotation/    # KMS keys with automatic yearly rotation
│   └── config-rules/        # AWS Config rules for continuous compliance
├── examples/
│   ├── full-baseline/       # Deploy everything in one shot
│   └── single-module/       # Use modules individually
├── tests/
│   └── validate.sh          # Checkov + tfsec + terraform validate
└── docs/
    └── architecture.md      # Architecture decision records
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        AWS Account                                │
│                                                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
│  │  CloudTrail  │  │  GuardDuty   │  │   Security Hub       │    │
│  │  (all regions)│  │  (threat det)│  │  (CIS + Foundational)│    │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘    │
│         │                 │                      │                │
│         ▼                 ▼                      ▼                │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │              SNS → Lambda → Slack/PagerDuty             │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                   │
│  ┌──────────────────────────────────────────────────────┐        │
│  │  VPC (10.0.0.0/16)                                    │        │
│  │  ├── Public Subnets (3 AZs) ── NAT Gateway           │        │
│  │  ├── Private Subnets (3 AZs) ── App workloads        │        │
│  │  ├── Isolated Subnets (3 AZs) ── Databases           │        │
│  │  ├── VPC Flow Logs → CloudWatch + S3                  │        │
│  │  └── NACLs + Security Groups (layered defense)        │        │
│  └──────────────────────────────────────────────────────┘        │
│                                                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐       │
│  │  IAM Baseline│  │  KMS Keys    │  │  AWS Config Rules │       │
│  │  (MFA, pwd)  │  │  (auto-rotate)│ │  (compliance)     │       │
│  └─────────────┘  └──────────────┘  └───────────────────┘       │
└──────────────────────────────────────────────────────────────────┘
```

## Quick start

```bash
git clone https://github.com/fdaniel-alvarez-dev/aws-security-baseline-terraform.git
cd aws-security-baseline-terraform/examples/full-baseline

# Review and customize
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# Deploy
terraform init
terraform plan
terraform apply
```

## Real-world context

These modules aren't academic exercises. Here's where the patterns come from:

- **VPC design**: Based on the network architecture I built at Tigo (Millicom Bolivia) for a private cloud serving 1M+ subscribers. The three-tier subnet layout (public/private/isolated) survived multiple security audits and zero breaches over 3+ years.

- **GuardDuty + alerting**: After we implemented threat detection at Tigo, we caught 3 unauthorized access attempts in the first month that had gone unnoticed for weeks. The alerting pipeline in this module is the same pattern we used.

- **IAM baseline**: The password policy and MFA enforcement here mirror the ISO 27001 controls I deployed as part of a security posture enhancement that reduced incidents by 30%.

- **CloudTrail + Config**: You can't fix what you can't see. Multi-region trailing with log validation caught a misconfigured S3 bucket within 4 hours of deployment — something that had been exposed for months.

## Module details

### vpc-secure

Deploys a production-ready VPC with defense-in-depth networking:

| Feature | Description |
|---------|-------------|
| 3-tier subnets | Public, private, isolated across 3 AZs |
| Flow logs | To CloudWatch (real-time) + S3 (long-term) |
| NACLs | Restrictive defaults, explicit allow rules |
| NAT Gateway | Single or HA (one per AZ) |
| VPC endpoints | S3, DynamoDB, ECR, CloudWatch (private access) |

### guardduty

Enables GuardDuty with automated response:

- Threat detection across EC2, S3, IAM, Kubernetes, and DNS
- Findings published to S3 (for SIEM integration) and SNS (for alerting)
- Optional auto-remediation Lambda for common findings

### iam-baseline

Enforces security hygiene:

- Password policy (14+ chars, complexity, 90-day rotation)
- MFA required for console access
- Break-glass admin role with CloudTrail monitoring
- Service-linked roles with least-privilege boundaries

## Running security checks

```bash
cd tests/
./validate.sh
```

This runs:
1. `terraform validate` — syntax check
2. `tfsec` — static analysis for Terraform security issues
3. `checkov` — policy-as-code compliance scanning

## Contributing

Found a security improvement? Open an issue or PR. I'm particularly interested in:
- Additional AWS Config rules for specific compliance frameworks
- Alternative alerting integrations (Teams, Discord, etc.)
- Cost optimization suggestions for the VPC endpoints

## Author

**Freddy Alvarez** — Senior Cloud Infrastructure Architect with 22+ years building and securing production systems. Currently pursuing a PhD in Cloud Computing Security.

- [LinkedIn](https://linkedin.com/in/falvarezpinto)
- [Medium](https://medium.com/@falvarezpinto) — 26 articles on cloud, DevOps, and AI infrastructure
- [GitHub](https://github.com/fdaniel-alvarez-dev)
