#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Security validation suite for Terraform modules
# Runs: terraform validate → tfsec → checkov
#
# I run this in CI before every merge. It's caught
# misconfigured S3 buckets, overly permissive IAM policies,
# and unencrypted resources more times than I can count.
# ──────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ERRORS=0

echo "═══════════════════════════════════════════════════════"
echo "  AWS Security Baseline — Validation Suite"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Step 1: Terraform Format Check ──────────────────────────
echo -e "${YELLOW}[1/4] Checking Terraform formatting...${NC}"
if terraform fmt -check -recursive "$ROOT_DIR/modules" 2>/dev/null; then
    echo -e "${GREEN}  ✓ All files properly formatted${NC}"
else
    echo -e "${RED}  ✗ Formatting issues found. Run: terraform fmt -recursive${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ── Step 2: Terraform Validate ──────────────────────────────
echo -e "${YELLOW}[2/4] Validating Terraform syntax...${NC}"
for module_dir in "$ROOT_DIR"/modules/*/; do
    module_name=$(basename "$module_dir")
    cd "$module_dir"
    if terraform init -backend=false -input=false >/dev/null 2>&1 && \
       terraform validate >/dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Module: $module_name${NC}"
    else
        echo -e "${RED}  ✗ Module: $module_name — validation failed${NC}"
        ERRORS=$((ERRORS + 1))
    fi
done

echo -e "${YELLOW}    Validating examples...${NC}"
for example_dir in "$ROOT_DIR"/examples/*/; do
    example_name=$(basename "$example_dir")
    if ls "$example_dir"/*.tf >/dev/null 2>&1; then
        cd "$example_dir"
        if terraform init -backend=false -input=false >/dev/null 2>&1 && \
           terraform validate >/dev/null 2>&1; then
            echo -e "${GREEN}  ✓ Example: $example_name${NC}"
        else
            echo -e "${RED}  ✗ Example: $example_name — validation failed${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done
echo ""

# ── Step 3: tfsec Static Analysis ───────────────────────────
echo -e "${YELLOW}[3/4] Running tfsec security scan...${NC}"
if command -v tfsec &>/dev/null; then
    if tfsec "$ROOT_DIR/modules" --minimum-severity HIGH --format default --no-color; then
        echo -e "${GREEN}  ✓ No HIGH/CRITICAL issues found${NC}"
    else
        echo -e "${RED}  ✗ tfsec found security issues${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${YELLOW}  ⚠ tfsec not installed. Install: brew install tfsec${NC}"
fi
echo ""

# ── Step 4: Checkov Policy-as-Code ──────────────────────────
echo -e "${YELLOW}[4/4] Running Checkov compliance scan...${NC}"
if command -v checkov &>/dev/null; then
    if checkov -d "$ROOT_DIR/modules" --framework terraform --compact; then
        echo -e "${GREEN}  ✓ Checkov compliance passed${NC}"
    else
        if [ "${CHECKOV_STRICT:-0}" = "1" ]; then
            echo -e "${RED}  ✗ Checkov found compliance issues${NC}"
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${YELLOW}  ⚠ Checkov found compliance issues (non-blocking). Re-run with CHECKOV_STRICT=1 to fail on findings.${NC}"
        fi
    fi
else
    echo -e "${YELLOW}  ⚠ Checkov not installed. Install: pip install checkov${NC}"
fi
echo ""

# ── Summary ─────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}  ALL CHECKS PASSED ✓${NC}"
    echo "═══════════════════════════════════════════════════════"
    exit 0
else
    echo -e "${RED}  $ERRORS CHECK(S) FAILED ✗${NC}"
    echo "═══════════════════════════════════════════════════════"
    exit 1
fi
