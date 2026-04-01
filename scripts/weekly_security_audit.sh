#!/usr/bin/env bash
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
#
# weekly_security_audit.sh — Idempotent weekly security audit script.
# Audits Python dependencies for vulnerabilities, updates requirements.txt,
# runs the test suite, and opens a pull request with the changes.

set -euo pipefail

###############################################################################
# Configuration
###############################################################################
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRANCH_NAME="security/audit-dependencies-update"
MAIN_BRANCH="main"
LOG_DIR="${REPO_ROOT}/logs"
LOG_FILE="${LOG_DIR}/weekly_security_audit.log"
RETENTION_DAYS=30
TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

###############################################################################
# Helpers
###############################################################################
log() {
    local msg="[${TIMESTAMP}] $*"
    echo "${msg}" | tee -a "${LOG_FILE}"
}

die() {
    log "FATAL: $*"
    exit 1
}

ensure_command() {
    if ! command -v "$1" &>/dev/null; then
        log "Installing $1 ..."
        pip install --quiet "$1" || die "Failed to install $1"
    fi
}

###############################################################################
# Setup logging with 30-day retention
###############################################################################
mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}"

# Prune log entries older than 30 days
if [[ -s "${LOG_FILE}" ]]; then
    cutoff_epoch="$(date -u -d "-${RETENTION_DAYS} days" '+%s' 2>/dev/null || date -u -v-${RETENTION_DAYS}d '+%s' 2>/dev/null || echo 0)"
    if [[ "${cutoff_epoch}" -gt 0 ]]; then
        tmp_log="$(mktemp)"
        while IFS= read -r line; do
            # Extract ISO timestamp from log line: [2024-01-01T00:00:00Z]
            ts="$(echo "${line}" | grep -oP '^\[\K[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' || true)"
            if [[ -z "${ts}" ]]; then
                echo "${line}" >> "${tmp_log}"
                continue
            fi
            entry_epoch="$(date -u -d "${ts}" '+%s' 2>/dev/null || echo 0)"
            if [[ "${entry_epoch}" -ge "${cutoff_epoch}" ]]; then
                echo "${line}" >> "${tmp_log}"
            fi
        done < "${LOG_FILE}"
        mv "${tmp_log}" "${LOG_FILE}"
    fi
fi

log "===== Weekly Security Audit Started ====="

###############################################################################
# Navigate to repo root
###############################################################################
cd "${REPO_ROOT}"

###############################################################################
# Fetch upstream
###############################################################################
log "Fetching upstream ${MAIN_BRANCH} ..."
if git remote | grep -q '^upstream$'; then
    git fetch upstream "${MAIN_BRANCH}" || die "Failed to fetch upstream"
    BASE_REF="upstream/${MAIN_BRANCH}"
else
    git fetch origin "${MAIN_BRANCH}" || die "Failed to fetch origin"
    BASE_REF="origin/${MAIN_BRANCH}"
fi
log "Fetched ${BASE_REF} successfully."

###############################################################################
# Idempotence: reuse or create the feature branch
###############################################################################
current_branch="$(git rev-parse --abbrev-ref HEAD)"

if git show-ref --verify --quiet "refs/heads/${BRANCH_NAME}"; then
    log "Branch ${BRANCH_NAME} already exists — switching to it and rebasing."
    git checkout "${BRANCH_NAME}"
    git rebase "${BASE_REF}" || {
        git rebase --abort 2>/dev/null || true
        die "Rebase failed — manual intervention required."
    }
else
    log "Creating branch ${BRANCH_NAME} from ${BASE_REF} ..."
    git checkout -b "${BRANCH_NAME}" "${BASE_REF}"
fi

###############################################################################
# Ensure audit tooling is available
###############################################################################
ensure_command pip-audit

###############################################################################
# Run pip-audit and capture results
###############################################################################
log "Running pip-audit ..."
audit_output="$(pip-audit -r "${REPO_ROOT}/requirements.txt" 2>&1)" || true
log "pip-audit output:"
log "${audit_output}"

###############################################################################
# Attempt to fix vulnerable dependencies
###############################################################################
log "Attempting to fix vulnerable dependencies ..."
fix_output="$(pip-audit -r "${REPO_ROOT}/requirements.txt" --fix 2>&1)" || true
log "pip-audit --fix output:"
log "${fix_output}"

# If pip-audit --fix updated requirements.txt it writes in place; capture any
# remaining vulnerabilities for the log.
remaining="$(pip-audit -r "${REPO_ROOT}/requirements.txt" 2>&1)" || true
log "Remaining vulnerabilities (if any):"
log "${remaining}"

###############################################################################
# Run the test suite
###############################################################################
log "Running test suite ..."
if pytest "${REPO_ROOT}" --tb=short -q 2>&1 | tee -a "${LOG_FILE}"; then
    log "All tests passed."
else
    die "Tests failed — aborting audit. Please fix tests before retrying."
fi

###############################################################################
# Commit changes (if any)
###############################################################################
if git diff --quiet && git diff --cached --quiet; then
    log "No dependency changes detected — nothing to commit."
else
    log "Committing dependency updates ..."
    git add "${REPO_ROOT}/requirements.txt"
    git commit -S -m "fix: update dependencies to resolve security vulnerabilities

Automated weekly security audit performed by scripts/weekly_security_audit.sh.
Vulnerable packages identified by pip-audit have been updated." || die "Commit failed."
    log "Changes committed."
fi

###############################################################################
# Push feature branch
###############################################################################
log "Pushing branch ${BRANCH_NAME} ..."
push_remote="origin"
git push --force-with-lease "${push_remote}" "${BRANCH_NAME}" || die "Push failed."
log "Branch pushed to ${push_remote}/${BRANCH_NAME}."

###############################################################################
# Open or update pull request
###############################################################################
if command -v gh &>/dev/null; then
    existing_pr="$(gh pr list --head "${BRANCH_NAME}" --base "${MAIN_BRANCH}" --json number --jq '.[0].number' 2>/dev/null || true)"
    if [[ -n "${existing_pr}" && "${existing_pr}" != "null" ]]; then
        log "Pull request #${existing_pr} already exists — skipping PR creation."
    else
        log "Opening pull request ..."
        pr_url="$(gh pr create \
            --title "fix: update dependencies to resolve security vulnerabilities" \
            --body "## Summary
- Automated weekly security audit via \`scripts/weekly_security_audit.sh\`
- Ran \`pip-audit\` to detect and fix vulnerable dependencies
- All tests pass after dependency updates

## Audit Log
\`\`\`
${remaining}
\`\`\`" \
            --base "${MAIN_BRANCH}" \
            --head "${BRANCH_NAME}" 2>&1)" || log "WARNING: PR creation failed: ${pr_url}"
        log "Pull request created: ${pr_url}"
    fi
else
    log "WARNING: gh CLI not found — skipping pull request creation."
fi

log "===== Weekly Security Audit Completed Successfully ====="
exit 0
