#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_DIR/logs"
LOG_FILE="$LOG_DIR/weekly_security_audit.log"
CURRENT_DATE=$(date +%Y%m%d)
BRANCH_NAME="weekly-audit-$CURRENT_DATE"
DATE_LOG=$(date '+%Y-%m-%d %H:%M:%S')

mkdir -p "$LOG_DIR"

log() {
    echo "[$DATE_LOG] $1" | tee -a "$LOG_FILE"
}

log "=== Starting Weekly Security Audit ==="

log "Step 1: Fetching latest main branch from upstream..."
git fetch upstream main --force 2>/dev/null || git fetch origin main --force
log "Successfully fetched latest main branch"

log "Step 2: Running dependency audit..."
AUDIT_TOOL=""
if command -v pip-audit &> /dev/null; then
    AUDIT_TOOL="pip-audit"
    log "Using pip-audit for dependency audit"
elif command -v safety &> /dev/null; then
    AUDIT_TOOL="safety"
    log "Using safety for dependency audit (pip-audit not available)"
else
    log "ERROR: No audit tool available (pip-audit or safety)"
    exit 1
fi

if [ "$AUDIT_TOOL" == "pip-audit" ]; then
    AUDIT_OUTPUT=$(pip-audit -r "$PROJECT_DIR/requirements.txt" 2>&1) || true
else
    AUDIT_OUTPUT=$(safety check -r "$PROJECT_DIR/requirements.txt" 2>&1) || true
fi

log "Audit output: $AUDIT_OUTPUT"

log "Step 3: Updating vulnerable dependencies..."
CHANGES_MADE=false
if [ "$AUDIT_TOOL" == "pip-audit" ]; then
    VULNERABLE_PKGS=$(pip-audit -r "$PROJECT_DIR/requirements.txt" 2>&1 | grep -E "Found [0-9]+ known vulnerability" || echo "")
    if [ -n "$VULNERABLE_PKGS" ]; then
        log "Vulnerabilities found, attempting updates..."
        pip install --upgrade -r "$PROJECT_DIR/requirements.txt"
        CHANGES_MADE=true
    else
        log "No vulnerabilities found, checking for outdated packages..."
        pip list --outdated --format=freeze 2>/dev/null | cut -d = -f 1 > /tmp/outdated.txt || true
        if [ -s /tmp/outdated.txt ]; then
            UPDATING=$(cat /tmp/outdated.txt | tr '\n' ' ')
            log "Updating outdated packages: $UPDATING"
            pip install --upgrade $UPDATING
            pip freeze > "$PROJECT_DIR/requirements.txt"
            CHANGES_MADE=true
        else
            log "No outdated packages found"
        fi
        rm -f /tmp/outdated.txt
    fi
else
    safety check -r "$PROJECT_DIR/requirements.txt" 2>&1 | grep -E "Found [0-9]+ known vulnerability" && {
        log "Vulnerabilities found, attempting updates..."
        pip install --upgrade -r "$PROJECT_DIR/requirements.txt"
        CHANGES_MADE=true
    } || {
        log "No vulnerabilities found, checking for outdated packages..."
        pip list --outdated --format=freeze 2>/dev/null | cut -d = -f 1 > /tmp/outdated.txt || true
        if [ -s /tmp/outdated.txt ]; then
            UPDATING=$(cat /tmp/outdated.txt | tr '\n' ' ')
            log "Updating outdated packages: $UPDATING"
            pip install --upgrade $UPDATING
            pip freeze > "$PROJECT_DIR/requirements.txt"
            CHANGES_MADE=true
        else
            log "No outdated packages found"
        fi
        rm -f /tmp/outdated.txt
    }
fi

log "Step 4: Running test suite..."
TEST_OUTPUT=$(python -m pytest tests/ -v --tb=short 2>&1)
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -ne 0 ]; then
    log "ERROR: Tests failed!"
    log "$TEST_OUTPUT"
    exit 1
else
    log "All tests passed successfully"
fi

log "Step 5: Checking for changes and creating commit..."
git status --porcelain > /tmp/git_status.txt
if [ -s /tmp/git_status.txt ]; then
    log "Changes detected: $(cat /tmp/git_status.txt | wc -l) file(s) modified"
    
    EXISTING_BRANCH=$(git branch --list "$BRANCH_NAME" | wc -l)
    if [ "$EXISTING_BRANCH" -gt 0 ]; then
        log "Branch $BRANCH_NAME already exists, checking if commit already made..."
        CURRENT_HASH=$(git rev-parse HEAD)
        PREVIOUS_COMMIT=$(git log --format="%H" -1)
        if [ "$CURRENT_HASH" == "$PREVIOUS_COMMIT" ]; then
            log "No new changes since last commit, skipping"
        else
            log "New changes detected, committing..."
            git add -A
            COMMIT_MSG="chore(deps): weekly security audit update $CURRENT_DATE"
            git commit -S -m "$COMMIT_MSG"
            log "Commit created: $COMMIT_MSG"
            
            git push -u origin "$BRANCH_NAME" --force
            log "Branch pushed to origin: $BRANCH_NAME"
            
            PR_EXISTS=$(gh pr list --head "$BRANCH_NAME" --state open --json number --jq '.[0].number' 2>/dev/null || echo "")
            if [ -n "$PR_EXISTS" ]; then
                log "PR already exists for branch $BRANCH_NAME: #$PR_EXISTS"
            else
                PR_URL=$(gh pr create --title "$COMMIT_MSG" --body "## Summary

This PR includes the results of the weekly security audit.

### Changes
- Dependency updates based on security audit
- Auto-generated on $CURRENT_DATE

### Testing
- All tests passed successfully

### Audit Results
\$(cat $LOG_FILE | tail -100)" --base main --head "$BRANCH_NAME" --draft 2>/dev/null || \
                gh pr create --title "$COMMIT_MSG" --body "## Summary

This PR includes the results of the weekly security audit.

### Changes
- Dependency updates based on security audit
- Auto-generated on $CURRENT_DATE

### Testing
- All tests passed successfully" --base main --head "$BRANCH_NAME" 2>/dev/null)
                log "PR created: $PR_URL"
            fi
        fi
    else
        log "Creating new branch: $BRANCH_NAME"
        git checkout -b "$BRANCH_NAME"
        
        git add -A
        COMMIT_MSG="chore(deps): weekly security audit update $CURRENT_DATE"
        git commit -S -m "$COMMIT_MSG"
        log "Commit created: $COMMIT_MSG"
        
        git push -u origin "$BRANCH_NAME" --force
        log "Branch pushed to origin: $BRANCH_NAME"
        
        PR_URL=$(gh pr create --title "$COMMIT_MSG" --body "## Summary

This PR includes the results of the weekly security audit.

### Changes
- Dependency updates based on security audit
- Auto-generated on $CURRENT_DATE

### Testing
- All tests passed successfully

### Audit Results
$(cat $LOG_FILE | tail -100)" --base main --head "$BRANCH_NAME" --draft 2>/dev/null || \
            gh pr create --title "$COMMIT_MSG" --body "## Summary

This PR includes the results of the weekly security audit.

### Changes
- Dependency updates based on security audit
- Auto-generated on $CURRENT_DATE

### Testing
- All tests passed successfully" --base main --head "$BRANCH_NAME" 2>/dev/null)
        log "PR created: $PR_URL"
    fi
else
    log "No changes detected, skipping commit and PR creation"
fi

rm -f /tmp/git_status.txt

log "Step 6: Setting up log retention (30 days)..."
find "$LOG_DIR" -name "weekly_security_audit.log" -mtime +30 -exec rm -f {} \; 2>/dev/null || true
log "Log retention policy applied"

log "=== Weekly Security Audit Completed Successfully ==="
log "Log file: $LOG_FILE"

exit 0
