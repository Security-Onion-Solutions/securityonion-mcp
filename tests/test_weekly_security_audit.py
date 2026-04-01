import os
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCRIPT = REPO_ROOT / "scripts" / "weekly_security_audit.sh"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _create_fake_repo(tmp_path: Path, *, with_log_lines: str = "") -> tuple[Path, Path, dict[str, str]]:
    repo = tmp_path / "repo"
    scripts_dir = repo / "scripts"
    logs_dir = repo / "logs"
    fake_bin = tmp_path / "fakebin"
    cmd_log = tmp_path / "cmd.log"

    scripts_dir.mkdir(parents=True)
    logs_dir.mkdir(parents=True)
    fake_bin.mkdir(parents=True)

    target_script = scripts_dir / "weekly_security_audit.sh"
    shutil.copy2(SOURCE_SCRIPT, target_script)
    target_script.chmod(target_script.stat().st_mode | stat.S_IXUSR)

    (repo / "requirements.txt").write_text("pytest==8.3.3\n")
    if with_log_lines:
        (logs_dir / "weekly_security_audit.log").write_text(with_log_lines)

    _write_executable(
        fake_bin / "git",
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            { printf 'git'; printf ' %q' "$@"; printf '\n'; } >> "${CMD_LOG:?}"
            cmd="${1:-}"
            shift || true

            case "$cmd" in
              remote)
                if [[ "${HAS_UPSTREAM:-0}" == "1" ]]; then
                  printf 'origin\nupstream\n'
                else
                  printf 'origin\n'
                fi
                ;;
              fetch)
                exit "${GIT_FETCH_EXIT:-0}"
                ;;
              rev-parse)
                printf '%s\n' "${CURRENT_BRANCH:-main}"
                ;;
              show-ref)
                if [[ "${BRANCH_EXISTS:-1}" == "1" ]]; then
                  exit 0
                fi
                exit 1
                ;;
              checkout)
                exit 0
                ;;
              rebase)
                if [[ "${1:-}" == "--abort" ]]; then
                  exit 0
                fi
                exit "${REBASE_EXIT:-0}"
                ;;
              diff)
                if [[ "${1:-}" == "--cached" ]]; then
                  if [[ "${CACHED_CHANGES:-0}" == "1" ]]; then
                    exit 1
                  fi
                  exit 0
                fi
                if [[ "${DIFF_CHANGES:-0}" == "1" ]]; then
                  exit 1
                fi
                exit 0
                ;;
              add|commit|push)
                exit 0
                ;;
              *)
                exit 0
                ;;
            esac
            """
        ),
    )

    _write_executable(
        fake_bin / "pip-audit",
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            { printf 'pip-audit'; printf ' %q' "$@"; printf '\n'; } >> "${CMD_LOG:?}"
            has_fix=0
            for arg in "$@"; do
              if [[ "$arg" == "--fix" ]]; then
                has_fix=1
              fi
            done
            if [[ "$has_fix" == "1" ]]; then
              printf '%s\n' "${PIP_AUDIT_FIX_OUTPUT:-fixed}"
              exit "${PIP_AUDIT_FIX_EXIT:-0}"
            fi
            printf '%s\n' "${PIP_AUDIT_SCAN_OUTPUT:-scan}"
            exit "${PIP_AUDIT_SCAN_EXIT:-0}"
            """
        ),
    )

    _write_executable(
        fake_bin / "pytest",
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            { printf 'pytest'; printf ' %q' "$@"; printf '\n'; } >> "${CMD_LOG:?}"
            printf 'simulated pytest run\n'
            exit "${PYTEST_EXIT:-0}"
            """
        ),
    )

    _write_executable(
        fake_bin / "pip",
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            { printf 'pip'; printf ' %q' "$@"; printf '\n'; } >> "${CMD_LOG:?}"
            exit 0
            """
        ),
    )

    _write_executable(
        fake_bin / "gh",
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            { printf 'gh'; printf ' %q' "$@"; printf '\n'; } >> "${CMD_LOG:?}"
            if [[ "${1:-}" == "pr" && "${2:-}" == "list" ]]; then
              if [[ -n "${GH_PR_NUMBER:-}" ]]; then
                printf '%s\n' "${GH_PR_NUMBER}"
              fi
              exit 0
            fi
            if [[ "${1:-}" == "pr" && "${2:-}" == "create" ]]; then
              printf '%s\n' "${GH_PR_URL:-https://example.test/pr/1}"
              exit 0
            fi
            exit 0
            """
        ),
    )

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env.get('PATH', '')}",
            "CMD_LOG": str(cmd_log),
        }
    )

    return repo, target_script, env


def _run_script(script_path: Path, repo: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(script_path)],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_script_is_executable() -> None:
    assert SOURCE_SCRIPT.exists(), "weekly_security_audit.sh must exist"
    assert os.access(SOURCE_SCRIPT, os.X_OK), "weekly_security_audit.sh must be executable"


def test_happy_path_commits_signed_and_opens_pr(tmp_path: Path) -> None:
    repo, script_path, env = _create_fake_repo(tmp_path)
    env.update({"HAS_UPSTREAM": "1", "BRANCH_EXISTS": "1", "DIFF_CHANGES": "1"})

    result = _run_script(script_path, repo, env)

    assert result.returncode == 0, result.stderr
    cmd_log = (tmp_path / "cmd.log").read_text()
    log_file = (repo / "logs" / "weekly_security_audit.log").read_text()

    assert "git fetch upstream main" in cmd_log
    assert "git rebase upstream/main" in cmd_log
    assert "pip-audit -r" in cmd_log
    assert "pip-audit -r" in cmd_log and "--fix" in cmd_log
    assert "pytest" in cmd_log
    assert "git commit -S" in cmd_log
    assert r"fix:\ update\ dependencies\ to\ resolve\ security\ vulnerabilities" in cmd_log
    assert "gh pr create" in cmd_log
    assert "Weekly Security Audit Completed Successfully" in log_file


def test_log_retention_prunes_old_entries(tmp_path: Path) -> None:
    old_line = "[2000-01-01T00:00:00Z] old entry\n"
    recent_line = "[2099-01-01T00:00:00Z] keep me\n"
    raw_line = "line without timestamp\n"
    repo, script_path, env = _create_fake_repo(tmp_path, with_log_lines=old_line + recent_line + raw_line)
    env.update({"HAS_UPSTREAM": "0", "BRANCH_EXISTS": "1", "DIFF_CHANGES": "0"})

    result = _run_script(script_path, repo, env)

    assert result.returncode == 0, result.stderr
    retained = (repo / "logs" / "weekly_security_audit.log").read_text()
    assert old_line not in retained
    assert recent_line in retained
    assert raw_line in retained


def test_aborts_on_pytest_failure_without_push(tmp_path: Path) -> None:
    repo, script_path, env = _create_fake_repo(tmp_path)
    env.update({"PYTEST_EXIT": "1", "BRANCH_EXISTS": "1"})

    result = _run_script(script_path, repo, env)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "Tests failed" in output

    cmd_log = (tmp_path / "cmd.log").read_text()
    assert "git push" not in cmd_log
    assert "git commit" not in cmd_log
