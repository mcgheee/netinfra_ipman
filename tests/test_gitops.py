import subprocess
from pathlib import Path

import pytest

from netinfra_ipman.config import AppConfig
from netinfra_ipman.gitops import commit_changes, ensure_clean_checkout, retry_commit_changes


def run_git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo, stderr=subprocess.STDOUT, text=True).strip()


@pytest.fixture
def checkout(tmp_path):
    repo = tmp_path / "checkout"
    repo.mkdir()
    run_git(repo, "init", "-b", "main")
    run_git(repo, "config", "user.name", "Temporary Test")
    run_git(repo, "config", "user.email", "test@example.invalid")
    source = repo / "inventory with spaces.yml"
    source.write_text("Hosts: []\n")
    (repo / "other.txt").write_text("original\n")
    run_git(repo, "add", "--", source.name, "other.txt")
    run_git(repo, "commit", "-m", "initial")
    config = AppConfig(
        netinfra_path=str(source), git_enabled=True, git_repo_path=str(repo),
        backup_dir=str(tmp_path / "backups"),
    )
    return config, repo, source


def test_clean_checkout_does_not_switch_branch_or_change_files(checkout):
    config, repo, source = checkout
    before = source.read_bytes()
    ensure_clean_checkout(config)
    assert run_git(repo, "branch", "--show-current") == "main"
    assert source.read_bytes() == before
    assert run_git(repo, "status", "--porcelain") == ""


@pytest.mark.parametrize("detached", [False, True])
def test_wrong_branch_and_detached_head_are_refused_without_switching(checkout, detached):
    config, repo, _ = checkout
    run_git(repo, "checkout", "--detach" if detached else "-b", *([] if detached else ["other"]))
    before = run_git(repo, "rev-parse", "HEAD")
    with pytest.raises(RuntimeError):
        ensure_clean_checkout(config)
    assert run_git(repo, "rev-parse", "HEAD") == before
    assert run_git(repo, "branch", "--show-current") == ("" if detached else "other")


@pytest.mark.parametrize("kind", ["modified", "staged", "untracked", "source"])
def test_clean_checkout_rejects_every_dirty_state(checkout, kind):
    config, repo, source = checkout
    path = source if kind == "source" else repo / ("new.txt" if kind == "untracked" else "other.txt")
    path.write_text("changed\n")
    if kind == "staged":
        run_git(repo, "add", "--", path.name)
    with pytest.raises(RuntimeError, match="not clean"):
        ensure_clean_checkout(config)
    assert path.read_text() == "changed\n"


def test_configured_repository_must_be_checkout_root(checkout):
    config, repo, source = checkout
    directory = repo / "nested"
    directory.mkdir()
    source.rename(directory / source.name)
    config.netinfra_path = str(directory / source.name)
    config.git_repo_path = str(directory)
    with pytest.raises(RuntimeError, match="checkout root"):
        ensure_clean_checkout(config)


def test_source_must_be_inside_configured_checkout(checkout, tmp_path):
    config, _, _ = checkout
    outside = tmp_path / "outside.yml"
    outside.write_text("Hosts: []")
    config.netinfra_path = str(outside)
    with pytest.raises(RuntimeError, match="inside"):
        ensure_clean_checkout(config)


def test_nested_source_checkout_is_not_committed_through_outer_checkout(checkout):
    config, repo, _ = checkout
    nested = repo / "nested"
    nested.mkdir()
    run_git(nested, "init", "-b", "main")
    source = nested / "source.yml"
    source.write_text("Hosts: []")
    config.netinfra_path = str(source)
    with pytest.raises(RuntimeError, match="different Git checkout"):
        ensure_clean_checkout(config)


def test_successful_commit_is_local_and_contains_only_source(checkout):
    config, repo, source = checkout
    ensure_clean_checkout(config)
    source.write_text("Hosts: [{Name: changed}]\n")
    commit_changes(config, "Change reviewed host", [str(source)])
    assert run_git(repo, "log", "-1", "--format=%s") == "Change reviewed host"
    assert run_git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD") == source.name
    assert run_git(repo, "status", "--porcelain") == ""
    assert run_git(repo, "remote") == ""


@pytest.mark.parametrize("staged", [False, True])
def test_retry_accepts_only_source_modification_or_staging(checkout, staged):
    config, repo, source = checkout
    source.write_text("Hosts: [{Name: retry}]\n")
    if staged:
        run_git(repo, "add", "--", source.name)
    retry_commit_changes(config, "Retry reviewed host", [str(source)])
    assert run_git(repo, "show", f"HEAD:{source.name}") == source.read_text().strip()
    assert run_git(repo, "status", "--porcelain") == ""


@pytest.mark.parametrize("staged", [False, True])
@pytest.mark.parametrize("function", [commit_changes, retry_commit_changes])
def test_commit_and_retry_refuse_unrelated_dirty_files(checkout, staged, function):
    config, repo, source = checkout
    source.write_text("Hosts: [{Name: saved}]\n")
    other = repo / "other.txt"
    other.write_text("unrelated\n")
    if staged:
        run_git(repo, "add", "--", other.name)
    before = run_git(repo, "rev-parse", "HEAD")
    with pytest.raises(RuntimeError, match="other than"):
        function(config, "must not commit", [str(source)])
    assert run_git(repo, "rev-parse", "HEAD") == before
    assert source.read_text() == "Hosts: [{Name: saved}]\n"
    assert other.read_text() == "unrelated\n"


def test_retry_refuses_untracked_files_and_wrong_branch(checkout):
    config, repo, source = checkout
    source.write_text("Hosts: [{Name: saved}]\n")
    extra = repo / "untracked"
    extra.write_text("unrelated")
    with pytest.raises(RuntimeError, match="other than"):
        retry_commit_changes(config, "retry", [str(source)])
    extra.unlink()
    run_git(repo, "checkout", "-b", "other")
    with pytest.raises(RuntimeError, match="configured branch"):
        retry_commit_changes(config, "retry", [str(source)])
    assert run_git(repo, "branch", "--show-current") == "other"


def test_failed_commit_preserves_saved_source_and_can_be_retried(checkout):
    config, repo, source = checkout
    source.write_text("Hosts: [{Name: saved}]\n")
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho 'private-hook-secret' >&2\nexit 1\n")
    hook.chmod(0o700)
    with pytest.raises(RuntimeError) as error:
        commit_changes(config, "reviewed change", [str(source)])
    assert "private-hook-secret" not in str(error.value)
    assert source.read_text() == "Hosts: [{Name: saved}]\n"
    assert run_git(repo, "diff", "--cached", "--name-only") == source.name
    hook.unlink()
    retry_commit_changes(config, "reviewed change", [str(source)])
    assert run_git(repo, "status", "--porcelain") == ""


@pytest.mark.parametrize("paths", [[], ["other.txt"], ["source.yml", "other.txt"]])
def test_commit_refuses_any_other_path_selection(checkout, paths):
    config, repo, _ = checkout
    with pytest.raises(RuntimeError, match="only the configured"):
        commit_changes(config, "invalid", paths)
    assert run_git(repo, "status", "--porcelain") == ""


def test_commit_accepts_cwd_relative_source(checkout, monkeypatch):
    config, repo, source = checkout
    monkeypatch.chdir(repo.parent)
    relative = str(Path(repo.name) / source.name)
    config.netinfra_path = relative
    source.write_text("Hosts: [{Name: relative}]\n")
    commit_changes(config, "relative path", [relative])
    assert run_git(repo, "status", "--porcelain") == ""


def test_git_process_failures_are_sanitized(checkout, monkeypatch):
    config, _, _ = checkout
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["git", "private-secret"], output="private-secret")
    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="Local Git operation failed") as error:
        ensure_clean_checkout(config)
    assert "private-secret" not in str(error.value)


def test_missing_git_binary_is_sanitized(checkout, monkeypatch):
    config, _, _ = checkout
    def fail(*args, **kwargs):
        raise FileNotFoundError("private-secret")
    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="Local Git operation failed") as error:
        ensure_clean_checkout(config)
    assert "private-secret" not in str(error.value)


def test_inherited_git_directory_cannot_redirect_operations(checkout, monkeypatch):
    config, repo, _ = checkout
    monkeypatch.setenv("GIT_DIR", "/does/not/exist/private-secret")
    monkeypatch.setenv("GIT_WORK_TREE", "/does/not/exist")
    ensure_clean_checkout(config)
    assert repo.exists()


def test_runtime_backup_check_catches_mutated_configuration(checkout):
    config, repo, _ = checkout
    config.backup_dir = str(repo / "backups")
    with pytest.raises(RuntimeError, match="outside"):
        ensure_clean_checkout(config)


@pytest.mark.parametrize("enabled", [False, True])
def test_config_rejects_backups_inside_actual_source_checkout(checkout, enabled):
    config, repo, _ = checkout
    config.git_enabled = enabled
    config.backup_dir = str(repo / "backups")
    with pytest.raises(ValueError, match="outside the source Git checkout"):
        config.validate()


def test_config_rejects_backups_inside_source_worktree(checkout, tmp_path):
    _, repo, _ = checkout
    worktree = tmp_path / "linked"
    run_git(repo, "worktree", "add", "-b", "linked", str(worktree))
    with pytest.raises(ValueError, match="outside the source Git checkout"):
        AppConfig(netinfra_path=str(worktree / "inventory with spaces.yml"), backup_dir=str(worktree / "backups"))


def test_disabled_git_never_invokes_git(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Git was invoked")
    monkeypatch.setattr(subprocess, "run", fail)
    config = AppConfig()
    ensure_clean_checkout(config)
    commit_changes(config, "disabled", [])
    retry_commit_changes(config, "disabled", [])


@pytest.mark.parametrize("kind", ["deleted", "renamed", "untracked"])
def test_retry_refuses_non_modification_source_states(checkout, kind):
    config, repo, source = checkout
    if kind == "deleted":
        source.unlink()
    elif kind == "renamed":
        run_git(repo, "mv", "--", source.name, "renamed.yml")
        config.netinfra_path = str(repo / "renamed.yml")
    else:
        run_git(repo, "rm", "--cached", "--", source.name)
    before = run_git(repo, "rev-parse", "HEAD")
    with pytest.raises(RuntimeError):
        retry_commit_changes(config, "must not commit", [config.netinfra_path])
    assert run_git(repo, "rev-parse", "HEAD") == before


def test_retry_stages_current_saved_source_not_older_index_contents(checkout):
    config, repo, source = checkout
    source.write_text("Hosts: [{Name: older}]\n")
    run_git(repo, "add", "--", source.name)
    source.write_text("Hosts: [{Name: reviewed}]\n")
    retry_commit_changes(config, "reviewed source", [str(source)])
    assert run_git(repo, "show", f"HEAD:{source.name}") == "Hosts: [{Name: reviewed}]"
    assert run_git(repo, "status", "--porcelain") == ""


def test_backup_alias_inside_checkout_is_refused_even_with_git_disabled(checkout, tmp_path):
    config, repo, _ = checkout
    alias = tmp_path / "backup-alias"
    alias.symlink_to(repo, target_is_directory=True)
    config.git_enabled = False
    config.backup_dir = str(alias / "backups")
    with pytest.raises(ValueError, match="outside the source Git checkout"):
        config.validate()


def test_valid_configuration_accepts_external_backup_retention(checkout):
    config, _, _ = checkout
    config.backup_retention = 1
    config.validate()
