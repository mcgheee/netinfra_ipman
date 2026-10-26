from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from netinfra_ipman import hostwrites
from netinfra_ipman.hostwrites import HostWriteError, HostWriteService
from netinfra_ipman.netinfra import load_netinfra


SOURCE = b'''# file policy
--- # document policy
subnets:
  - cidr: 10.0.0.0/24
Custom:
  nested: "quoted"
Hosts:
  - Name: original # owner policy
    Extra:
      nested: [one, two]
    Records:
      - Target: 10.0.0.1
        ZoneName: example.com
      - RRType: TXT
        Target: 'verification=custom'
'''


def digest(content):
    return hashlib.sha256(content).hexdigest()


def payload(name="new", target="10.0.0.2", extra=""):
    return f"Name: {name}\nRecords:\n  - Target: {target}\n    ZoneName: example.com\n{extra}"


@pytest.fixture
def service(tmp_path):
    source = tmp_path / "inventory" / "NetInfra.yml"
    source.parent.mkdir()
    source.write_bytes(SOURCE)
    source.chmod(0o640)
    config = SimpleNamespace(netinfra_path=str(source), backup_dir=str(tmp_path / "backups"),
        backup_retention=2, git_enabled=False, git_repo_path=str(source.parent), git_branch="main")
    return HostWriteService(config)


def review(service, operation="create", content=None, host_index=None):
    source = Path(service.config.netinfra_path)
    return service.preview("editor", digest(source.read_bytes()), operation,
                           payload() if content is None else content, host_index)


def test_review_apply_preserves_document_and_backup(service):
    preview = review(service)
    assert preview.token and not preview.findings
    assert "--- NetInfra (current)" in preview.diff
    result = service.apply("editor", preview.token)
    source = Path(service.config.netinfra_path)
    saved = source.read_text()
    assert saved.startswith("# file policy\n--- # document policy\n")
    assert "# owner policy" in saved
    assert 'nested: "quoted"' in saved
    assert "'verification=custom'" in saved
    assert load_netinfra(source)["Hosts"][0]["Extra"] == {"nested": ["one", "two"]}
    assert result.revision == preview.proposed_revision == digest(source.read_bytes())
    assert result.git_status == "disabled"
    assert Path(result.backup).read_bytes() == SOURCE
    assert Path(result.backup).stat().st_mode & 0o777 == 0o600
    assert source.stat().st_mode & 0o777 == 0o640
    with pytest.raises(HostWriteError):
        service.apply("editor", preview.token)


def test_advanced_update_and_delete(service):
    content = payload("changed") + "CustomHost:\n  nested: [1, 2]\n"
    preview = review(service, "update", content, 0)
    service.apply("editor", preview.token)
    assert load_netinfra(service.config.netinfra_path)["Hosts"][0]["CustomHost"] == {"nested": [1, 2]}
    preview = review(service, "delete", "", 0)
    service.apply("editor", preview.token)
    assert load_netinfra(service.config.netinfra_path)["Hosts"] == []


@pytest.mark.parametrize("content", ["[", "[]", "null", "Name: x\nRecords: {}\n"])
def test_malformed_proposals_cannot_apply(service, content):
    try:
        preview = review(service, content=content)
    except HostWriteError:
        pass
    else:
        assert preview.findings and not preview.token
        with pytest.raises(HostWriteError):
            service.apply("editor", preview.token)
    assert Path(service.config.netinfra_path).read_bytes() == SOURCE


@pytest.mark.parametrize("content", [
    payload("ORIGINAL."), payload(target="192.0.2.1"), payload(target="bad"),
    payload(extra="    MAC: invalid\n"), payload(extra="    TTL: -1\n"),
    payload(extra="    Port: true\n"), payload(extra="    Block_DHCP: yes\n"),
    payload(extra="    Comment: [not, text]\n"),
    "Name: ipv6\nRecords:\n  - RRType: AAAA\n    Target: nope\n",
])
def test_invalid_values_and_cross_host_consistency_block_save(service, content):
    preview = review(service, content=content)
    assert preview.findings and not preview.token
    assert Path(service.config.netinfra_path).read_bytes() == SOURCE


def test_shared_ip_consistent_mac_and_custom_records_are_valid(service):
    content = '''Hosts:
  - Name: alias
    Records:
      - Target: 10.0.0.1
        MAC: aa:bb:cc:dd:ee:ff
  - Name: alias2
    Records:
      - Target: 10.0.0.1
        MAC: AABB.CCDD.EEFF
      - RRType: CNAME
        Target: elsewhere.example.
        Custom: {nested: [one, two]}
      - RRType: AAAA
        Target: "2001:db8::1"
'''
    preview = review(service, "import", content)
    assert not preview.findings
    service.apply("editor", preview.token)
    assert len(load_netinfra(service.config.netinfra_path)["Hosts"]) == 3


def test_cross_host_mac_conflict_is_rejected(service):
    first = review(service, content=payload("first", "10.0.0.1", "    MAC: aa:bb:cc:dd:ee:ff\n"))
    service.apply("editor", first.token)
    conflicting = review(service, content=payload("second", "10.0.0.1", "    MAC: 00:11:22:33:44:55\n"))
    assert not conflicting.token
    assert any("Conflicting" in finding for finding in conflicting.findings)


@pytest.mark.parametrize("content", [
    "Hosts:\n  - Name: new\n    Records: []\n  - Name: NEW.\n    Records: []\n",
    "- Name: original\n  Records: []\n- Name: innocent\n  Records: []\n",
    "Hosts: []\nsubnets: []\n",
])
def test_entire_import_is_rejected_without_partial_save(service, content):
    try:
        preview = review(service, "import", content)
    except HostWriteError:
        pass
    else:
        assert not preview.token and preview.findings
    assert Path(service.config.netinfra_path).read_bytes() == SOURCE


def test_tokens_are_opaque_actor_bound_expiring_and_not_client_mutable(service, monkeypatch):
    preview = review(service)
    for actor, token in [("other", preview.token), ("editor", preview.token + "x"), ("editor", "")]:
        with pytest.raises(HostWriteError):
            service.apply(actor, token)
    forged_view = replace(preview, proposed_revision="tampered", diff="arbitrary")
    # The public object is presentation only: bytes come from the server token.
    result = service.apply("editor", forged_view.token)
    assert result.revision == preview.proposed_revision
    preview = review(service, content=payload("later"))
    monkeypatch.setattr(hostwrites.time, "monotonic", lambda: float("inf"))
    with pytest.raises(HostWriteError):
        service.apply("editor", preview.token)


def test_restart_and_changed_settings_fail_closed(service):
    preview = review(service)
    restarted = HostWriteService(service.config)
    with pytest.raises(HostWriteError):
        restarted.apply("editor", preview.token)
    service.config.git_branch = "changed"
    with pytest.raises(HostWriteError):
        service.apply("editor", preview.token)


def test_stale_preview_and_stale_creation_are_rejected(service):
    preview = review(service)
    source = Path(service.config.netinfra_path)
    source.write_bytes(SOURCE + b"# external edit\n")
    with pytest.raises(HostWriteError, match="changed"):
        service.apply("editor", preview.token)
    with pytest.raises(HostWriteError, match="changed"):
        service.preview("editor", digest(SOURCE), "create", payload())


def test_concurrent_app_writers_only_save_one_preview(service):
    first = review(service, content=payload("first"))
    second = review(service, content=payload("second"))

    def apply(token):
        try:
            return service.apply("editor", token)
        except HostWriteError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(apply, [first.token, second.token]))
    assert sum(result is not None for result in results) == 1
    assert len(load_netinfra(service.config.netinfra_path)["Hosts"]) == 2


@pytest.mark.parametrize("failure", ["backup", "replace", "fsync"])
def test_filesystem_failures_preserve_source_and_token_for_retry(service, monkeypatch, failure):
    preview = review(service)
    with monkeypatch.context() as patch:
        def fail(*args, **kwargs):
            raise OSError("simulated failure")
        if failure == "backup":
            patch.setattr(service, "_backup", fail)
        elif failure == "replace":
            patch.setattr(hostwrites.os, "replace", fail)
        else:
            patch.setattr(hostwrites.os, "fsync", fail)
        with pytest.raises(HostWriteError):
            service.apply("editor", preview.token)
    assert Path(service.config.netinfra_path).read_bytes() == SOURCE
    service.apply("editor", preview.token)


def test_external_change_during_backup_is_rechecked(service, monkeypatch):
    preview = review(service)
    backup = service._backup
    source = Path(service.config.netinfra_path)

    def changed(source_path, content):
        result = backup(source_path, content)
        source.write_bytes(SOURCE + b"# external\n")
        return result

    monkeypatch.setattr(service, "_backup", changed)
    with pytest.raises(HostWriteError, match="changed"):
        service.apply("editor", preview.token)
    assert source.read_bytes() == SOURCE + b"# external\n"


def test_backups_are_outside_checkout_even_when_git_disabled(service):
    source = Path(service.config.netinfra_path)
    (source.parent / ".git").mkdir()
    service.config.backup_dir = str(source.parent / "backups")
    preview = review(service)
    with pytest.raises(HostWriteError, match="outside"):
        service.apply("editor", preview.token)
    assert source.read_bytes() == SOURCE


def test_backup_retention(service):
    for index in range(4):
        preview = review(service, content=payload(f"host{index}"))
        service.apply("editor", preview.token)
    assert len(list(Path(service.config.backup_dir).glob("*.bak"))) == 2


def test_git_precheck_failure_does_not_save_and_allows_retry(service, monkeypatch):
    service.config.git_enabled = True
    preview = review(service)
    with monkeypatch.context() as patch:
        def fail(config):
            raise RuntimeError("dirty checkout")
        patch.setattr(hostwrites.gitops, "ensure_clean_checkout", fail)
        with pytest.raises(HostWriteError):
            service.apply("editor", preview.token)
    assert Path(service.config.netinfra_path).read_bytes() == SOURCE
    monkeypatch.setattr(hostwrites.gitops, "ensure_clean_checkout", lambda config: None)
    monkeypatch.setattr(hostwrites.gitops, "commit_changes", lambda *args: None)
    assert service.apply("editor", preview.token).git_status == "committed"


def git_failure_service(service, monkeypatch):
    service.config.git_enabled = True
    monkeypatch.setattr(hostwrites.gitops, "ensure_clean_checkout", lambda config: None)
    def fail(*args):
        raise RuntimeError("Local Git operation failed")
    monkeypatch.setattr(hostwrites.gitops, "commit_changes", fail)
    return service.apply("editor", review(service).token)


def test_git_failure_is_saved_with_actor_bound_revision_bound_retry(service, monkeypatch):
    result = git_failure_service(service, monkeypatch)
    assert result.git_status == "failed" and result.retry_token
    assert result.revision == digest(Path(service.config.netinfra_path).read_bytes())
    with pytest.raises(HostWriteError):
        service.retry_commit("other", result.retry_token)
    calls = []
    monkeypatch.setattr(hostwrites.gitops, "retry_commit_changes", lambda *args: calls.append(args))
    retried = service.retry_commit("editor", result.retry_token)
    assert retried.git_status == "committed"
    assert calls[0][2] == [str(Path(service.config.netinfra_path).resolve())]
    with pytest.raises(HostWriteError):
        service.retry_commit("editor", result.retry_token)


def test_git_retry_rejects_external_changes(service, monkeypatch):
    result = git_failure_service(service, monkeypatch)
    source = Path(service.config.netinfra_path)
    source.write_bytes(source.read_bytes() + b"# changed\n")
    with pytest.raises(HostWriteError, match="changed"):
        service.retry_commit("editor", result.retry_token)


def test_git_retry_failure_retains_retry_token(service, monkeypatch):
    result = git_failure_service(service, monkeypatch)
    def fail(*args):
        raise RuntimeError("Local Git operation failed")
    monkeypatch.setattr(hostwrites.gitops, "retry_commit_changes", fail)
    retry = service.retry_commit("editor", result.retry_token)
    assert retry.git_status == "failed" and retry.retry_token == result.retry_token


def test_apply_revalidates_complete_server_side_proposal(service):
    preview = review(service)
    pending = service._previews[preview.token]
    service._previews[preview.token] = replace(pending, proposed=b"Hosts: [invalid]\n")
    with pytest.raises(HostWriteError, match="validation"):
        service.apply("editor", preview.token)
    assert Path(service.config.netinfra_path).read_bytes() == SOURCE


def test_preview_storage_is_bounded_and_evicted_tokens_fail_closed(service):
    service.max_pending = 2
    first = review(service, content=payload("first"))
    review(service, content=payload("second"))
    third = review(service, content=payload("third"))
    assert len(service._previews) == 2
    with pytest.raises(HostWriteError):
        service.apply("editor", first.token)
    assert service.apply("editor", third.token).revision == third.proposed_revision


def test_replace_write_failure_preserves_source_and_allows_retry(service, monkeypatch):
    preview = review(service)
    original_fdopen = hostwrites.os.fdopen

    class FailingWriter:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.handle.close()

        def fileno(self):
            return self.handle.fileno()

        def write(self, content):
            raise OSError("write failed")

    backup = service._backup

    def backup_then_fail_write(source, content):
        result = backup(source, content)
        monkeypatch.setattr(hostwrites.os, "fdopen",
                            lambda *args: FailingWriter(original_fdopen(*args)))
        return result

    with monkeypatch.context() as patch:
        # Restore fdopen explicitly before the retry after the failure scope.
        patch.setattr(service, "_backup", backup_then_fail_write)
        with pytest.raises(HostWriteError):
            service.apply("editor", preview.token)
    monkeypatch.setattr(hostwrites.os, "fdopen", original_fdopen)
    assert Path(service.config.netinfra_path).read_bytes() == SOURCE
    service.apply("editor", preview.token)
