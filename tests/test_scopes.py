"""Scoped vaults: config, matching, write-back policy, manifests and Secret delivery."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from auto_pass import k8s, kdbx, scopes
from auto_pass.keepassxc import KeepassCommandError

CONFIG = """
[settings]
scopes_dir = "{dir}"
[scopes.intake]
entries = ["infra/intake-*", "shared/store"]
writable = ["infra/intake-api"]
writeback_path = "{dir}/pod.kdbx"
[scopes.media]
entries = ["media/*"]
"""


def _cfg(tmp_path: Path) -> scopes.ScopeConfig:
    path = tmp_path / "scopes.toml"
    path.write_text(CONFIG.format(dir=tmp_path))
    return scopes.load_config(path)


def _entry(path: str, password: str = "pw", modified: str = "", **extra: str) -> kdbx.Entry:
    fields = {"Title": path.rsplit("/", 1)[-1], "Password": password, **extra}
    return kdbx.Entry(path, fields, modified=modified)


# --- config ------------------------------------------------------------------------------------


def test_load_config_defaults(tmp_path):
    cfg = _cfg(tmp_path)
    assert cfg.scopes["media"].namespace == "media"
    assert cfg.scopes["media"].secret_name == "media-vault"
    assert cfg.output_path(cfg.scopes["media"]) == tmp_path / "media.kdbx"


@pytest.mark.parametrize(
    "body, message",
    [
        ('[scopes.Bad_Name]\nentries = ["a"]', "DNS label"),
        ("[scopes.x]\nentries = []", "at least one glob"),
        ('[scopes.x]\nentries = ["a"]\nwritable = ["a"]', "writeback_path"),
        (
            '[scopes.a]\nentries = ["a"]\nnamespace = "n"\nsecret_name = "s"\n'
            '[scopes.b]\nentries = ["b"]\nnamespace = "n"\nsecret_name = "s"',
            "reuses secret",
        ),
    ],
)
def test_load_config_rejects(tmp_path, body, message):
    path = tmp_path / "s.toml"
    path.write_text(body)
    with pytest.raises(scopes.ScopeError, match=message):
        scopes.load_config(path)


def test_match_entries_excludes_reserved_prefix(tmp_path):
    cfg = _cfg(tmp_path)
    broad = scopes.Scope("x", "x", "x-vault", entries=("*",))
    master = {p: _entry(p) for p in ("infra/intake-api", "auto-pass/scopes/intake", "other")}
    assert set(scopes.match_entries(broad, master)) == {"infra/intake-api", "other"}
    assert set(scopes.match_entries(cfg.scopes["intake"], master)) == {"infra/intake-api"}


# --- state -------------------------------------------------------------------------------------


def test_state_file_is_private_and_roundtrips(tmp_path):
    state = scopes.State.load(tmp_path / "state.json")
    state.scopes["a"] = {"digest": "d"}
    state.save()
    assert (tmp_path / "state.json").stat().st_mode & 0o777 == 0o600
    again = scopes.State.load(tmp_path / "state.json")
    assert again.key == state.key
    assert again.get("a") == {"digest": "d"}


# --- write-back policy (kdbx I/O faked) ---------------------------------------------------------


@pytest.fixture
def wb(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    scope = cfg.scopes["intake"]
    pod = tmp_path / "pod.kdbx"
    pod.write_bytes(b"x")
    state = scopes.State(b"k" * 32, path=tmp_path / "st.json")
    master = scopes.Master("/m.kdbx", "mpw")
    written: dict[str, str] = {}
    monkeypatch.setattr(
        scopes,
        "run_keepassxc_set_password_direct",
        lambda path, value, **kw: written.__setitem__(path, value),
    )

    def run(master_entries, pod_entries, baseline):
        monkeypatch.setattr(kdbx, "read_entries", lambda *a, **k: pod_entries)
        state.scopes["intake"] = {"passwords": baseline}
        result = scopes.ScopeResult("intake")
        scopes._write_back(scope, pod, master, master_entries, "spw", state, result)
        return result

    return run, written, state


def _d(state, value):
    return _entry("x", value).password_digest(state.key)


def test_writeback_applies_change_when_master_unmoved(wb):
    run, written, state = wb
    m = {"infra/intake-api": _entry("infra/intake-api", "old")}
    p = {"infra/intake-api": _entry("infra/intake-api", "new")}
    result = run(m, p, {"infra/intake-api": _d(state, "old")})
    assert written == {"infra/intake-api": "new"}
    assert result.written_back == ["infra/intake-api"]


def _both_changed(wb, master_time, pod_time):
    run, written, state = wb
    path = "infra/intake-api"
    m = {path: _entry(path, "master-new", master_time)}
    p = {path: _entry(path, "pod-new", pod_time)}
    return run(m, p, {path: _d(state, "old")}), written


def test_both_changed_pod_newer_wins(wb):
    result, written = _both_changed(wb, "2026-11-20T10:00:00Z", "2026-11-20T11:00:00Z")
    assert written == {"infra/intake-api": "pod-new"}
    assert result.resolved == ["infra/intake-api: pod newer, applied"]


def test_both_changed_master_newer_wins(wb):
    result, written = _both_changed(wb, "2026-11-20T12:00:00Z", "2026-11-20T11:00:00Z")
    assert written == {}
    assert result.resolved == ["infra/intake-api: master newer, kept"]


def test_both_changed_equal_time_keeps_master(wb):
    _result, written = _both_changed(wb, "2026-11-20T11:00:00Z", "2026-11-20T11:00:00Z")
    assert written == {}


def test_both_changed_future_pod_timestamp_is_not_believed(wb):
    result, written = _both_changed(wb, "2026-11-20T10:00:00Z", "2999-01-01T00:00:00Z")
    assert written == {}
    assert "untrusted pod timestamp" in result.conflicts[0]


def test_both_changed_unparseable_time_keeps_master(wb):
    result, written = _both_changed(wb, "", "2026-11-20T11:00:00Z")
    assert written == {} and result.conflicts


def test_writeback_ignores_new_readonly_and_unchanged(wb):
    run, written, state = wb
    m = {
        "infra/intake-api": _entry("infra/intake-api", "same"),
        "shared/store": _entry("shared/store", "old"),
    }
    p = {
        "infra/intake-api": _entry("infra/intake-api", "same"),
        "shared/store": _entry("shared/store", "tampered"),  # in scope, not writable
        "infra/evil": _entry("infra/evil", "x"),  # not in the master
    }
    base = {"infra/intake-api": _d(state, "same"), "shared/store": _d(state, "old")}
    result = run(m, p, base)
    assert written == {}
    assert sorted(result.ignored) == ["infra/evil", "shared/store"]
    assert result.conflicts == []


def test_writeback_ignores_entry_outside_scope_even_if_in_master(wb):
    run, written, state = wb
    m = {"infra/intake-api": _entry("infra/intake-api", "a"), "prod/root": _entry("prod/root")}
    p = {"prod/root": _entry("prod/root", "pwned")}
    result = run(m, p, {})
    assert written == {}
    assert result.ignored == ["prod/root"]


def test_writeback_consumes_each_pod_file_once(wb, tmp_path):
    run, written, state = wb
    m = {"infra/intake-api": _entry("infra/intake-api", "old")}
    p = {"infra/intake-api": _entry("infra/intake-api", "new")}
    base = {"infra/intake-api": _d(state, "old")}
    run(m, p, base)
    assert written
    written.clear()
    # Same file, master later changed back: the stale pod copy must not be replayed.
    result = scopes.ScopeResult("intake")
    state.scopes["intake"]["passwords"] = base
    scopes._write_back(
        _cfg(tmp_path).scopes["intake"],
        tmp_path / "pod.kdbx",
        scopes.Master("/m", "p"),
        m,
        "spw",
        state,
        result,
    )
    assert written == {} and not result.written_back


def test_writeback_refusal_is_a_warning_not_a_crash(wb, monkeypatch):
    run, _written, state = wb

    def boom(*a, **k):
        raise KeepassCommandError("nope")

    monkeypatch.setattr(scopes, "run_keepassxc_set_password_direct", boom)
    m = {"infra/intake-api": _entry("infra/intake-api", "old")}
    p = {"infra/intake-api": _entry("infra/intake-api", "new")}
    result = run(m, p, {"infra/intake-api": _d(state, "old")})
    assert result.warnings and not result.written_back


# --- manifests and Secret delivery --------------------------------------------------------------


def test_manifests_give_pods_no_permissions(tmp_path):
    cfg = _cfg(tmp_path)
    docs = k8s.scope_documents(cfg.scopes["intake"], cfg, with_namespace=True)
    kinds = [d["kind"] for d in docs]
    assert kinds == ["Namespace", "ServiceAccount", "Role", "RoleBinding"]
    sa = docs[1]
    assert sa["automountServiceAccountToken"] is False
    role = docs[2]
    named = [r for r in role["rules"] if "resourceNames" in r]
    assert named[0]["resourceNames"] == ["intake-vault"]
    assert set(named[0]["verbs"]) == {"get", "update", "patch"}
    assert [r["verbs"] for r in role["rules"] if "resourceNames" not in r] == [["create"]]
    # No Role or binding grants the pod's own ServiceAccount anything.
    assert all(
        s["name"] != "intake" for d in docs if d["kind"] == "RoleBinding" for s in d["subjects"]
    )
    assert docs[0]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"


def test_rendered_manifest_has_no_secret_data(tmp_path):
    cfg = _cfg(tmp_path)
    text = k8s.render_manifests(list(cfg.scopes.values()), cfg)
    assert 'kind: "Secret"' not in text
    assert text.count('\nkind: "Role"\n') == 2


def test_apply_secret_sends_data_on_stdin_only(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["stdin"] = cmd, kw["input"]
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    k8s.apply_secret(cfg.scopes["intake"], cfg, b"DB", "hunter2", "a" * 40)
    assert seen["cmd"] == ["kubectl", "apply", "-f", "-"]
    body = json.loads(seen["stdin"])
    assert body["metadata"]["name"] == "intake-vault"
    assert set(body["data"]) == {"vault.kdbx", "password"}
    assert "hunter2" not in " ".join(seen["cmd"])


def test_verify_isolation_flags_cross_access(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    answers = iter(
        # intake-sa/media-sa vs each secret: get, update (4 each), then the sync check
        ["no", "no", "no", "no", "yes", "no", "yes", "no", "no", "yes"]
    )
    monkeypatch.setattr(k8s, "_can_i", lambda *a, **k: next(answers))
    checks = k8s.verify_isolation(list(cfg.scopes.values()), cfg)
    assert [c.ok for c in checks].count(False) == 1


# --- real keepassxc-cli (skipped where it is not installed) -------------------------------------

real = pytest.mark.skipif(shutil.which("keepassxc-cli") is None, reason="keepassxc-cli missing")


def _cli(*args, stdin=""):
    r = subprocess.run(["keepassxc-cli", *args], input=stdin, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


@pytest.fixture
def vault(tmp_path):
    db = str(tmp_path / "master.kdbx")
    _cli("db-create", "-q", "-p", db, stdin="mpw\nmpw\n")
    _cli("mkdir", "-q", db, "infra", stdin="mpw\n")
    _cli(
        "add", "-q", "-p", "-u", "bob", "--notes", "a\nb: c", db, "infra/intake-api",
        stdin="mpw\nTOK1\nTOK1\n",
    )  # fmt: skip
    _cli("add", "-q", "-p", db, "infra/other", stdin="mpw\nOTHER\nOTHER\n")
    return db


@real
def test_scoped_vault_contains_only_scope_and_roundtrips_writeback(tmp_path, vault):
    cfg = _cfg(tmp_path)
    scope = cfg.scopes["intake"]
    master = scopes.Master(vault, "mpw")
    state = scopes.State.load(tmp_path / "state.json")

    first = scopes.sync_scope(scope, cfg, master, state)
    assert first.rebuilt and first.matched == 1
    spw = kdbx.read_entries(vault, "mpw")["auto-pass/scopes/intake"].fields["Password"]
    built = kdbx.read_entries(str(cfg.output_path(scope)), spw)
    assert set(built) == {"infra/intake-api"}
    assert built["infra/intake-api"].fields["Notes"] == "a\nb: c"
    # The master password does not open the scoped vault, and vice versa.
    assert subprocess.run(
        ["keepassxc-cli", "ls", "-q", str(cfg.output_path(scope))],
        input="mpw\n", capture_output=True, text=True,
    ).returncode != 0  # fmt: skip
    assert not scopes.sync_scope(scope, cfg, master, state).rebuilt

    pod = tmp_path / "pod.kdbx"
    shutil.copy(cfg.output_path(scope), pod)
    _cli("edit", "-q", "-p", str(pod), "infra/intake-api", stdin=f"{spw}\nTOK2\nTOK2\n")
    _cli("add", "-q", "-p", str(pod), "infra/evil", stdin=f"{spw}\nX\nX\n")
    result = scopes.sync_scope(scope, cfg, master, state)
    assert result.written_back == ["infra/intake-api"] and result.ignored == ["infra/evil"]
    after = kdbx.read_entries(vault, "mpw")
    assert after["infra/intake-api"].fields["Password"] == "TOK2"
    assert "infra/evil" not in after


@real
def test_consolidate_merges_under_alias_and_is_idempotent(tmp_path, vault):
    from auto_pass import consolidate

    sub = str(tmp_path / "fin.kdbx")
    _cli("db-create", "-q", "-p", sub, stdin="vpw\nvpw\n")
    _cli("mkdir", "-q", sub, "bank", stdin="vpw\n")
    _cli("add", "-q", "-p", "-u", "u1", sub, "bank/checking", stdin="vpw\nB1\nB1\n")
    _cli("mkdir", "-q", vault, "vaults", stdin="mpw\n")
    _cli("add", "-q", "-p", vault, "vaults/fin.kdbx", stdin="mpw\nvpw\nvpw\n")
    index = tmp_path / "idx.json"
    index.write_text(
        json.dumps(
            {
                "databases": {
                    "master": {"database_path": vault},
                    "fin": {
                        "database_path": sub,
                        "database_password_source": {"entry": "vaults/fin.kdbx"},
                    },
                }
            }
        )
    )
    master = scopes.Master(vault, "mpw")
    plans = consolidate.plan(master, index)
    assert {p.alias: p.new for p in plans if not p.skipped_reason} == {"fin": 1}
    assert not any("fin/" in p for p in kdbx.read_entries(vault, "mpw"))  # a plan changes nothing

    _, backups = consolidate.apply(master, index)
    assert len(backups) == 2 and all(b.exists() for b in backups)
    merged = kdbx.read_entries(vault, "mpw")
    assert merged["fin/bank/checking"].fields["Password"] == "B1"
    assert merged["infra/other"].fields["Password"] == "OTHER"  # nothing removed
    assert consolidate.apply(master, index)[1] == []  # idempotent: nothing new, no backups


@real
def test_common_split_then_merge_gives_alias_groups(tmp_path, vault):
    from auto_pass import consolidate

    sub = str(tmp_path / "fin.kdbx")
    _cli("db-create", "-q", "-p", sub, stdin="vpw\nvpw\n")
    _cli("mkdir", "-q", sub, "bank", stdin="vpw\n")
    _cli("add", "-q", "-p", sub, "bank/checking", stdin="vpw\nB1\nB1\n")
    _cli("mkdir", "-q", vault, "vaults", stdin="mpw\n")
    _cli("add", "-q", "-p", vault, "vaults/fin.kdbx", stdin="mpw\nvpw\nvpw\n")
    index = tmp_path / "idx.json"
    index.write_text(
        json.dumps(
            {
                "databases": {
                    "master": {"database_path": vault},
                    "fin": {
                        "database_path": sub,
                        "database_password_source": {"entry": "vaults/fin.kdbx"},
                    },
                }
            }
        )
    )
    master = scopes.Master(vault, "mpw")
    planned = consolidate.plan(master, index, with_common=True)
    assert planned[0].alias == "common" and planned[0].create
    assert not (tmp_path / "common.kdbx").exists()  # plan only

    consolidate.apply(master, index, with_common=True)
    assert json.loads(index.read_text())["databases"]["common"]["database_path"].endswith(
        "common.kdbx"
    )
    merged = kdbx.read_entries(vault, "mpw")
    assert merged["common/infra/intake-api"].fields["Password"] == "TOK1"
    assert merged["common/vaults/fin.kdbx"].fields["Password"] == "vpw"
    assert merged["fin/bank/checking"].fields["Password"] == "B1"
    assert not any(p.startswith("common/auto-pass") for p in merged)
    # The common vault opens with the password stored in the master and holds the old master.
    cpw = merged["vaults/common.kdbx"].fields["Password"]
    assert "infra/intake-api" in kdbx.read_entries(str(tmp_path / "common.kdbx"), cpw)
    assert consolidate.apply(master, index, with_common=True)[1] == []  # idempotent


def test_return_secret_rbac_is_limited_to_one_object(tmp_path):
    path = tmp_path / "s.toml"
    path.write_text(
        '[scopes.intake]\nentries = ["a/*"]\nwritable = ["a/x"]\nwriteback = "secret"\n'
    )
    cfg = scopes.load_config(path)
    scope = cfg.scopes["intake"]
    assert cfg.writeback_file(scope) == cfg.scopes_dir / "intake.return.kdbx"
    docs = k8s.scope_documents(scope, cfg)
    role = next(d for d in docs if d["metadata"]["name"] == "intake-return" and d["kind"] == "Role")
    assert role["rules"] == [
        {
            "apiGroups": [""],
            "resources": ["secrets"],
            "resourceNames": ["intake-vault-return"],
            "verbs": ["get", "update", "patch"],
        }
    ]
    binding = next(
        d for d in docs if d["kind"] == "RoleBinding" and "return" in d["metadata"]["name"]
    )
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "intake", "namespace": "intake"}
    ]


def test_writeback_secret_mode_validation(tmp_path):
    path = tmp_path / "s.toml"
    path.write_text('[scopes.x]\nentries = ["a"]\nwriteback = "secret"\n')
    with pytest.raises(scopes.ScopeError, match="needs a writable list"):
        scopes.load_config(path)


def test_pull_return_writes_private_file_and_skips_unchanged(tmp_path, monkeypatch):
    import base64

    cfg = _cfg(tmp_path)
    scope = cfg.scopes["intake"]
    payload = json.dumps({"data": {"vault.kdbx": base64.b64encode(b"KDBX").decode()}})
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, payload, "")
    )
    dest = tmp_path / "ret.kdbx"
    assert k8s.pull_return(scope, cfg, dest) is True
    assert dest.read_bytes() == b"KDBX" and dest.stat().st_mode & 0o777 == 0o600
    assert k8s.pull_return(scope, cfg, dest) is False


def test_push_return_patches_only_the_named_secret(tmp_path, monkeypatch):
    sa = tmp_path / "sa"
    sa.mkdir()
    (sa / "token").write_text("TKN")
    (sa / "namespace").write_text("intake")
    (sa / "ca.crt").write_text("")
    monkeypatch.setattr(k8s, "_SA_DIR", sa)
    monkeypatch.setattr(k8s.ssl, "create_default_context", lambda **kw: None)
    seen = {}

    class Resp:
        def close(self):
            pass

    def fake_open(request, **kw):
        seen["url"], seen["method"] = request.full_url, request.method
        seen["auth"] = request.headers["Authorization"]
        seen["body"] = json.loads(request.data)
        return Resp()

    monkeypatch.setattr(k8s.urllib.request, "urlopen", fake_open)
    vault = tmp_path / "v.kdbx"
    vault.write_bytes(b"DATA")
    k8s.push_return(vault, "intake-vault-return")
    assert seen["url"].endswith("/api/v1/namespaces/intake/secrets/intake-vault-return")
    assert seen["method"] == "PATCH" and seen["auth"] == "Bearer TKN"
    assert list(seen["body"]["data"]) == ["vault.kdbx"]
    big = tmp_path / "big.kdbx"
    big.write_bytes(b"x" * (k8s.MAX_RETURN_BYTES + 1))
    with pytest.raises(k8s.K8sError, match="return Secret holds"):
        k8s.push_return(big, "s")
