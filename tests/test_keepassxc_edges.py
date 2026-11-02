"""keepassxc.py edge cases: credentials, the master-password cache, and command failures.

No real keepassxc-cli, vault, terminal or home directory is used: ``subprocess.run`` and
``getpass`` are replaced, the environment is isolated, and every cache file lives under
``tmp_path``.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from auto_pass import keepassxc as kp
from auto_pass.keepassxc import KeepassCommandError, KeepassXCStoreConfig

ENV_NAMES = (
    "AUTO_PASS_KEEPASSXC_DB_PATH",
    "PF_KEEPASSXC_DB_PATH",
    "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
    "PF_KEEPASSXC_DB_PASSWORD",
    "AUTO_PASS_KEEPASSXC_KEY_FILE",
    "PF_KEEPASSXC_KEY_FILE",
)
SECRET = "master-pw-s3cret"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(kp.sys.stdin, "isatty", lambda: False, raising=False)


class Runner:
    """Stands in for subprocess.run and records every call."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.results:
            result = self.results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return done()


def done(stdout="", stderr="", code=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code)


def config(tmp_path, **kwargs):
    kwargs.setdefault("database_path", "/vault/db.kdbx")
    kwargs.setdefault("database_password_cache_file", str(tmp_path / "cache" / "pw.json"))
    return KeepassXCStoreConfig(**kwargs)


@pytest.fixture
def runner(monkeypatch):
    def install(*results):
        run = Runner(*results)
        monkeypatch.setattr(kp.subprocess, "run", run)
        return run

    return install


@pytest.fixture
def with_password(monkeypatch):
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_DB_PASSWORD", SECRET)


# --- the env context manager ------------------------------------------------------------


def test_context_sets_and_restores_credentials(monkeypatch):
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_DB_PATH", "/old.kdbx")
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_KEY_FILE", "/old.key")

    with kp.with_keepassxc_context("/new.kdbx", "pw", "/new.key"):
        assert os.environ["AUTO_PASS_KEEPASSXC_DB_PATH"] == "/new.kdbx"
        assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == "pw"
        assert os.environ["AUTO_PASS_KEEPASSXC_KEY_FILE"] == "/new.key"

    assert os.environ["AUTO_PASS_KEEPASSXC_DB_PATH"] == "/old.kdbx"
    assert os.environ["AUTO_PASS_KEEPASSXC_KEY_FILE"] == "/old.key"
    assert "AUTO_PASS_KEEPASSXC_DB_PASSWORD" not in os.environ


def test_context_without_key_file_hides_an_inherited_one(monkeypatch):
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_KEY_FILE", "/inherited.key")

    with kp.with_keepassxc_context("/db.kdbx", "pw"):
        assert "AUTO_PASS_KEEPASSXC_KEY_FILE" not in os.environ

    assert os.environ["AUTO_PASS_KEEPASSXC_KEY_FILE"] == "/inherited.key"


def test_context_restores_and_unlocks_when_the_body_raises():
    with pytest.raises(RuntimeError):
        with kp.with_keepassxc_context("/db.kdbx", "pw"):
            raise RuntimeError("boom")

    assert "AUTO_PASS_KEEPASSXC_DB_PASSWORD" not in os.environ
    assert kp._keepass_env_lock.acquire(blocking=False)
    kp._keepass_env_lock.release()


def test_context_serialises_threads():
    seen = []
    ready = threading.Event()

    def other():
        ready.set()
        with kp.with_keepassxc_context("/b.kdbx", "pw-b"):
            seen.append(os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"])

    with kp.with_keepassxc_context("/a.kdbx", "pw-a"):
        thread = threading.Thread(target=other)
        thread.start()
        ready.wait(2)
        time.sleep(0.05)
        assert seen == []
        assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == "pw-a"
    thread.join(2)

    assert seen == ["pw-b"]


# --- attribute names ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("pw", "Password"),
        ("USER", "UserName"),
        ("Website", "URL"),
        ("otp", "TOTP"),
        ("  note  ", "Notes"),
        ("CustomField", "CustomField"),
        ("", ""),
        (None, ""),
    ],
)
def test_attribute_names_are_normalised(given, expected):
    assert kp.normalize_keepass_attribute_name(given) == expected


def test_field_lookup_blank_name_finds_nothing():
    assert kp.lookup_keepass_field_case_insensitive({"Password": "x"}, "  ") == ""


def test_field_lookup_prefers_the_exact_name_then_the_normalised_one():
    fields = {"pw": "alias-value", "Password": "canonical"}
    assert kp.lookup_keepass_field_case_insensitive(fields, "pw") == "alias-value"
    assert kp.lookup_keepass_field_case_insensitive({"Password": "canonical"}, "pw") == "canonical"


def test_field_lookup_skips_blank_values_and_falls_back_to_a_case_insensitive_match():
    fields = {"pw": "   ", "PASSWORD": "from-upper"}
    assert kp.lookup_keepass_field_case_insensitive(fields, "pw") == "from-upper"


def test_field_lookup_ignores_a_case_insensitive_match_that_is_blank():
    assert kp.lookup_keepass_field_case_insensitive({"password": "  "}, "Password") == ""


def test_field_lookup_unknown_is_empty():
    assert kp.lookup_keepass_field_case_insensitive({"a": "b"}, "missing") == ""


# --- configuration lookup -----------------------------------------------------------------


def test_database_path_comes_from_env_before_config(monkeypatch, tmp_path):
    monkeypatch.setenv("PF_KEEPASSXC_DB_PATH", "/from-env.kdbx")
    assert kp._resolve_db_path(config(tmp_path)) == "/from-env.kdbx"


def test_missing_database_path_names_the_variable_to_export(tmp_path):
    with pytest.raises(KeepassCommandError, match="AUTO_PASS_KEEPASSXC_DB_PATH"):
        kp._resolve_db_path(KeepassXCStoreConfig())


def test_key_file_from_env_then_config(monkeypatch, tmp_path):
    assert kp._resolve_key_file(config(tmp_path, database_key_file="/cfg.key")) == "/cfg.key"
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_KEY_FILE", "/env.key")
    assert kp._resolve_key_file(config(tmp_path, database_key_file="/cfg.key")) == "/env.key"


def test_default_cache_path_is_per_database(tmp_path):
    cfg = KeepassXCStoreConfig(database_password_cache_dir=str(tmp_path))
    first = kp._default_cache_path(cfg, "/a.kdbx")
    second = kp._default_cache_path(cfg, "/b.kdbx")
    assert first != second
    assert first.parent == tmp_path
    assert kp._default_cache_path(cfg, "/a.kdbx") == first


def test_explicit_cache_file_wins(tmp_path):
    cfg = KeepassXCStoreConfig(database_password_cache_file=str(tmp_path / "x.json"))
    assert kp._default_cache_path(cfg, "/a.kdbx") == tmp_path / "x.json"


# --- the master-password cache ------------------------------------------------------------


def prompt_with(monkeypatch, value):
    monkeypatch.setattr(kp.sys.stdin, "isatty", lambda: True, raising=False)
    asked = []

    def fake(prompt):
        asked.append(prompt)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(kp, "getpass", fake)
    return asked


def test_an_existing_password_is_left_alone(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_DB_PASSWORD", "already")
    asked = prompt_with(monkeypatch, "never")

    kp.seed_keepass_password_env_for_tty(config(tmp_path))

    assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == "already"
    assert asked == []


def test_prompted_password_is_cached_owner_only_even_under_a_zero_umask(monkeypatch, tmp_path):
    prompt_with(monkeypatch, SECRET)
    cfg = config(tmp_path)
    cache = tmp_path / "cache" / "pw.json"
    old = os.umask(0)
    try:
        kp.seed_keepass_password_env_for_tty(cfg)
    finally:
        os.umask(old)

    assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == SECRET
    assert json.loads(cache.read_text()) == {"password": SECRET}
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600
    assert stat.S_IMODE(cache.parent.stat().st_mode) == 0o700


def test_the_cache_file_is_never_created_wider_than_owner_only(monkeypatch, tmp_path):
    """The mode must be right at creation, not fixed by a chmod afterwards."""
    prompt_with(monkeypatch, SECRET)
    modes = []
    real_open = os.open

    def spy(path, flags, mode=0o777, **kw):
        if str(path).endswith("pw.json"):
            modes.append(mode)
        return real_open(path, flags, mode, **kw)

    monkeypatch.setattr(kp.os, "open", spy)
    kp.seed_keepass_password_env_for_tty(config(tmp_path))

    assert modes == [0o600]


def test_an_existing_loose_cache_file_is_tightened_when_rewritten(monkeypatch, tmp_path):
    cache = tmp_path / "cache" / "pw.json"
    cache.parent.mkdir()
    cache.write_text("{}")
    cache.chmod(0o644)
    prompt_with(monkeypatch, SECRET)

    kp.seed_keepass_password_env_for_tty(config(tmp_path))

    assert stat.S_IMODE(cache.stat().st_mode) == 0o600
    assert json.loads(cache.read_text()) == {"password": SECRET}


def test_a_fresh_cache_is_used_without_prompting(monkeypatch, tmp_path):
    cache = tmp_path / "cache" / "pw.json"
    cache.parent.mkdir()
    cache.write_text(json.dumps({"password": "  cached-pw  "}))
    asked = prompt_with(monkeypatch, "never")

    kp.seed_keepass_password_env_for_tty(config(tmp_path))

    assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == "cached-pw"
    assert asked == []


def test_an_expired_cache_is_deleted_and_the_user_asked_again(monkeypatch, tmp_path):
    cache = tmp_path / "cache" / "pw.json"
    cache.parent.mkdir()
    cache.write_text(json.dumps({"password": "stale"}))
    old = time.time() - 7200
    os.utime(cache, (old, old))
    asked = prompt_with(monkeypatch, "fresh")

    kp.seed_keepass_password_env_for_tty(config(tmp_path, database_password_cache_ttl_seconds=60))

    assert len(asked) == 1
    assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == "fresh"
    assert json.loads(cache.read_text()) == {"password": "fresh"}


def test_a_zero_ttl_means_the_cache_never_expires(monkeypatch, tmp_path):
    cache = tmp_path / "cache" / "pw.json"
    cache.parent.mkdir()
    cache.write_text(json.dumps({"password": "forever"}))
    old = time.time() - 10**7
    os.utime(cache, (old, old))

    kp.seed_keepass_password_env_for_tty(config(tmp_path, database_password_cache_ttl_seconds=0))

    assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == "forever"


@pytest.mark.parametrize("body", ["not json", "[1, 2]", json.dumps({"password": "  "}), "{}"])
def test_an_unusable_cache_is_ignored(monkeypatch, tmp_path, body):
    cache = tmp_path / "cache" / "pw.json"
    cache.parent.mkdir()
    cache.write_text(body)

    kp.seed_keepass_password_env_for_tty(config(tmp_path))  # not a tty: nothing to ask

    assert "AUTO_PASS_KEEPASSXC_DB_PASSWORD" not in os.environ


def test_a_disabled_cache_is_neither_read_nor_written(monkeypatch, tmp_path):
    cache = tmp_path / "cache" / "pw.json"
    cache.parent.mkdir()
    cache.write_text(json.dumps({"password": "cached"}))
    prompt_with(monkeypatch, "typed")

    kp.seed_keepass_password_env_for_tty(config(tmp_path, database_password_cache_enabled=False))

    assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == "typed"
    assert json.loads(cache.read_text()) == {"password": "cached"}


def test_without_a_terminal_nothing_is_asked(monkeypatch, tmp_path):
    asked = []
    monkeypatch.setattr(kp, "getpass", lambda p: asked.append(p) or "x")

    kp.seed_keepass_password_env_for_tty(config(tmp_path))

    assert asked == []
    assert "AUTO_PASS_KEEPASSXC_DB_PASSWORD" not in os.environ


@pytest.mark.parametrize("answer", [EOFError(), KeyboardInterrupt(), ""])
def test_an_aborted_or_empty_prompt_sets_and_caches_nothing(monkeypatch, tmp_path, answer):
    prompt_with(monkeypatch, answer)

    kp.seed_keepass_password_env_for_tty(config(tmp_path))

    assert "AUTO_PASS_KEEPASSXC_DB_PASSWORD" not in os.environ
    assert not (tmp_path / "cache" / "pw.json").exists()


def test_an_unwritable_cache_still_lets_this_run_proceed(monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where the directory should be")
    prompt_with(monkeypatch, SECRET)

    kp.seed_keepass_password_env_for_tty(
        config(tmp_path, database_password_cache_file=str(blocker / "pw.json"))
    )

    assert os.environ["AUTO_PASS_KEEPASSXC_DB_PASSWORD"] == SECRET


def test_the_prompt_names_the_database_not_the_password(monkeypatch, tmp_path):
    asked = prompt_with(monkeypatch, SECRET)

    kp.seed_keepass_password_env_for_tty(config(tmp_path))

    assert asked == ["KeePassXC DB password for /vault/db.kdbx: "]


# --- context resolution -------------------------------------------------------------------


def test_no_password_and_no_way_to_ask_is_an_error_naming_the_variable(tmp_path):
    with pytest.raises(KeepassCommandError, match="AUTO_PASS_KEEPASSXC_DB_PASSWORD"):
        kp._resolve_context(config(tmp_path), allow_interactive=False)


def test_interactive_runs_may_proceed_without_a_password(tmp_path):
    context = kp._resolve_context(config(tmp_path), allow_interactive=True)
    assert context.db_password == ""
    assert context.interactive_allowed is True


def test_a_tty_counts_as_interactive(monkeypatch, tmp_path):
    monkeypatch.setattr(kp.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(kp, "seed_keepass_password_env_for_tty", lambda cfg: None)
    assert kp._resolve_context(config(tmp_path), allow_interactive=False).interactive_allowed


# --- running the tool ---------------------------------------------------------------------


def test_the_password_goes_to_stdin_never_the_command_line(runner, with_password, tmp_path):
    run = runner(done("v\n"))
    kp.resolve_keepassxc_entry("e", {"p": "pw"}, config=config(tmp_path), notify=False)

    cmd, kwargs = run.calls[0]
    assert SECRET not in " ".join(cmd)
    assert kwargs["input"] == SECRET + "\n"


def test_updating_a_password_without_a_known_master_password_is_refused(runner, tmp_path):
    run = runner()
    with pytest.raises(KeepassCommandError, match="requires the KeePass database password"):
        kp.upsert_keepassxc_entry(
            "g/e", password="new", allow_interactive=True, config=config(tmp_path)
        )
    assert run.calls == []


def test_without_a_stored_password_the_tool_prompts_on_the_terminal(runner, tmp_path):
    run = runner(done("v\n"))
    kp.resolve_keepassxc_entry(
        "e", {"p": "pw"}, config=config(tmp_path), notify=False, allow_interactive=True
    )

    _, kwargs = run.calls[0]
    assert "input" not in kwargs
    assert kwargs["stderr"] is None


def test_failures_report_the_exit_code_and_stderr_but_never_the_password(
    runner, with_password, tmp_path
):
    runner(done(stderr="Invalid credentials were provided\n", code=1))
    with pytest.raises(KeepassCommandError) as info:
        kp.resolve_keepassxc_entry("e", {"p": "pw"}, config=config(tmp_path), notify=False)

    message = str(info.value)
    assert "'e'" in message
    assert ": 1;" in message
    assert "Invalid credentials were provided" in message
    assert "password_env_present=True" in message
    assert "key_file_present=False" in message
    assert SECRET not in message


def test_a_failure_without_stderr_has_no_detail_suffix(runner, with_password, tmp_path):
    runner(done(code=2))
    with pytest.raises(KeepassCommandError) as info:
        kp.resolve_keepassxc_entry("e", {"p": "pw"}, config=config(tmp_path), notify=False)
    assert "stderr=" not in str(info.value)


def test_interactive_failures_are_labelled_as_such(runner, tmp_path):
    runner(done(code=1))
    with pytest.raises(KeepassCommandError, match="interactive_prompt"):
        kp.resolve_keepassxc_entry(
            "e", {"p": "pw"}, config=config(tmp_path), notify=False, allow_interactive=True
        )


# --- reading entries ----------------------------------------------------------------------


def test_entry_and_attributes_are_required(tmp_path):
    with pytest.raises(KeepassCommandError, match="entry is required"):
        kp.resolve_keepassxc_entry("  ", {"p": "pw"}, config=config(tmp_path))
    with pytest.raises(KeepassCommandError, match="non-empty mapping"):
        kp.resolve_keepassxc_entry("e", {}, config=config(tmp_path))
    with pytest.raises(KeepassCommandError, match="entry is required"):
        kp.resolve_keepassxc_entry_all_fields("", config=config(tmp_path))


def test_requested_attributes_are_deduplicated_and_mapped_back(runner, with_password, tmp_path):
    run = runner(done("alice\nhunter2\n"))

    got = kp.resolve_keepassxc_entry(
        "web/site",
        {"user": "user", "login": "UserName", "secret": "pw"},
        config=config(tmp_path, database_key_file="/k.key"),
        notify=False,
    )

    cmd, _ = run.calls[0]
    assert cmd == [
        "keepassxc-cli", "show", "-s", "-a", "UserName", "-a", "Password",
        "-k", "/k.key", "/vault/db.kdbx", "web/site",
    ]  # fmt: skip
    assert got == {"user": "alice", "login": "alice", "secret": "hunter2"}


def test_too_few_values_back_is_an_error(runner, with_password, tmp_path):
    runner(done("only-one\n"))
    with pytest.raises(KeepassCommandError, match="returned 1 attributes, expected 2"):
        kp.resolve_keepassxc_entry(
            "e", {"a": "user", "b": "pw"}, config=config(tmp_path), notify=False
        )


def test_a_notification_failure_does_not_lose_the_secret(
    runner, with_password, tmp_path, monkeypatch, caplog
):
    runner(done("hunter2\n"))

    def boom(**kwargs):
        raise kp.PasswordRetrievalNotificationError("channel down")

    monkeypatch.setattr(kp, "maybe_notify_password_retrieval", boom)

    got = kp.resolve_keepassxc_entry("e", {"p": "pw"}, config=config(tmp_path))

    assert got == {"p": "hunter2"}
    assert "channel down" in caplog.text
    assert "hunter2" not in caplog.text


def test_the_notification_reports_attributes_not_values(
    runner, with_password, tmp_path, monkeypatch
):
    runner(done("hunter2\n"))
    sent = {}
    monkeypatch.setattr(kp, "maybe_notify_password_retrieval", lambda **kw: sent.update(kw))

    kp.resolve_keepassxc_entry("e", {"p": "pw"}, config=config(tmp_path))

    assert sent["entry"] == "e"
    assert sent["requested_attributes"] == ["Password"]
    assert "hunter2" not in repr(sent)


def test_all_fields_parses_multiline_notes_and_skips_section_headers(
    runner, with_password, tmp_path
):
    runner(
        done(
            "Title: Site\n"
            "UserName: alice\n"
            "Password: hunter2\n"
            "Notes: first line\n"
            "  second line\n"
            "\n"
            "  third line\n"
            "Attributes:\n"
            "  stray continuation\n"
            ": no key\n"
            "Attachments:\n"
            "URL: https://x.test/a:b\n"
        )
    )

    fields = kp.resolve_keepassxc_entry_all_fields("e", config=config(tmp_path), notify=False)

    assert fields["Notes"] == "first line\nsecond line\nthird line"
    assert fields["URL"] == "https://x.test/a:b"
    assert "Attributes" not in fields
    assert "Attachments" not in fields
    assert "stray continuation" not in " ".join(fields.values())
    assert fields["Password"] == "hunter2"
    assert "" not in fields  # a line with no key is dropped, not stored under ""


def test_all_fields_only_notes_continue_onto_following_lines(runner, with_password, tmp_path):
    runner(done("Title: Site\n  looks like a continuation\nPassword: hunter2\n  so does this\n"))

    fields = kp.resolve_keepassxc_entry_all_fields("e", config=config(tmp_path), notify=False)

    assert fields == {"Title": "Site", "Password": "hunter2"}


def test_all_fields_notes_may_start_on_the_next_line(runner, with_password, tmp_path):
    runner(done("Notes:\nbody text\n"))
    fields = kp.resolve_keepassxc_entry_all_fields("e", config=config(tmp_path), notify=False)
    assert fields["Notes"] == "body text"


def test_all_fields_failure_and_key_file(runner, with_password, tmp_path):
    run = runner(done(stderr="nope", code=1))
    with pytest.raises(KeepassCommandError, match="nope"):
        kp.resolve_keepassxc_entry_all_fields(
            "e", config=config(tmp_path, database_key_file="/k.key"), notify=False
        )
    assert run.calls[0][0] == [
        "keepassxc-cli", "show", "--all", "-s", "-k", "/k.key", "/vault/db.kdbx", "e",
    ]  # fmt: skip


def test_all_fields_notification_failure_is_not_fatal(runner, with_password, tmp_path, monkeypatch):
    runner(done("Password: x\n"))

    def boom(**kwargs):
        raise kp.PasswordRetrievalNotificationError("down")

    monkeypatch.setattr(kp, "maybe_notify_password_retrieval", boom)

    assert kp.resolve_keepassxc_entry_all_fields("e", config=config(tmp_path)) == {"Password": "x"}


# --- the daemon's direct paths ------------------------------------------------------------


def test_validate_reports_whether_the_password_opens_the_database(runner):
    run = runner(done(code=0), done(code=1))

    assert kp.validate_keepassxc_database("/db.kdbx", "right", "/k.key") is True
    assert kp.validate_keepassxc_database("/db.kdbx", "wrong") is False

    first, second = run.calls
    assert first[0] == ["keepassxc-cli", "ls", "-k", "/k.key", "/db.kdbx"]
    assert second[0] == ["keepassxc-cli", "ls", "/db.kdbx"]
    assert first[1]["input"] == "right\n"
    assert first[1]["timeout"] == 30


@pytest.mark.parametrize(
    "failure", [OSError("no such tool"), subprocess.TimeoutExpired("keepassxc-cli", 30)]
)
def test_validate_is_false_when_the_tool_cannot_run_or_hangs(runner, failure):
    runner(failure)
    assert kp.validate_keepassxc_database("/db.kdbx", "pw") is False


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"entry": " "}, "entry is required"),
        ({"attrs": {}}, "non-empty mapping"),
        ({"db_path": ""}, "db_path is required"),
        ({"db_password": ""}, "db_password is required"),
    ],
)
def test_show_direct_refuses_incomplete_requests(runner, kwargs, message):
    run = runner()
    args = {"entry": "e", "attrs": {"p": "pw"}, "db_path": "/db.kdbx", "db_password": "pw"}
    args.update(kwargs)

    with pytest.raises(KeepassCommandError, match=message):
        kp.run_keepassxc_show_direct(
            args["entry"],
            args["attrs"],
            db_path=args["db_path"],
            db_password=args["db_password"],
        )
    assert run.calls == []


def test_show_direct_uses_only_the_credentials_it_is_given(runner, monkeypatch):
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_DB_PASSWORD", "ambient-must-not-be-used")
    run = runner(done("alice\nhunter2\n"))

    got = kp.run_keepassxc_show_direct(
        "web/site",
        {"u": "user", "p": "pw"},
        db_path="/sub.kdbx",
        db_password="sub-pw",
        key_file="/sub.key",
    )

    cmd, kwargs = run.calls[0]
    assert cmd == [
        "keepassxc-cli", "show", "-s", "-a", "UserName", "-a", "Password",
        "-k", "/sub.key", "/sub.kdbx", "web/site",
    ]  # fmt: skip
    assert kwargs["input"] == "sub-pw\n"
    assert got == {"u": "alice", "p": "hunter2"}


def test_show_direct_failure_and_short_output(runner):
    runner(done(stderr="bad", code=1), done("one\n"))
    with pytest.raises(KeepassCommandError, match="bad") as info:
        kp.run_keepassxc_show_direct("e", {"p": "pw"}, db_path="/d", db_password="sub-pw")
    assert "sub-pw" not in str(info.value)
    with pytest.raises(KeepassCommandError, match="returned 1 attributes, expected 2"):
        kp.run_keepassxc_show_direct(
            "e", {"a": "user", "b": "pw"}, db_path="/d", db_password="sub-pw"
        )


# --- writing ------------------------------------------------------------------------------


def test_entry_parent_group():
    assert kp._entry_parent_group("a/b/c") == "a/b"
    assert kp._entry_parent_group("/a/b/") == "a"
    assert kp._entry_parent_group("solo") == ""
    assert kp._entry_parent_group("//") == ""


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        ("Could not find entry with path x", True),
        (RuntimeError("Entry NOT FOUND"), True),
        ("no entry here", True),
        ("Invalid credentials", False),
        ("", False),
    ],
)
def test_not_found_detection(error, expected):
    assert kp.is_keepass_entry_not_found_error(error) is expected


def test_ensure_group_creates_reports_existing_and_raises_on_other_errors(
    runner, with_password, tmp_path
):
    run = runner(done(), done(stderr="Group Already Exists", code=1), done(stderr="locked", code=1))
    cfg = config(tmp_path, database_key_file="/k.key")

    assert kp.ensure_group("/a/b/", config=cfg) is True
    assert kp.ensure_group("a/b", config=cfg) is False
    with pytest.raises(KeepassCommandError, match="locked"):
        kp.ensure_group("a/b", config=cfg)

    assert run.calls[0][0] == [
        "keepassxc-cli", "mkdir", "-q", "-k", "/k.key", "/vault/db.kdbx", "a/b",
    ]  # fmt: skip


def test_ensure_group_requires_a_name(tmp_path):
    with pytest.raises(KeepassCommandError, match="group path is required"):
        kp.ensure_group(" / ", config=config(tmp_path))


def test_upsert_requires_an_entry_and_something_to_change(tmp_path):
    with pytest.raises(KeepassCommandError, match="entry is required"):
        kp.upsert_keepassxc_entry(" ", username="u", config=config(tmp_path))
    with pytest.raises(KeepassCommandError, match="At least one"):
        kp.upsert_keepassxc_entry("g/e", config=config(tmp_path))


def test_upsert_edits_an_existing_entry_with_the_password_on_stdin(runner, with_password, tmp_path):
    run = runner(done())

    outcome = kp.upsert_keepassxc_entry(
        "g/e",
        username="alice",
        password="new-pw",
        url="https://x.test",
        notes="n",
        config=config(tmp_path, database_key_file="/k.key"),
    )

    cmd, kwargs = run.calls[0]
    assert outcome == "edit"
    assert cmd == [
        "keepassxc-cli", "edit", "-q", "-u", "alice", "--url", "https://x.test",
        "--notes", "n", "-p", "-k", "/k.key", "/vault/db.kdbx", "g/e",
    ]  # fmt: skip
    assert "new-pw" not in " ".join(cmd)
    assert kwargs["input"] == f"{SECRET}\nnew-pw\nnew-pw\n"


def test_upsert_adds_a_missing_entry_and_creates_its_group(runner, with_password, tmp_path):
    run = runner(
        done(stderr="Could not find entry", code=1),  # edit
        done(),  # mkdir
        done(),  # add
    )

    outcome = kp.upsert_keepassxc_entry("grp/sub/e", username="u", config=config(tmp_path))

    assert outcome == "add"
    verbs = [call[0][1] for call in run.calls]
    assert verbs == ["edit", "mkdir", "add"]
    assert run.calls[1][0][-1] == "grp/sub"


def test_upsert_can_skip_group_creation(runner, with_password, tmp_path):
    run = runner(done(stderr="not found", code=1), done())

    outcome = kp.upsert_keepassxc_entry(
        "grp/e", username="u", create_group=False, config=config(tmp_path)
    )

    assert outcome == "add"
    assert [call[0][1] for call in run.calls] == ["edit", "add"]


def test_upsert_top_level_entry_needs_no_group(runner, with_password, tmp_path):
    run = runner(done(stderr="not found", code=1), done())

    kp.upsert_keepassxc_entry("solo", username="u", config=config(tmp_path))

    assert [call[0][1] for call in run.calls] == ["edit", "add"]


def test_upsert_reports_other_edit_errors_without_trying_to_add(runner, with_password, tmp_path):
    run = runner(done(stderr="Invalid credentials", code=1))
    with pytest.raises(KeepassCommandError, match="Invalid credentials"):
        kp.upsert_keepassxc_entry("g/e", username="u", config=config(tmp_path))
    assert len(run.calls) == 1


def test_upsert_reports_a_failed_add(runner, with_password, tmp_path):
    runner(done(stderr="not found", code=1), done(stderr="disk full", code=1))
    with pytest.raises(KeepassCommandError, match="disk full"):
        kp.upsert_keepassxc_entry("solo", username="u", config=config(tmp_path))


def test_remove_deletes_reports_missing_and_raises_on_other_errors(runner, with_password, tmp_path):
    run = runner(done(), done(stderr="No entry found", code=1), done(stderr="locked", code=1))
    cfg = config(tmp_path, database_key_file="/k.key")

    assert kp.remove_keepassxc_entry("g/e", config=cfg) is True
    assert kp.remove_keepassxc_entry("g/e", config=cfg) is False
    with pytest.raises(KeepassCommandError, match="locked"):
        kp.remove_keepassxc_entry("g/e", config=cfg)

    assert run.calls[0][0] == [
        "keepassxc-cli", "rm", "-q", "-k", "/k.key", "/vault/db.kdbx", "g/e",
    ]  # fmt: skip


def test_remove_requires_an_entry(tmp_path):
    with pytest.raises(KeepassCommandError, match="entry is required"):
        kp.remove_keepassxc_entry(" ", config=config(tmp_path))


def test_list_returns_trimmed_nonblank_lines(runner, with_password, tmp_path):
    run = runner(done("  a/one  \n\n b/two\n   \n"))

    got = kp.list_keepassxc_entries("grp", config=config(tmp_path, database_key_file="/k.key"))

    assert got == ["a/one", "b/two"]
    assert run.calls[0][0] == [
        "keepassxc-cli", "ls", "-q", "-R", "-f", "-k", "/k.key", "/vault/db.kdbx", "grp",
    ]  # fmt: skip


def test_list_flags_and_default_group(runner, with_password, tmp_path):
    run = runner(done(""))

    assert (
        kp.list_keepassxc_entries("", recursive=False, flatten=False, config=config(tmp_path)) == []
    )

    assert run.calls[0][0] == ["keepassxc-cli", "ls", "-q", "/vault/db.kdbx", "/"]


def test_list_failure_is_an_error(runner, with_password, tmp_path):
    runner(done(stderr="locked", code=1))
    with pytest.raises(KeepassCommandError, match="locked"):
        kp.list_keepassxc_entries(config=config(tmp_path))
