from __future__ import annotations

import argparse
import json
import os
import sys
from getpass import getpass
from pathlib import Path

from .envfile import (
    DEFAULT_ENV_FILE,
    activate_keepass_profile,
    apply_keepass_profile_environment,
    get_active_keepass_profile,
    list_keepass_profiles,
    load_config_environment,
)
from .keepassxc import (
    ensure_group,
    resolve_keepassxc_entry,
    resolve_keepassxc_entry_all_fields,
    upsert_keepassxc_entry,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto-pass",
        description="Automate common KeePassXC-backed password store operations.",
    )
    parser.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_FILE),
        help=(f"Local env file to load before running commands. Defaults to {DEFAULT_ENV_FILE}."),
    )
    parser.add_argument(
        "--no-env-file",
        action="store_true",
        help="Do not load the local env file before running commands.",
    )
    parser.add_argument(
        "--profile",
        help=(
            "Override AUTO_PASS_PROFILE for this command. The value is normalized "
            "the same way as profile names in the env file."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    get_parser = subparsers.add_parser(
        "get",
        help="Read one or more fields from a KeePassXC entry.",
    )
    get_parser.add_argument("entry", help="KeePass entry path, for example web/github")
    get_parser.add_argument(
        "--field",
        action="append",
        default=[],
        help="Field name or alias. Defaults to username and password.",
    )
    get_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON object instead of key=value lines.",
    )
    get_parser.add_argument(
        "--allow-interactive",
        action="store_true",
        help="Allow prompting for the KeePass database password when possible.",
    )

    get_all_parser = subparsers.add_parser(
        "get-all",
        help="Read all fields from a KeePassXC entry.",
    )
    get_all_parser.add_argument(
        "entry",
        help="KeePass entry path, for example web/github",
    )
    get_all_parser.add_argument(
        "--allow-interactive",
        action="store_true",
        help="Allow prompting for the KeePass database password when possible.",
    )

    set_parser = subparsers.add_parser(
        "set",
        help="Create or update a KeePassXC entry.",
    )
    set_parser.add_argument("entry", help="KeePass entry path, for example web/github")
    set_parser.add_argument("--username", help="UserName value to store.")
    set_parser.add_argument("--password", help="Password value to store.")
    set_parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password value from stdin.",
    )
    set_parser.add_argument("--url", help="URL value to store.")
    set_parser.add_argument("--notes", help="Notes value to store.")
    set_parser.add_argument(
        "--notes-file",
        help="Read notes content from a file.",
    )
    set_parser.add_argument(
        "--no-create-group",
        action="store_true",
        help="Do not create the parent group path before adding a missing entry.",
    )
    set_parser.add_argument(
        "--allow-interactive",
        action="store_true",
        help="Allow prompting for the KeePass database password when possible.",
    )

    mkdir_parser = subparsers.add_parser(
        "mkdir",
        help="Ensure a KeePassXC group path exists.",
    )
    mkdir_parser.add_argument("group", help="Group path, for example web or infra/github")
    mkdir_parser.add_argument(
        "--allow-interactive",
        action="store_true",
        help="Allow prompting for the KeePass database password when possible.",
    )

    list_profiles_parser = subparsers.add_parser(
        "list-profiles",
        help="List configured KeePass profiles from the current env context.",
    )
    list_profiles_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON object with the active profile and available profiles.",
    )

    # ------------------------------------------------------------------
    # Provisioning service commands
    # ------------------------------------------------------------------

    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the provisioning daemon (Unix socket server).",
    )
    serve_parser.add_argument(
        "--db-path",
        help="Master KeePassXC database path. Overrides db-index lookup and AUTO_PASS_KEEPASSXC_DB_PATH.",
    )
    serve_parser.add_argument(
        "--key-file",
        help="Master KeePassXC key file path. Defaults to AUTO_PASS_KEEPASSXC_KEY_FILE.",
    )
    serve_parser.add_argument(
        "--db-index",
        help=(
            "Path to keepass-dbs.local.json. Defaults to AUTO_PASS_DB_INDEX_PATH "
            "or config/keepass-dbs.local.json."
        ),
    )
    serve_parser.add_argument(
        "--master-alias",
        default="master",
        help="DB alias for the master vault in the db index. Default: master.",
    )
    serve_parser.add_argument(
        "--allowlist",
        help=(
            "Allowlist TOML file path. Defaults to AUTO_PASS_PROVISIONING_ALLOWLIST "
            "or config/provisioning-allowlist.local.toml."
        ),
    )
    serve_parser.add_argument(
        "--socket",
        help=(
            "Unix socket path. Defaults to AUTO_PASS_PROVISIONING_SOCKET "
            "or ~/.cache/auto-pass/provisioning.sock."
        ),
    )

    unlock_parser = subparsers.add_parser(
        "unlock",
        help="Unlock the running provisioning daemon.",
    )
    unlock_parser.add_argument(
        "--socket",
        help="Unix socket path for the daemon.",
    )
    unlock_parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the database password from stdin instead of prompting.",
    )

    lock_parser = subparsers.add_parser(
        "lock",
        help="Lock the running provisioning daemon (clears the in-memory password).",
    )
    lock_parser.add_argument(
        "--socket",
        help="Unix socket path for the daemon.",
    )

    daemon_status_parser = subparsers.add_parser(
        "daemon-status",
        help="Show the provisioning daemon status.",
    )
    daemon_status_parser.add_argument(
        "--socket",
        help="Unix socket path for the daemon.",
    )
    daemon_status_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON.",
    )

    provision_get_parser = subparsers.add_parser(
        "provision-get",
        help="Retrieve a credential via the provisioning daemon (for testing / scripting).",
    )
    provision_get_parser.add_argument("entry", help="KeePassXC entry path.")
    provision_get_parser.add_argument(
        "--field",
        default="password",
        help="Field name or alias. Defaults to password.",
    )
    provision_get_parser.add_argument(
        "--db",
        help="DB alias (e.g. master, infra). Required for multi-vault repos.",
    )
    provision_get_parser.add_argument(
        "--socket",
        help="Unix socket path for the daemon.",
    )

    subparsers.add_parser(
        "notify-summary",
        help=(
            "Send a daily summary of logged password retrievals and clear the log. "
            "Requires AUTO_PASS_NOTIFY_DAILY_SUMMARY=1 and a configured recipient."
        ),
    )

    web_parser = subparsers.add_parser(
        "web",
        help="Start the web UI (requires: pip install 'auto-pass[web]').",
    )
    web_parser.add_argument("--host", default="127.0.0.1", help="Bind host. Default: 127.0.0.1.")
    web_parser.add_argument("--port", type=int, default=8080, help="Bind port. Default: 8080.")

    return parser


def _read_password_from_stdin() -> str:
    return sys.stdin.read().rstrip("\n")


def _read_notes(args: argparse.Namespace) -> str | None:
    if args.notes_file:
        return Path(args.notes_file).read_text(encoding="utf-8")
    if args.notes is not None:
        return args.notes
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.no_env_file:
        load_config_environment(args.env_file, profile=args.profile)
    elif args.profile:
        activate_keepass_profile(args.profile)
        apply_keepass_profile_environment()

    if args.command == "get":
        field_names = args.field or ["username", "password"]
        attrs_map = {name: name for name in field_names}
        resolved = resolve_keepassxc_entry(
            entry=args.entry,
            attrs_map=attrs_map,
            allow_interactive=args.allow_interactive,
        )
        if args.json:
            print(json.dumps(resolved, indent=2, sort_keys=True))
            return 0
        if len(resolved) == 1:
            print(next(iter(resolved.values())))
            return 0
        for key, value in resolved.items():
            print(f"{key}={value}")
        return 0

    if args.command == "get-all":
        resolved = resolve_keepassxc_entry_all_fields(
            entry=args.entry,
            allow_interactive=args.allow_interactive,
        )
        print(json.dumps(resolved, indent=2, sort_keys=True))
        return 0

    if args.command == "set":
        password = _read_password_from_stdin() if args.password_stdin else args.password
        notes = _read_notes(args)
        mode = upsert_keepassxc_entry(
            entry=args.entry,
            username=args.username,
            password=password,
            url=args.url,
            notes=notes,
            create_group=not args.no_create_group,
            allow_interactive=args.allow_interactive,
        )
        print(mode)
        return 0

    if args.command == "mkdir":
        created = ensure_group(
            args.group,
            allow_interactive=args.allow_interactive,
        )
        print("created" if created else "exists")
        return 0

    if args.command == "list-profiles":
        active_profile = get_active_keepass_profile()
        profiles = list_keepass_profiles()
        if args.json:
            print(
                json.dumps(
                    {"active_profile": active_profile, "profiles": profiles},
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        for profile in profiles:
            prefix = "* " if profile == active_profile else "  "
            print(f"{prefix}{profile}")
        return 0

    if args.command == "serve":
        return _cmd_serve(args)

    if args.command == "unlock":
        return _cmd_unlock(args)

    if args.command == "lock":
        return _cmd_lock(args)

    if args.command == "daemon-status":
        return _cmd_daemon_status(args)

    if args.command == "provision-get":
        return _cmd_provision_get(args)

    if args.command == "notify-summary":
        return _cmd_notify_summary(args)

    if args.command == "web":
        return _cmd_web(args)

    raise AssertionError(f"Unhandled command: {args.command}")


# ------------------------------------------------------------------
# Provisioning command implementations
# ------------------------------------------------------------------


def _provision_client(args: argparse.Namespace):
    from .client import ProvisioningClient
    from .server import default_socket_path

    socket_path = Path(args.socket) if getattr(args, "socket", None) else default_socket_path()
    return ProvisioningClient(socket_path=socket_path)


def _cmd_serve(args: argparse.Namespace) -> int:
    import logging

    from .allowlist import default_allowlist_path
    from .dbindex import DatabaseIndexError, resolve_database_alias
    from .server import ProvisioningServer, default_socket_path

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    db_index_path = Path(args.db_index) if getattr(args, "db_index", None) else None
    master_alias = (getattr(args, "master_alias", None) or "master").strip() or "master"

    db_path = (getattr(args, "db_path", None) or "").strip() or os.environ.get(
        "AUTO_PASS_KEEPASSXC_DB_PATH", ""
    )
    if not db_path:
        try:
            entry = resolve_database_alias(master_alias, db_index_path)
            db_path = str(entry.get("database_path", "")).strip()
        except DatabaseIndexError:
            pass

    if not db_path:
        print(
            "error: master database path not set — use --db-path, "
            "export AUTO_PASS_KEEPASSXC_DB_PATH, or add the master alias to keepass-dbs.local.json",
            file=sys.stderr,
        )
        return 1

    key_file = (getattr(args, "key_file", None) or "").strip() or os.environ.get(
        "AUTO_PASS_KEEPASSXC_KEY_FILE", ""
    )
    allowlist_path = Path(args.allowlist) if args.allowlist else default_allowlist_path()
    socket_path = Path(args.socket) if args.socket else default_socket_path()

    if not allowlist_path.exists():
        print(
            f"warning: allowlist not found at {allowlist_path} — all credential requests will be denied",
            file=sys.stderr,
        )

    server = ProvisioningServer(
        master_db_path=db_path,
        master_key_file=key_file,
        master_db_alias=master_alias,
        allowlist_path=allowlist_path,
        socket_path=socket_path,
        db_index_path=db_index_path,
    )
    server.serve()
    return 0


def _cmd_unlock(args: argparse.Namespace) -> int:
    from .client import ProvisioningClientError

    client = _provision_client(args)
    if not client.is_running():
        print("error: provisioning daemon is not running", file=sys.stderr)
        return 1

    if getattr(args, "password_stdin", False):
        password = _read_password_from_stdin()
    else:
        try:
            password = getpass("KeePassXC database password: ")
        except (EOFError, KeyboardInterrupt):
            print("", file=sys.stderr)
            return 1

    if not password:
        print("error: password is required", file=sys.stderr)
        return 1

    try:
        client.unlock(password)
        print("unlocked")
        return 0
    except ProvisioningClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _cmd_lock(args: argparse.Namespace) -> int:
    from .client import ProvisioningClientError

    client = _provision_client(args)
    try:
        client.lock()
        print("locked")
        return 0
    except (OSError, ProvisioningClientError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _cmd_daemon_status(args: argparse.Namespace) -> int:
    from .client import ProvisioningClientError

    client = _provision_client(args)
    try:
        result = client.status()
    except OSError:
        result = {"ok": False, "running": False, "locked": True}
    except ProvisioningClientError as exc:
        result = {"ok": False, "error": str(exc)}

    running = result.get("ok", False)
    locked = result.get("locked", True)

    if getattr(args, "json", False):
        print(json.dumps({"running": running, "locked": locked}, indent=2))
        return 0

    if not running:
        print("daemon: not running")
    else:
        print(f"daemon: running  locked: {locked}")
    return 0


def _cmd_web(args: argparse.Namespace) -> int:
    try:
        import uvicorn
        from .web.app import app
    except ImportError:
        print(
            "error: web dependencies not installed. Run: pip install 'auto-pass[web]'",
            file=sys.stderr,
        )
        return 1

    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if not os.environ.get("AUTO_PASS_WEB_TOKEN", "").strip():
        from .client import ProvisioningClient, ProvisioningClientError

        try:
            token = ProvisioningClient().get("auto-pass/web-token", db="infra")
            if not token:
                raise RuntimeError("daemon returned empty web token from infra vault")
            os.environ["AUTO_PASS_WEB_TOKEN"] = token
        except (OSError, ProvisioningClientError) as exc:
            print(
                f"error: AUTO_PASS_WEB_TOKEN is not set and daemon is unavailable: {exc}",
                file=sys.stderr,
            )
            print(
                "  Set AUTO_PASS_WEB_TOKEN in your env, or start and unlock the provisioning daemon.",
                file=sys.stderr,
            )
            return 1
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    from .web.auth import get_configured_token

    try:
        get_configured_token()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"auto-pass web UI on http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def _cmd_notify_summary(args: argparse.Namespace) -> int:  # noqa: ARG001
    from .notifications import PasswordRetrievalNotificationError, send_daily_summary

    try:
        count = send_daily_summary()
    except PasswordRetrievalNotificationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if count > 0:
        print(f"Sent summary of {count} retrieval(s).")
    return 0


def _cmd_provision_get(args: argparse.Namespace) -> int:
    from .client import ProvisioningClientError

    client = _provision_client(args)
    db = getattr(args, "db", None) or None
    try:
        value = client.get(args.entry, field=args.field, db=db)
        print(value)
        return 0
    except (OSError, ProvisioningClientError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
