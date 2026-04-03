from __future__ import annotations

import argparse
import json
import sys
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

    raise AssertionError(f"Unhandled command: {args.command}")
