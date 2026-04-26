from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auto_pass.dbindex import (
    DatabaseIndexError,
    list_database_aliases,
    load_database_index,
    resolve_database_alias,
)


class DatabaseIndexTests(unittest.TestCase):
    def test_load_database_index_returns_empty_mapping_when_file_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "keepass-dbs.local.json"
            self.assertEqual(load_database_index(missing), {})

    def test_resolve_database_alias_normalizes_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "keepass-dbs.local.json"
            index_path.write_text(
                json.dumps(
                    {
                        "databases": {
                            "Finance": {
                                "database_path": "/vaults/finance.kdbx",
                                "database_password_source": {
                                    "database_alias": "master",
                                    "entry": "vaults/finance.kdbx",
                                },
                            },
                            "master": {"database_path": "/vaults/master.kdbx"},
                        }
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            finance = resolve_database_alias(" finance ", index_path)
            aliases = list_database_aliases(index_path)

        self.assertEqual(finance["database_path"], "/vaults/finance.kdbx")
        self.assertEqual(finance["database_password_source"]["database_alias"], "master")
        self.assertEqual(aliases, ["finance", "master"])

    def test_load_database_index_rejects_non_object_database_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "keepass-dbs.local.json"
            index_path.write_text(
                json.dumps({"databases": {"finance": "/vaults/finance.kdbx"}}) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(DatabaseIndexError):
                load_database_index(index_path)
