"""Real interpreter and filesystem regressions for credential storage."""
import os
import stat
import tempfile
from unittest.mock import patch

import subprocess
import sys
import unittest
from pathlib import Path


class StoreImportTests(unittest.TestCase):
    def test_store_imports_in_a_fresh_interpreter(self):
        result = subprocess.run(
            [sys.executable, "-c", "from panel.store import AccountStore; assert callable(AccountStore.list_enabled)"],
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(os.name == "posix", "POSIX permission bits")
class StorePermissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o755)
        old_umask = os.umask(0o022)
        self.addCleanup(os.umask, old_umask)

    def test_new_sqlite_sidecars_inherit_private_database_mode(self):
        from panel.store import AccountStore

        path = self.root / "accounts.db"
        store = AccountStore(path)
        with store._conn() as conn:
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("INSERT INTO accounts(name, base_url, created_at, updated_at) VALUES ('a', 'https://a.test', '', '')")
            journal = Path(str(path) + "-journal")
            self.assertTrue(journal.exists())
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
        with store._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("UPDATE accounts SET password='secret'")
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(path) + suffix)
                self.assertTrue(sidecar.exists())
                self.assertEqual(stat.S_IMODE(sidecar.stat().st_mode), 0o600)

    def test_existing_backup_is_tightened_without_overwriting(self):
        from panel.store import AccountStore

        path = self.root / "accounts.db"
        AccountStore(path)
        backup = path.with_suffix(".v1.bak")
        backup.write_bytes(b"existing-backup")
        backup.chmod(0o644)
        AccountStore(path)
        self.assertEqual(backup.read_bytes(), b"existing-backup")
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_legacy_backup_is_private_during_its_first_write(self):
        from panel.store import AccountStore
        from panel.tests.test_store import _V1_SCHEMA
        import builtins
        import sqlite3

        path = self.root / "accounts.db"
        with sqlite3.connect(path) as conn:
            conn.executescript(_V1_SCHEMA)
            conn.execute("INSERT INTO accounts(name, provider, password) VALUES ('old', 'anyrouter', 'secret')")
        backup = path.with_suffix(".v1.bak")
        real_open = builtins.open
        observed = []

        def observe(file, mode="r", *args, **kwargs):
            handle = real_open(file, mode, *args, **kwargs)
            if "w" in mode and (file == backup or isinstance(file, int)):
                observed.append(stat.S_IMODE(os.fstat(handle.fileno()).st_mode))
                self.assertEqual(observed[-1], 0o600)
            return handle

        with patch("builtins.open", side_effect=observe):
            AccountStore(path)
        self.assertTrue(observed, "observe real destination before first copy write")
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        with sqlite3.connect(backup) as conn:
            self.assertEqual(conn.execute("SELECT password FROM accounts").fetchone()[0], "secret")

    def test_existing_wal_files_are_private_before_sqlite_reopens(self):
        from panel.store import AccountStore
        import sqlite3

        path = self.root / "accounts.db"
        store = AccountStore(path)
        writer = sqlite3.connect(path)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE wal_probe (secret TEXT)")
        writer.commit()
        files = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
        for file in files:
            self.assertTrue(file.exists())
            file.chmod(0o644)
        connect = sqlite3.connect

        def observe(database, *args, **kwargs):
            for file in files:
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600, str(file))
            return connect(database, *args, **kwargs)

        with patch("panel.store.sqlite3.connect", side_effect=observe):
            self.assertEqual(store.list(), [])
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)

    def test_new_parent_directories_are_private(self):
        from panel.store import AccountStore

        path = self.root / "new" / "nested" / "accounts.db"
        AccountStore(path)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)

    def test_database_is_private_before_sqlite_opens_it(self):
        from panel.store import AccountStore
        import sqlite3

        path = self.root / "accounts.db"
        connect = sqlite3.connect

        def observe(database, *args, **kwargs):
            self.assertTrue(Path(database).exists(), "precreate DB before SQLite can write secrets")
            self.assertEqual(stat.S_IMODE(Path(database).stat().st_mode), 0o600)
            return connect(database, *args, **kwargs)

        with patch("panel.store.sqlite3.connect", side_effect=observe):
            store = AccountStore(path)
            store.create(name="private", base_url="https://example.test", password="secret")
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)
        self.assertEqual(store.get(1).password, "secret")
