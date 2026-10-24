"""Tests for the webshell registry."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from shellshock.manager import registry


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "registry.json"

    def _registry(self) -> registry.Registry:
        store = registry.Registry(self.path)
        store.load()
        return store

    def _seed(self, store: registry.Registry) -> None:
        store.upsert(
            url="http://x/a.php",
            vector="cookie",
            mode="plain",
            has_secret=False,
            name="Alpha",
            now="2026-01-01T00:00:00+00:00",
        )
        store.upsert(
            url="http://x/b.php",
            vector="post",
            mode="auth",
            has_secret=True,
            name="beta",
            now="2026-01-02T00:00:00+00:00",
        )
        store.upsert(
            url="http://x/c.php",
            vector="header",
            mode="encrypted",
            has_secret=True,
            now="2026-01-03T00:00:00+00:00",
        )

    def test_missing_file_is_empty(self):
        self.assertEqual(self._registry().all(), [])

    def test_upsert_creates_record(self):
        record = self._registry().upsert(
            url="http://x/1.php",
            vector="cookie",
            mode="plain",
            has_secret=False,
            now="2026-01-01T00:00:00+00:00",
        )
        self.assertTrue(record.id)
        self.assertFalse(record.has_secret)
        self.assertEqual(record.created_at, "2026-01-01T00:00:00+00:00")
        self.assertEqual(record.last_used, "2026-01-01T00:00:00+00:00")

    def test_upsert_by_url_preserves_id_and_created_at(self):
        store = self._registry()
        first = store.upsert(
            url="http://x/1.php",
            vector="cookie",
            mode="plain",
            has_secret=False,
            name="one",
            now="2026-01-01T00:00:00+00:00",
        )
        second = store.upsert(
            url="http://x/1.php",
            vector="post",
            mode="auth",
            has_secret=True,
            now="2026-01-02T00:00:00+00:00",
        )
        self.assertEqual(first.id, second.id)
        self.assertEqual(second.created_at, "2026-01-01T00:00:00+00:00")
        self.assertEqual(second.last_used, "2026-01-02T00:00:00+00:00")
        self.assertEqual(second.vector, "post")
        self.assertEqual(second.mode, "auth")
        self.assertTrue(second.has_secret)
        self.assertEqual(second.name, "one")  # preserved when omitted
        self.assertEqual(len(store.all()), 1)

    def test_upsert_updates_name_when_provided(self):
        store = self._registry()
        store.upsert(
            url="http://x/1.php",
            vector="cookie",
            mode="plain",
            has_secret=False,
            name="one",
            now="2026-01-01T00:00:00+00:00",
        )
        updated = store.upsert(
            url="http://x/1.php",
            vector="cookie",
            mode="plain",
            has_secret=False,
            name="two",
            now="2026-01-02T00:00:00+00:00",
        )
        self.assertEqual(updated.name, "two")

    def test_save_and_load_round_trip(self):
        store = self._registry()
        self._seed(store)
        store.save()

        other = registry.Registry(self.path)
        other.load()
        self.assertEqual(other.all(), store.all())

        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(raw["version"], registry.REGISTRY_VERSION)
        self.assertEqual(len(raw["shells"]), 3)

    def test_corrupt_registry_raises(self):
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(registry.RegistryError):
            self._registry()

    def test_newer_version_raises(self):
        self.path.write_text(
            json.dumps({"version": 99, "shells": []}), encoding="utf-8"
        )
        with self.assertRaises(registry.RegistryError):
            self._registry()

    def test_query_default_last_used_desc(self):
        store = self._registry()
        self._seed(store)
        self.assertEqual(
            [record.url for record in store.query()],
            ["http://x/c.php", "http://x/b.php", "http://x/a.php"],
        )

    def test_query_order_name_asc(self):
        store = self._registry()
        self._seed(store)
        self.assertEqual(
            [record.url for record in store.query(order="name", descending=False)],
            ["http://x/a.php", "http://x/b.php", "http://x/c.php"],
        )

    def test_query_filters(self):
        store = self._registry()
        self._seed(store)
        self.assertEqual(
            [record.url for record in store.query(filters=("mode == auth",))],
            ["http://x/b.php"],
        )
        self.assertEqual(
            [record.url for record in store.query(filters=("name contains alp",))],
            ["http://x/a.php"],
        )
        self.assertEqual(len(store.query(filters=("has_secret == true",))), 2)
        self.assertEqual(
            [
                record.url
                for record in store.query(
                    filters=("has_secret == true", "vector != post")
                )
            ],
            ["http://x/c.php"],
        )

    def test_query_rejects_bad_input(self):
        store = self._registry()
        self._seed(store)
        for bad in ("nope", "url ~ x", "bogus == x"):
            with self.assertRaises(registry.RegistryError):
                store.query(filters=(bad,))
        with self.assertRaises(registry.RegistryError):
            store.query(order="bogus")

    def test_get(self):
        store = self._registry()
        self._seed(store)
        record = store.all()[0]
        self.assertEqual(store.get(record.id), record)
        self.assertIsNone(store.get("missing"))

    def test_update_name_preserves_timestamps(self):
        store = self._registry()
        self._seed(store)
        record = store.all()[0]
        updated = store.update(record.id, {"name": "Renamed"})
        self.assertEqual(updated.name, "Renamed")
        self.assertEqual(updated.id, record.id)
        self.assertEqual(updated.created_at, record.created_at)
        self.assertEqual(updated.last_used, record.last_used)

    def test_update_clear_name(self):
        store = self._registry()
        self._seed(store)
        record = store.all()[0]
        updated = store.update(record.id, {"name": None})
        self.assertIsNone(updated.name)

    def test_update_rejects_unknown_field(self):
        store = self._registry()
        self._seed(store)
        record = store.all()[0]
        with self.assertRaises(registry.RegistryError):
            store.update(record.id, {"url": "http://x"})

    def test_update_not_found(self):
        store = self._registry()
        with self.assertRaises(registry.RegistryError):
            store.update("missing", {"name": "x"})

    def test_delete(self):
        store = self._registry()
        self._seed(store)
        record = store.all()[0]
        deleted = store.delete(record.id)
        self.assertEqual(deleted.id, record.id)
        self.assertIsNone(store.get(record.id))
        self.assertEqual(len(store.all()), 2)

    def test_delete_not_found(self):
        store = self._registry()
        with self.assertRaises(registry.RegistryError):
            store.delete("missing")

    def test_update_and_delete_round_trip(self):
        store = self._registry()
        self._seed(store)
        store.update(store.all()[0].id, {"name": "Renamed"})
        store.delete(store.all()[1].id)
        store.save()

        other = registry.Registry(self.path)
        other.load()
        self.assertEqual(len(other.all()), 2)
        self.assertIn("Renamed", [record.name for record in other.all()])


if __name__ == "__main__":
    unittest.main()
