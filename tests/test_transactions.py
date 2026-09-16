import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from helpers import FakeServices, PortableStore, bundle, populate
from ruavc import backup, doctor, model
from ruavc.errors import Error
from ruavc.storage import encoded, read_json, write
from ruavc.transaction import Transaction


class Transactions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = PortableStore(Path(self.temp.name))
        self.bundle = populate(self.store, bundle())
        self.services = FakeServices(self.store)
        self.tx = Transaction(self.store, self.services)
        self.first = self.tx.apply(self.bundle, "install")

    def test_commit_publishes_sources_and_artifacts_together(self):
        change = self.store.load()
        change["config"]["routing"]["direct"] = False
        second = self.tx.apply(change, "direct off")
        self.assertNotEqual(second, self.first)
        active = self.store.load()
        self.assertFalse(active["config"]["routing"]["direct"])
        device = active["devices"][0]
        profile = read_json(self.store.generation(second) / "web/routing" / (device["token"] + ".json"), private=False)
        self.assertNotIn("geoip:ru", profile["DirectIp"])
        self.assertFalse(self.store.pending.exists())
        self.assertTrue(list(self.store.backups.glob("*.json")))

    def test_validation_restart_and_health_failures_restore_every_document(self):
        for phase in ("validate", "restart", "health"):
            with self.subTest(phase=phase):
                before = self.store.load()
                change = copy.deepcopy(before)
                change["devices"].append(model.new_device("new"))
                self.services.failure = phase
                with self.assertRaises(Error):
                    self.tx.apply(change, "test")
                self.assertEqual(self.store.active_name(), self.first)
                self.assertEqual(self.store.load(), before)
                self.assertFalse(self.store.pending.exists())

    def test_first_install_health_failure_removes_pointer(self):
        other = PortableStore(Path(self.temp.name) / "fresh")
        b = populate(other, bundle())
        service = FakeServices(other)
        service.failure = "health"
        with self.assertRaises(Error):
            Transaction(other, service).apply(b, "install")
        self.assertIsNone(other.active_name())
        self.assertEqual(service.stops, 1)

    def test_recovery_after_crash_between_pointer_and_commit(self):
        change = self.store.load()
        change["devices"] = []
        candidate = self.tx.prepare(change)
        write(self.store.pending, encoded({"previous": self.first, "candidate": candidate, "reason": "revoke"}))
        self.store.activate(candidate)
        self.assertTrue(self.tx.recover())
        self.assertEqual(self.store.active_name(), self.first)
        self.assertEqual(len(self.store.load()["devices"]), 1)

    def test_boot_recovery_does_not_start_services(self):
        write(self.store.pending, encoded({"previous": self.first, "candidate": self.first, "reason": "test"}))
        restarts = self.services.restarts
        self.tx.recover(boot=True)
        self.assertEqual(self.services.restarts, restarts)

    def test_failed_recovery_keeps_durable_journal(self):
        write(self.store.pending, encoded({"previous": self.first, "candidate": self.first, "reason": "test"}))
        self.services.failure = "restart"
        with self.assertRaises(Error):
            self.tx.recover()
        self.assertTrue(self.store.pending.exists())

    def test_reissue_rotates_both_credentials_and_checks_revocation(self):
        before = self.store.load()
        old = before["devices"][0].copy()
        before["devices"][0].update(model.new_device(old["name"]))
        self.tx.apply(before, "reissue")
        new = self.store.load()["devices"][0]
        self.assertNotEqual(old["uuid"], new["uuid"])
        self.assertNotEqual(old["token"], new["token"])
        self.assertIn(old["token"], self.services.revoked)
        self.assertFalse((self.store.generation(self.store.active_name()) / "web/sub" / old["token"]).exists())

    def test_rollback_increases_incy_revision(self):
        changed = self.store.load()
        changed["config"]["server"]["country"] = "FI"
        self.tx.apply(changed, "country")
        revision = self.store.load()["release"]["routing_revision"]
        self.tx.rollback()
        after = self.store.load()
        self.assertEqual(after["config"]["server"]["country"], "DE")
        self.assertGreater(after["release"]["routing_revision"], revision)

    def test_component_update_preserves_identity_and_settings(self):
        before = self.store.load()
        self.tx.apply(copy.deepcopy(before), "update ruavc")
        after = self.store.load()
        for key in ("devices", "secrets", "sites", "config"):
            self.assertEqual(before[key], after[key])

    def test_status_never_contains_credentials(self):
        b = self.store.load()
        text = json.dumps(doctor.status(self.store, self.services))
        for d in b["devices"]:
            self.assertNotIn(d["uuid"], text)
            self.assertNotIn(d["token"], text)
        for value in b["secrets"].values():
            self.assertNotIn(value, text)

    def test_tampering_prevents_mutation(self):
        path = self.store.generation(self.first) / "generated/xray.json"
        write(path, "{}")
        with self.assertRaises(Error):
            self.tx.apply(self.bundle, "test")
        self.assertEqual(self.store.active_name(), self.first)

    def test_portable_backup_restore(self):
        name = backup.create(self.store)
        before = self.store.load()
        changed = copy.deepcopy(before)
        changed["devices"] = []
        self.tx.apply(changed, "revoke")
        with patch("ruavc.install.certificate"):
            backup.restore(self.store, name, self.tx)
        self.assertEqual(self.store.load()["devices"], before["devices"])

    def test_backup_path_traversal_rejected(self):
        with self.assertRaises(Error):
            backup.restore(self.store, "../../etc/passwd", self.tx)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink/permission test")
    def test_symlink_and_world_readable_secret_rejected(self):
        path = self.store.generation(self.first) / "secrets.json"
        path.chmod(0o644)
        with self.assertRaises(Error):
            self.store.load()
        path.chmod(0o600)
        target = path.with_name("saved.json")
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(Error):
            self.store.load()

    @unittest.skipUnless(os.name == "posix", "POSIX lock test")
    def test_overlapping_mutations_are_rejected(self):
        with self.store.lock():
            with self.assertRaises(Error) as failure:
                with self.store.lock():
                    pass
        self.assertEqual(failure.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
