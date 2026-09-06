#!/usr/bin/env python3
"""Tests for source selection and the private-to-public export boundary."""
import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sync", ROOT / "sync-records.py")
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)

class SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads((ROOT / "advisory-sources.json").read_text())
        cls.config = json.loads((ROOT / "readme-data.json").read_text())
        cls.records = {r["ghsa"]: r for r in cls.snapshot["advisories"]}

    def test_export_boundary(self):
        raw = copy.deepcopy(next(iter(self.records.values()))["repository"])
        raw.update(private_fork={"secret": True}, collaborators=["private"], internal_note="secret")
        clean = sync.public_repository(raw)
        self.assertNotIn("private_fork", clean)
        self.assertNotIn("collaborators", clean)
        self.assertNotIn("internal_note", clean)
        for state in ("draft", "triage", "closed", None):
            raw["state"] = state
            with self.assertRaises(ValueError):
                sync.public_repository(raw)

    def test_repository_dates_and_severity(self):
        rows = sync.csv_rows(self.snapshot, self.config)
        for row in rows:
            source = self.records[row["ghsa"]]
            self.assertEqual(row["published"], source["repository"]["published"][:10])
            self.assertEqual(row["severity"], source["repository"]["severity"])
            self.assertEqual(row["globally_indexed"] == "yes", source["global"]["status"] == "found")
            self.assertNotIn("sole_reporter", row)

    def test_v4_and_missing_scores(self):
        flowise = self.records["GHSA-9cvr-5wv9-2gxr"]
        self.assertEqual(sync.primary_score(flowise)["version"], "4.0")
        self.assertEqual(sync.primary_score(flowise)["score"], 7.6)
        empty = {"repository": {}, "global": {}, "cve": {}}
        self.assertEqual(sync.primary_score(empty)["score"], "")

    def test_source_disagreement_is_preserved(self):
        row = self.records["GHSA-p3hw-mv63-rf9w"]
        repo = row["repository"]["vulnerabilities"]
        global_ = row["global"]["record"]["vulnerabilities"]
        self.assertTrue(any("0.82.0" in (p.get("patched_versions") or "") for p in repo))
        self.assertTrue(any(p.get("first_patched_version") == "0.83.0" for p in global_))
        kata = self.records["GHSA-q49m-57vm-c8cc"]
        self.assertEqual(kata["repository"]["severity"], "critical")
        self.assertEqual(kata["global"]["record"]["severity"], "high")

    def test_roles_and_multiple_packages(self):
        roles = {c["type"] for c in self.records["GHSA-jp5f-qr64-c9vw"]["repository"]["credits"]}
        self.assertEqual(roles, {"reporter", "remediation_developer", "coordinator"})
        self.assertEqual(len(self.records["GHSA-9cvr-5wv9-2gxr"]["repository"]["vulnerabilities"]), 2)

    def test_unavailable_cve_is_not_verified(self):
        for ghsa in ("GHSA-29rf-f4vv-pvq6", "GHSA-ggg4-v8vp-jxqh", "GHSA-w5cv-pw74-4rxc"):
            self.assertEqual(self.records[ghsa]["cve"]["status"], "not_found")
            self.assertTrue(self.records[ghsa]["cve"]["identifier"])

    def test_new_advisory_needs_no_editorial_row(self):
        sample = copy.deepcopy(next(iter(self.records.values())))
        sample["ghsa"] = sample["repository"]["ghsa"] = "GHSA-2222-3333-4444"
        rows = sync.csv_rows({"advisories": [sample]}, {"advisory_details": {}})
        self.assertEqual(rows[0]["tldr"], sample["repository"]["summary"])

if __name__ == "__main__":
    unittest.main()
