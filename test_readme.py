#!/usr/bin/env python3
"""README regression tests: counts, identity, references, safety, and completeness."""
import collections
import copy
import csv
import importlib.util
import io
import json
import pathlib
import re
import subprocess
import unittest
import base64
import xml.etree.ElementTree as ET
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("readme", ROOT / "build-readme.py")
readme = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readme)

class ReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = readme.load()
        cls.template = (ROOT / "README.tmpl.md").read_text()

    def render(self, data=None):
        return readme.render(*(data or self.data), self.template)

    def test_all_records_and_project_sections(self):
        result = self.render()
        rows, upstream, config, sources, standalone, projects = self.data
        self.assertGreaterEqual(len(rows), 70)
        self.assertGreaterEqual(len(upstream), 28)
        self.assertGreaterEqual(len(config["standalone_findings"]), 2)
        self.assertEqual(result.count('<a id="project-'), len(projects))
        self.assertEqual(result.count("published advisories ·"), 1)
        self.assertNotIn("sole reporter", result.lower())
        self.assertNotIn("img.shields.io", result)
        self.assertNotIn("reef-header", result)
        for row in rows:
            self.assertIn(readme.prose(row["tldr"]), result)
            self.assertIn(row["advisory_url"], result)
        for row in upstream:
            self.assertEqual(result.count(readme.prose(row["what"])), 1)

    def test_preserve_original_source_links(self):
        result = self.render()
        baseline = "06b30f4"
        def old(name):
            return subprocess.check_output(["git", "show", f"{baseline}:{name}"], text=True)
        for row in csv.DictReader(io.StringIO(old("advisories.csv"))):
            for key in ("advisory_url", "cve_url"):
                if row[key]:
                    self.assertTrue(readme.url(row[key]) in result, "Missing original link: " + row[key])
        for row in csv.DictReader(io.StringIO(old("upstream.csv"))):
            for key in ("url", "reference_url"):
                if row[key]:
                    self.assertTrue(readme.url(row[key]) in result, "Missing original link: " + row[key])
        config = json.loads(old("readme-data.json"))
        for item in config["coverage"]:
            for source in item["sources"]:
                self.assertIn(readme.url(source["url"]), result)
        for item in config["incomplete_fixes"]:
            for prior in item["predecessors"]:
                self.assertIn(readme.url(prior["url"]), result)
        for item in config["standalone_findings"]:
            for key in ("report", "fix"):
                self.assertIn(readme.url(item[key]["url"]), result)

    def test_new_project_updates_automatically(self):
        data = copy.deepcopy(self.data)
        rows, upstream, config, sources, standalone, projects = data
        source = copy.deepcopy(sources[0])
        identifier = "GHSA-2222-3333-4444"
        source["ghsa"] = source["repository"]["ghsa"] = identifier
        source["repository"]["repo"] = "example/new-project"
        source["repository"]["url"] = "https://github.com/example/new-project/security/advisories/" + identifier
        source["repository"]["summary"] = "A future published finding"
        source["cve"] = {"identifier": None, "status": "not_assigned", "checked_at": "2026-09-06"}
        source["global"] = {"status": "not_found", "checked_at": "2026-09-06"}
        row = readme.SYNC.csv_rows({"advisories": [source]}, config)[0]
        row = {key: str(value) for key, value in row.items()}
        rows.append(row)
        sources.append(source)
        readme.validate(*data)
        rendered = self.render(data)
        self.assertIn(f"{len(projects) + 1} projects · {len(rows)} published advisories", rendered)
        self.assertIn('id="project-example-new-project"', rendered)
        self.assertIn("A future published finding", rendered)

    def test_invalid_references_fail(self):
        for mutate in (
            lambda d: d[0].append(copy.deepcopy(d[0][0])),
            lambda d: d[2]["coverage"].append(copy.deepcopy(d[2]["coverage"][0])),
            lambda d: d[2]["coverage"][0].update(advisory="GHSA-missing"),
            lambda d: d[2]["incomplete_fixes"][0].update(advisory="GHSA-missing"),
            lambda d: d[1][0].update(kind="promotional_claim"),
            lambda d: d[1][0].update(advisory="GHSA-missing"),
            lambda d: d[1][0].update(date=""),
            lambda d: d[2].update(unhandled=[]),
            lambda d: d[2]["standalone_findings"][0].update(published="1900-01-01"),
        ):
            with self.subTest(mutation=mutate):
                data = copy.deepcopy(self.data)
                mutate(data)
                with self.assertRaises(ValueError):
                    readme.validate(*data)

    def test_unhandled_placeholders_fail(self):
        with self.assertRaises(ValueError):
            readme.render(*self.data, self.template + "{{UNKNOWN}}")
        with self.assertRaises(ValueError):
            readme.render(*self.data, self.template + "{{COUNT_LINE}}")

    def test_markdown_safety(self):
        self.assertEqual(readme.text("<script>|[x]*"), "&lt;script&gt;\\|\\[x\\]\\*")
        self.assertNotIn("<script>", readme.prose("<script>alert(1)</script>"))
        self.assertIn("%29", readme.link("x", "https://example.com/a)b"))
        for value in ("javascript:alert(1)", "https://example.com/a b", "https://user@example.com/a"):
            with self.assertRaises(ValueError):
                readme.url(value)

    def test_standalone_scope_and_source_differences(self):
        result = self.render()
        self.assertIn("NGINX Ingress Controller", result)
        self.assertIn('id="project-nginx-nginx"', result)
        self.assertIn('id="project-nginx-kubernetes-ingress"', result)
        self.assertEqual(result.count("Standalone finding; excluded"), len(self.data[2]["standalone_findings"]))
        self.assertIn("The maintainer and global severity labels differ", result)
        self.assertIn("0.82.0", result)
        self.assertIn("0.83.0", result)
        self.assertIn("remediation developer", result)
        self.assertIn("coordinator", result)
        self.assertIn("no structured CVSS score", result)
        self.assertIn("Lyrie Research", result)

    def test_catalog_descriptions_span_the_panel(self):
        result = self.render()
        self.assertNotIn("<kbd>", result)
        for row in self.data[0]:
            self.assertIn('<tr><td colspan="2" width="10000">\n\n' + readme.prose(row["tldr"]), result)
        self.assertIn('id="letter-a"', result)
        self.assertIn('[A](#letter-a)', result)
        for project_id, project in self.data[5].items():
            if project.get("logo") and not project.get("text_only"):
                self.assertIn(readme.catalog_assets.paths(project_id)["light"], result)

    def test_every_project_panel_requests_full_width(self):
        # Apply the GitHub-compatible width hint even to short upstream-only
        # projects. Percentages on the table itself are overridden by GitHub.
        result = self.render()
        panels = re.findall(r'<a id="project-[^"]+"></a>(.*?)(?=<a id="(?:project-|letter-)|<a id="notes")',
                            result, re.DOTALL)
        self.assertEqual(len(panels), len(self.data[5]))
        for panel in panels:
            self.assertIn('<tr><td colspan="2" width="10000">', panel)
            self.assertIn('<th align="left" width="70%">', panel)
            self.assertIn('<th align="right" width="30%">', panel)
        for row in self.data[1]:
            if not row["advisory"]:
                self.assertIn('<tr><td colspan="2" width="10000">\n\n' + readme.prose(row["what"]), result)
        for row in self.data[2]["standalone_findings"]:
            self.assertIn('<tr><td colspan="2" width="10000">\n\n' + readme.prose(row["summary"]), result)

    def test_gallery_embeds_original_marks_without_recoloring(self):
        assets = readme.catalog_assets
        for project in self.data[5].values():
            if not project.get("logo") or project.get("text_only"):
                continue
            for theme in ("light", "dark"):
                svg = ET.fromstring(assets.tile(project, theme))
                image = svg.find("{http://www.w3.org/2000/svg}image")
                embedded = base64.b64decode(image.attrib["href"].split(",", 1)[1])
                source = project.get("logo_dark", project["logo"]) if theme == "dark" else project["logo"]
                self.assertEqual(embedded, (ROOT / source["file"]).read_bytes())
                self.assertEqual(svg.find("{http://www.w3.org/2000/svg}title").text, project["name"])
                self.assertLessEqual(len(assets.label_lines(project["name"])), 2)

    def test_gallery_staleness_check(self):
        assets = readme.catalog_assets
        with tempfile.TemporaryDirectory(prefix="koda-gallery-test-") as directory:
            with mock.patch.object(assets, "ROOT", pathlib.Path(directory)), mock.patch.object(
                assets, "generated", return_value={"assets/catalog/test.svg": "<svg/>"}
            ):
                with self.assertRaises(ValueError):
                    assets.sync({}, check=True)
                assets.sync({})
                assets.sync({}, check=True)
                (pathlib.Path(directory) / "assets/catalog/test.svg").write_text("stale")
                with self.assertRaises(ValueError):
                    assets.sync({}, check=True)

if __name__ == "__main__":
    unittest.main()
