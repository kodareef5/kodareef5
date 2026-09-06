#!/usr/bin/env python3
"""Generate the complete project-based README. Use --check for a read-only check.

Public source policy: RECORD-REVIEW.md. Refresh/export: sync-records.py.
"""
import collections
import csv
import hashlib
import html
import importlib.util
import json
import pathlib
import re
import sys
from urllib.parse import quote, urlsplit
import catalog_assets

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("record_sync", HERE / "sync-records.py")
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)
SEVERITY = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Moderate", "low": "🔵 Low", "unknown": "Unrated"}
PATCH_KINDS = {"authored_merged", "authored_merged_own_advisory"}
KINDS = {
    "authored_merged": "Merged patch", "authored_merged_own_advisory": "Merged patch",
    "advisory_text": "Report acknowledgement", "changelog": "Changelog acknowledgement",
    "commit_credit": "Upstream acknowledgement", "errata": "Downstream fixes",
    "issue_fixed": "Report and fixes", "release": "Release acknowledgement",
    "release_note": "Release acknowledgement", "thanks_file": "Acknowledgement",
    "vendor_doc": "Vendor acknowledgement",
}
CONFIG_KEYS = {"incomplete_fixes", "coverage", "standalone_findings", "cve_mappings", "advisory_details"}


def read_csv(path):
    with path.open(newline="", encoding="utf8") as stream:
        return list(csv.DictReader(stream))


def unique(values, context):
    duplicate = [v for v, n in collections.Counter(values).items() if n > 1]
    if duplicate:
        raise ValueError(f"{context}: duplicate references: {duplicate}")


def required(record, names, context):
    for name in names:
        if record.get(name) in (None, "", []):
            raise ValueError(f"{context}: missing {name}")


def url(value):
    if not isinstance(value, str) or any(c.isspace() for c in value):
        raise ValueError(f"Invalid URL: {value!r}")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username:
        raise ValueError(f"Expected a public HTTPS URL: {value!r}")
    return quote(value, safe="/:?=&%#@+;,-._~")


def text(value):
    value = html.escape(str(value or ""), quote=False)
    value = re.sub(r"([\\*_\[\]|])", r"\\\1", value).replace(chr(96), "\\" + chr(96))
    return value.replace("\r", "").replace("\n", " ")


def prose(value):
    """Explicit inline code is allowed, but arbitrary HTML/Markdown is escaped."""
    chunks = str(value or "").split(chr(96))
    return "".join(
        f"<code>{html.escape(chunk)}</code>" if index % 2 and index < len(chunks) - 1
        else text(chunk) for index, chunk in enumerate(chunks))


def link(label, target):
    return f"[{text(label)}]({url(target)})"


def slug(project_id):
    return "project-" + re.sub(r"[^a-z0-9]+", "-", project_id.lower()).strip("-")


def logo(project, size=24):
    item = project.get("logo")
    if not item or project.get("text_only"):
        return ""
    ratio = item["width"] / item["height"]
    width = min(round(size * ratio), size * 2)
    height = max(1, round(width / ratio))
    image = f'<img src="./{html.escape(item["file"], quote=True)}" width="{width}" height="{height}" alt="">'
    if project.get("logo_dark"):
        dark = html.escape(project["logo_dark"]["file"], quote=True)
        image = f'<picture><source media="(prefers-color-scheme: dark)" srcset="./{dark}">{image}</picture>'
    return image + " "


def load():
    rows = read_csv(HERE / "advisories.csv")
    upstream = read_csv(HERE / "upstream.csv")
    config = json.loads((HERE / "readme-data.json").read_text())
    sources = json.loads((HERE / "advisory-sources.json").read_text())["advisories"]
    standalone = json.loads((HERE / "standalone-sources.json").read_text())["records"]
    projects = json.loads((HERE / "projects.json").read_text())
    provenance = json.loads((HERE / "upstream-sources.json").read_text())["records"]
    unique((r["id"] for r in provenance), "upstream provenance")
    if {r["id"] for r in upstream} != {r["id"] for r in provenance}:
        raise ValueError("Upstream/provenance reference mismatch")
    provenance = {r["id"]: r for r in provenance}
    for row in upstream:
        source = provenance[row["id"]]
        if any(row[key] != source[key] for key in ("url", "date", "date_kind")):
            raise ValueError(f"Upstream source mismatch: {row['id']}")
    validate(rows, upstream, config, sources, standalone, projects)
    return rows, upstream, config, sources, standalone, projects


def validate(rows, upstream, config, sources, standalone, projects):
    if set(config) != CONFIG_KEYS:
        raise ValueError(f"Unexpected/missing README configuration keys: {set(config) ^ CONFIG_KEYS}")
    unique((r["ghsa"] for r in rows), "advisories")
    unique((r["ghsa"] for r in sources), "source snapshots")
    ids = {r["ghsa"] for r in rows}
    if ids != {r["ghsa"] for r in sources}:
        raise ValueError("Advisory/source reference mismatch")
    by_id = {r["ghsa"]: r for r in sources}
    for row in rows:
        required(row, ("ghsa", "repo", "project_id", "published", "severity", "advisory_url", "tldr"), row["ghsa"])
        if not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", row["ghsa"]):
            raise ValueError("Invalid advisory identifier")
        if row["severity"] not in SEVERITY:
            raise ValueError("Unknown severity")
        source = by_id[row["ghsa"]]
        if source["repository"]["state"] != "published":
            raise ValueError("Unpublished source cannot render")
        if row["project_id"] != source["repository"]["repo"]:
            raise ValueError("Advisory project identity mismatch")
        if row["severity"] != source["repository"]["severity"] or row["published"] != source["repository"]["published"][:10]:
            raise ValueError("Stale canonical severity/publication; refresh the export")
        url(row["advisory_url"])
        if row["cve_url"]:
            url(row["cve_url"])
        if source["global"]["status"] not in {"found", "not_found"}:
            raise ValueError("Unverified global indexing status")
    for section in ("advisory_details", "cve_mappings"):
        if set(config[section]) - ids:
            raise ValueError(f"{section}: unknown advisory references")
    for section in ("incomplete_fixes", "coverage"):
        unique((r["advisory"] for r in config[section]), section)
        for entry in config[section]:
            if entry["advisory"] not in ids:
                raise ValueError(f"{section}: unknown advisory {entry['advisory']}")
            children = "predecessors" if section == "incomplete_fixes" else "sources"
            required(entry, (children,), section)
            unique((p["url"] for p in entry[children]), children)
            for child in entry[children]:
                required(child, ("url", "id" if children == "predecessors" else "label"), children)
                url(child["url"])
            if section == "incomplete_fixes":
                required(entry, ("relationship", "type"), section)
                unique((p["id"] for p in entry["predecessors"]), "predecessors")
                if entry["type"] not in {"incomplete_fix", "related"}:
                    raise ValueError("Unknown relationship kind")
            else:
                for item in entry["sources"]:
                    if item["status"] not in {"verified", "unavailable"}:
                        raise ValueError("Unknown coverage verification status")
                    required(item, ("verified",) if item["status"] == "verified" else ("note", "last_attempted"), "coverage check")
    unique((r["id"] for r in upstream), "upstream")
    for row in upstream:
        required(row, ("id", "project_id", "kind", "what", "url", "verified"), "upstream")
        if row["kind"] not in KINDS:
            raise ValueError(f"Unhandled upstream kind: {row['kind']}")
        url(row["url"])
        if row["reference_url"]:
            required(row, ("reference_label",), "upstream reference")
            url(row["reference_url"])
        for item in json.loads(row["additional_links"]):
            required(item, ("label", "url"), "upstream link")
            url(item["url"])
        if row["advisory"]:
            if row["advisory"] not in ids:
                raise ValueError("Unknown upstream advisory association")
            if row["project_id"] != by_id[row["advisory"]]["repository"]["repo"]:
                raise ValueError("Upstream/advisory project mismatch")
        if row["kind"] == "authored_merged_own_advisory" and not row["advisory"]:
            raise ValueError("Associated authored patch must identify its advisory")
        if row["kind"] in PATCH_KINDS and not row["date"]:
            raise ValueError("Authored patch is missing its merge/commit date")
    unique((r["identifier"] for r in config["standalone_findings"]), "standalone")
    unique((r["identifier"] for r in standalone), "standalone sources")
    if {r["identifier"] for r in standalone} != {r["identifier"] for r in config["standalone_findings"]}:
        raise ValueError("Standalone/source reference mismatch")
    for item in config["standalone_findings"]:
        required(item, ("identifier", "project_id", "published", "severity", "summary", "record_url", "source_url", "credit"), "standalone")
        if item["identifier"] in {r["cve"] for r in rows if r["cve"]}:
            raise ValueError("Standalone duplicates an advisory CVE")
        for key in ("record_url", "source_url"):
            url(item[key])
        for key in ("report", "fix"):
            if item.get(key):
                url(item[key]["url"])
        source = next(r for r in standalone if r["identifier"] == item["identifier"])
        if source["status"] != "found" or source["record"]["metadata"]["state"] != "PUBLISHED":
            raise ValueError("Standalone record is not publicly verified")
        if item["published"] != source["record"]["metadata"]["datePublished"][:10]:
            raise ValueError("Standalone publication date mismatch")
    used = {r["project_id"] for r in rows + upstream + config["standalone_findings"]}
    if set(projects) - used:
        raise ValueError(f"Unknown project display references: {set(projects) - used}")
    unique((slug(p) for p in used), "project anchors")
    for project in projects.values():
        required(project, ("name", "url"), "project display")
        url(project["url"])
        for key in ("logo", "logo_dark"):
            if not project.get(key):
                continue
            item = project[key]
            required(item, ("file", "source", "provenance", "sha256", "width", "height", "verified"), "logo")
            path = HERE / item["file"]
            if path.parent != HERE / "assets/logos" or not path.is_file():
                raise ValueError(f"Missing/unsafe local logo: {item['file']}")
            if min(item["width"], item["height"]) <= 0:
                raise ValueError("Invalid logo dimensions")
            if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                raise ValueError(f"Logo checksum mismatch: {item['file']}")
            url(item["source"])
            url(item["provenance"])


def facts(rows, upstream, standalone, projects):
    return {"advisories": len(rows), "patches": sum(r["kind"] in PATCH_KINDS for r in upstream),
            "standalone": len(standalone), "projects": len(projects),
            "global": sum(r["globally_indexed"] == "yes" for r in rows)}


def rating_text(source, name):
    values = SYNC.scores(source)
    if not values:
        return f"{name}: no structured CVSS score."
    return f"{name}: " + "; ".join(f"CVSS {v['version']} **{v['score']}**" for v in values) + "."


def package_lines(packages, name, global_=False):
    if not packages:
        return [f"{name}: no package/version data published."]
    lines = [f"**{name} package records**", "", "| Package | Affected | Fixed |", "|---|---|---|"]
    for package in packages:
        fixed = package.get("first_patched_version") if global_ else package.get("patched_versions")
        if isinstance(fixed, dict):
            fixed = fixed.get("identifier")
        lines.append(f"| {text(package.get('package', {}).get('name') or 'Unspecified')} | {text(package.get('vulnerable_version_range') or 'Not specified')} | {text(fixed or 'Not specified')} |")
    return lines


def cna_details(source):
    lines = []
    scores = SYNC.cna_scores(source)
    if scores:
        lines.append("CVE CNA: " + "; ".join(f"CVSS {s['version']} **{s['score']}**" for s in scores) + ".")
    for affected in source.get("affected") or []:
        versions = []
        for version in affected.get("versions") or []:
            terms = [version.get("status", "unspecified") + ": " + version.get("version", "unspecified")]
            for key, label in (("lessThan", "<"), ("lessThanOrEqual", "≤")):
                if version.get(key):
                    terms.append(label + " " + version[key])
            versions.append(" ".join(terms))
        if versions:
            lines.append(f"CNA version record — {text(affected.get('product') or 'Unspecified')}: {text('; '.join(versions))}.")
    return lines


def contributor_line(credits):
    if not credits:
        return "No structured contributor roles published."
    values = []
    for credit in credits:
        name = credit.get("login") or credit.get("user", {}).get("login") or "unknown"
        values.append(f"{link(name, 'https://github.com/' + name)} ({text(credit.get('type', 'unspecified').replace('_', ' '))})")
    return "Contributors: " + ", ".join(values) + "."


def upstream_visible(row):
    date = f" · {row['date']} ({row['date_kind']})" if row["date"] else ""
    return f"**{link(KINDS[row['kind']], row['url'])}**{date} — {prose(row['what'])}"


def html_link(label, target):
    return f'<a href="{html.escape(url(target), quote=True)}">{html.escape(label)}</a>'


def panel_row(heading, metadata, description):
    """Two metadata cells; the description always gets the complete width."""
    return [
        "<tr>",
        f'<td valign="top">{heading}</td>',
        f'<td align="right" valign="top">{metadata}</td>',
        "</tr>",
        '<tr><td colspan="2">',
        "",
        description,
        "",
        "</td></tr>",
    ]


def upstream_panel(row):
    meta = f'{row["date"]}<br><sub>{html.escape(row["date_kind"])}</sub>' if row["date"] else ""
    return panel_row(
        "<strong>" + html_link(KINDS[row["kind"]], row["url"]) + "</strong>",
        meta, prose(row["what"]),
    )


def upstream_details(row):
    lines = [f"**{link(KINDS[row['kind']], row['url'])}:** {prose(row['credit_text'])}. Checked {row['verified']}."]
    links = json.loads(row["additional_links"])
    if row["reference_url"]:
        links.insert(0, {"label": row["reference_label"], "url": row["reference_url"]})
    if links:
        lines += ["", "Sources: " + " · ".join(link(x["label"], x["url"]) for x in links) + "."]
    if row["notes"]:
        lines += ["", prose(row["notes"])]
    return lines


def advisory_details(row, source, config, attached):
    repo = source["repository"]
    lines = [f"#### {text(row['ghsa'])}", "", link("Maintainer advisory", repo["url"]) +
             f" · Published {row['published']} · Checked {row['last_checked']}", "",
             f"Maintainer severity: {SEVERITY[row['severity']]}. " + rating_text(repo, "Maintainer")]
    if SYNC.primary_score(source)["score"] == "":
        lines += ["", "CVSS: no structured score available from the checked sources."]
    global_ = source["global"].get("record")
    if global_:
        lines += ["", link("GitHub global record", global_["html_url"]) + f" · Indexed {(global_.get('published_at') or '')[:10]}.",
                  "", f"Global severity: {SEVERITY[global_['severity']]}. " + rating_text(global_, "GitHub global")]
        if global_["severity"] != repo["severity"]:
            lines += ["", "The maintainer and global severity labels differ; this page uses the maintainer’s label."]
    else:
        lines += ["", f"Not found in GitHub’s global advisory database at the {source['global']['checked_at'][:10]} lookup."]
    lines += ["", contributor_line(repo.get("credits") or [])]
    if repo.get("withdrawn"):
        lines += ["", f"Withdrawn by source: {text(repo['withdrawn'])}."]
    if row["cwe"]:
        lines += ["", "Maintainer weaknesses: " + ", ".join(link(c, f"https://cwe.mitre.org/data/definitions/{c.split('-')[1]}.html") for c in row["cwe"].split(";")) + "."]
    if global_:
        global_cwes = [c["cwe_id"] for c in global_.get("cwes") or []]
        if global_cwes != (repo.get("cwes") or []):
            lines += ["", "Global weaknesses: " + text(", ".join(global_cwes) or "Not specified") + "."]
    lines += [""] + package_lines(repo.get("vulnerabilities") or [], "Maintainer")
    if global_:
        lines += [""] + package_lines(global_.get("vulnerabilities") or [], "GitHub global", True)
    cve = source["cve"]
    if cve["identifier"]:
        lines += ["", link(cve["identifier"], row["cve_url"])]
        if cve["status"] == "found":
            lines += ["", link("CVE CNA source", cve["url"])] + [""] + cna_details(cve["record"])
        else:
            lines += ["", f"Verification note: the advisory supplies this CVE identifier, but its public CVE JSON was not retrievable at the {cve['checked_at'][:10]} check."]
    editorial = config["advisory_details"].get(row["ghsa"], {})
    if editorial.get("details") and editorial["details"] != row["tldr"]:
        lines += ["", prose(editorial["details"])]
    if editorial.get("legacy_fixed_in") and not repo.get("vulnerabilities"):
        lines += ["", "Earlier editorial fix note (not package-verified): " + text(editorial["legacy_fixed_in"]) + "."]
    fix = row["fix_pr"]
    if fix and "#" in fix and not fix.startswith("https://"):
        repository, number = fix.rsplit("#", 1)
        fix = f"https://github.com/{repository}/pull/{number}"
    if fix and not any(u["url"] == fix for u in attached):
        lines += ["", link("Fix reference", fix)]
    old_url = editorial.get("legacy_url")
    if old_url and old_url not in (repo["url"], (global_ or {}).get("html_url")):
        lines += ["", link("Previously linked advisory record", old_url)]
    old_cve_url = editorial.get("legacy_cve_url")
    if old_cve_url and old_cve_url != row["cve_url"]:
        lines += ["", link("NVD record" if "nvd.nist.gov/" in old_cve_url else "Additional CVE record", old_cve_url)]
    for relation in config["incomplete_fixes"]:
        if relation["advisory"] == row["ghsa"]:
            label = "Incomplete fix" if relation["type"] == "incomplete_fix" else "Related work"
            lines += ["", f"**{label}:** " + " · ".join(link(p["id"], p["url"]) for p in relation["predecessors"]) +
                      ". " + prose(relation["relationship"])]
    for entry in config["coverage"]:
        if entry["advisory"] == row["ghsa"]:
            lines += ["", "**Coverage:** " + " · ".join(link(s["label"], s["url"]) for s in entry["sources"]) + "."]
            for item in entry["sources"]:
                if item["status"] == "unavailable":
                    lines += ["", f"{text(item['label'])}: {text(item['note'])}"]
    for item in attached:
        lines += [""] + upstream_details(item)
    return lines


def render(rows, upstream, config, sources, standalone_sources, projects, template):
    source_map = {r["ghsa"]: r for r in sources}
    standalone_map = {r["identifier"]: r for r in standalone_sources}
    used = {r["project_id"] for r in rows + upstream + config["standalone_findings"]}
    projects = {p: projects.get(p, {"name": p.split("/")[-1], "url": "https://github.com/" + p}) for p in used}
    ordered = sorted(projects, key=lambda p: (projects[p]["name"].casefold(), p.casefold()))
    index, text_index = [], []
    for project_id in ordered:
        project = projects[project_id]
        if project.get("logo") and not project.get("text_only"):
            paths = catalog_assets.paths(project_id)
            image = (
                f'<picture><source media="(prefers-color-scheme: dark)" srcset="./{paths["dark"]}">'
                f'<img src="./{paths["light"]}" width="{catalog_assets.WIDTH}" height="{catalog_assets.HEIGHT}" alt="{html.escape(project["name"], quote=True)}"></picture>'
            )
            index.append(f'<a href="#{slug(project_id)}">{image}</a>')
        else:
            name = html.escape(project["name"]).replace(" ", "&nbsp;")
            text_index.append(f'<a href="#{slug(project_id)}">{name}</a>')
    index_html = '<p align="center">\n' + "\n".join(index) + "\n</p>"
    if text_index:
        index_html += '\n\n<p align="center">\n' + " · ".join(text_index) + "\n</p>"
    letters = sorted({projects[p]["name"][0].upper() for p in ordered})
    letter_nav = " &nbsp; ".join(f"[{letter}](#letter-{letter.lower()})" for letter in letters)
    f = facts(rows, upstream, config["standalone_findings"], projects)
    counts = f"{f['projects']} projects · {f['advisories']} published advisories · {f['patches']} merged patches"
    sections, rendered = [], []
    last_letter = None
    for project_id in ordered:
        project = projects[project_id]
        letter = project["name"][0].upper()
        if letter != last_letter:
            sections += [f'<a id="letter-{letter.lower()}"></a>\n\n## {letter}\n']
            last_letter = letter
        lines = [
            f'<a id="{slug(project_id)}"></a>', "",
            "<table>",
            "<thead><tr>",
            f'<th align="left" width="70%"><h3>{logo(project, 32)}{html_link(project["name"], project["url"])}</h3></th>',
            '<th align="right" width="30%"><a href="#projects" aria-label="Back to project gallery">↑</a></th>',
            "</tr></thead>",
            "<tbody>",
        ]
        events = [(r["published"], "advisory", r) for r in rows if r["project_id"] == project_id]
        events += [(r["date"], "upstream", r) for r in upstream if r["project_id"] == project_id and not r["advisory"]]
        events += [(r["published"], "standalone", r) for r in config["standalone_findings"] if r["project_id"] == project_id]
        events.sort(key=lambda x: (x[0], x[1], x[2].get("ghsa", x[2].get("id", ""))), reverse=True)
        detailed = []
        for date, kind, row in events:
            if kind == "advisory":
                rendered.append(row["ghsa"])
                identifiers = []
                if row["cve"]:
                    identifiers.append("<strong>" + html_link(row["cve"], row["cve_url"]) + "</strong>")
                identifiers.append(html_link(row["ghsa"], row["advisory_url"]))
                attached = [r for r in upstream if r["advisory"] == row["ghsa"]]
                rendered.extend(r["id"] for r in attached)
                description = prose(row["tldr"])
                for item in attached:
                    description += "\n\n" + upstream_visible(item)
                lines += panel_row("<br>".join(identifiers),
                                   f'{SEVERITY[row["severity"]].replace(" ", "&nbsp;")}<br><sub>{row["published"].replace("-", "&#8209;")}</sub>',
                                   description)
                detailed += advisory_details(row, source_map[row["ghsa"]], config, attached) + [""]
            elif kind == "upstream":
                rendered.append(row["id"])
                lines += upstream_panel(row)
                detailed += upstream_details(row) + [""]
            else:
                rendered.append(row["identifier"])
                lines += panel_row(
                    "<strong>" + html_link(row["identifier"], row["record_url"]) + "</strong><br><sub>Vendor/CVE record</sub>",
                    f'{SEVERITY[row["severity"]].replace(" ", "&nbsp;")}<br><sub>{row["published"].replace("-", "&#8209;")}</sub>',
                    prose(row["summary"]),
                )
                detailed += [f"#### {text(row['identifier'])}", "", prose(row["credit"]), "",
                             link("CVE CNA source", row["source_url"]), ""] + cna_details(standalone_map[row["identifier"]]["record"])
                for key in ("report", "fix"):
                    if row.get(key):
                        detailed += ["", link(row[key]["label"], row[key]["url"])]
                detailed += ["", "Standalone finding; excluded from GitHub advisory statistics.", ""]
        detail_label = "Versions, credits, and sources" if any(e[1] != "upstream" for e in events) else "Credit and sources"
        lines += [
            '<tr><td colspan="2">', "",
            "<details>", f"<summary>{detail_label}</summary>", "",
        ] + detailed + [
            "</details>", "", "</td></tr>", "</tbody>", "</table>", "",
        ]
        sections.append("\n".join(lines))
    expected = [r["ghsa"] for r in rows] + [r["id"] for r in upstream] + [r["identifier"] for r in config["standalone_findings"]]
    if collections.Counter(rendered) != collections.Counter(expected):
        raise ValueError("A record was lost or rendered more than once")
    notes = [
        "Advisory counts cover published GitHub advisories with structured credit. "
        "Vendor/CVE-only findings, prose acknowledgements, and patches are separate records.", "",
        "Repository publication dates and maintainer severity labels are used throughout. "
        "CVSS versions, source-specific ratings, package fixes, and contributor roles appear under each project. "
        "Undated acknowledgements follow dated work; verification dates are not publication dates.", "",
        f"{f['global']} advisories were found in GitHub’s global database; "
        f"{f['advisories'] - f['global']} were not found there and are linked to their repository publications. "
        "These are lookup results, not a claim that repository advisories are private.", "",
        "<details>", "<summary>Distributions and verification notes</summary>", "",
        "Advisory-only distributions. A record may name multiple weaknesses; these tables are independent.", "",
        "#### Maintainer severity", "", "| Severity | Advisories |", "|---|---:|",
    ]
    severity = collections.Counter(r["severity"] for r in rows)
    for key in SEVERITY:
        if severity[key]:
            notes.append(f"| {SEVERITY[key]} | {severity[key]} |")
    notes += ["", "#### Language / ecosystem", "", "Editorial grouping by the affected implementation; not inferred from the logo.", "",
              "| Language / ecosystem | Advisories |", "|---|---:|"]
    for key, count in sorted(collections.Counter(r["ecosystem"] or "Not classified" for r in rows).items(), key=lambda x: (-x[1], x[0])):
        notes.append(f"| {text(key)} | {count} |")
    notes += ["", "#### Published weaknesses", "", "| Weakness | Advisories |", "|---|---:|"]
    cwe_names = json.loads((HERE / "cwe_names.json").read_text())
    cwes = collections.Counter(c for r in rows for c in r["cwe"].split(";") if c)
    for key, count in sorted(cwes.items(), key=lambda x: (-x[1], x[0])):
        name = cwe_names.get(key, key)
        notes.append(f"| {link(key, 'https://cwe.mitre.org/data/definitions/' + key.split('-')[1] + '.html')} — {text(name)} | {count} |")
    if sum(not r["cwe"] for r in rows):
        notes.append(f"| Not specified | {sum(not r['cwe'] for r in rows)} |")
    notes += ["", "#### Verification limits", ""]
    unavailable = [s["cve"]["identifier"] for s in sources if s["cve"]["status"] == "not_found"]
    if unavailable:
        notes += ["The published advisories supply " + ", ".join(text(c) for c in unavailable) +
                  ", but their public CVE JSON was unavailable at the recorded checks. Their IDs are retained with source-specific notes.", ""]
    for item in config["coverage"]:
        for source in item["sources"]:
            if source["status"] == "unavailable":
                notes += [f"{link(source['label'], source['url'])}: {text(source['note'])}", ""]
    notes += ["See [record review](./RECORD-REVIEW.md) for the factual corrections and source policy.", "", "</details>"]
    values = {"PROJECT_INDEX": index_html, "COUNT_LINE": counts, "LETTER_NAV": letter_nav,
              "PROJECT_WORK": "\n".join(sections), "RECORD_NOTES": "\n".join(notes)}
    placeholders = re.findall(r"\{\{([A-Z_]+)\}\}", template)
    if collections.Counter(placeholders) != collections.Counter(values.keys()):
        raise ValueError("Template placeholders must occur exactly once and match generated sections")
    result = re.sub(r"\{\{([A-Z_]+)\}\}", lambda m: values[m.group(1)], template)
    if re.search(r"\{\{[A-Z_]+\}\}", result):
        raise ValueError("Unresolved generated placeholder")
    return result


def main():
    try:
        data = load()
        catalog_assets.sync(data[5], check="--check" in sys.argv)
        result = render(*data, (HERE / "README.tmpl.md").read_text())
        path = HERE / "README.md"
        if "--check" in sys.argv:
            if path.read_text() != result:
                raise ValueError("README.md is stale; run ./build-readme.py")
            print("README is current; all records resolve and render exactly once.")
        else:
            path.write_text(result)
            print(f"Rendered {len(data[0])} advisories, {len(data[1])} upstream records, and {len(data[2]['standalone_findings'])} standalone findings.")
    except (ValueError, KeyError) as error:
        raise SystemExit(f"README validation failed: {error}")


if __name__ == "__main__":
    main()
