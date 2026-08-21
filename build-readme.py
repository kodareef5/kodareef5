#!/usr/bin/env python3
"""Render README.md from structured research records.

README.tmpl.md owns section order and fixed prose. advisories.csv supplies the
published advisory record, upstream.csv supplies work outside that ledger, and
readme-data.json contains small editorial lists that reference those records.
No project, finding, count, credit, or coverage row is maintained in the
template.

  ./build-readme.py            render README.md
  ./build-readme.py --check    verify the committed README matches the inputs

WHERE advisories.csv COMES FROM — read this before editing it.
This file is NOT the source of truth and must not be hand-maintained. It is fed
from the private record at kodareef5/koda-worklog, whose data/advisories.csv is
rebuilt from the GitHub advisory API by bin/sync-advisories.sh:

    python3 bin/sync-profile.py ~/dev/kodareef5 --apply   # run in koda-worklog
    ./build-readme.py                                     # run here

(The old credit-sweep.sh referenced here is gone; sync-advisories.sh absorbed it.)

Treating this CSV as the source of truth is exactly what went wrong before: on
2026-08-20 the live badges read sole_reporter 51 / high_or_critical 40 while the
API said 45 / 38, because seven severities and eight sole-reporter flags had been
hand-set and never rechecked, and two published advisories were missing outright.
Everything the API is authoritative on — severity, cve, co_credited and the
sole_reporter derived from it — now comes from sync-profile.py and will be
overwritten if you edit it here.

These columns are editorial and are NEVER touched by the sync, so they are
yours to write: class, ecosystem, cwe, tldr, fixed_in, fix_pr, summary,
published, cvss, advisory_url. A new row arrives with those blank.
"""

import collections
import csv
import json
import pathlib
import re
import sys
from urllib.parse import quote

from orgs import CWE_PLAIN, DOMAINS, META


HERE = pathlib.Path(__file__).parent
ADVISORIES = HERE / "advisories.csv"
UPSTREAM = HERE / "upstream.csv"
README_DATA = HERE / "readme-data.json"
CWE_NAMES = HERE / "cwe_names.json"
TMPL = HERE / "README.tmpl.md"
OUT = HERE / "README.md"

SEV_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_BADGE = {
    "critical": "b91c1c",
    "high": "ea580c",
    "medium": "ca8a04",
    "low": "64748b",
}
SEV_LABEL_BADGE = {
    "critical": "7f1d1d",
    "high": "9a3412",
    "medium": "854d0e",
    "low": "334155",
}
ECO_BADGE = {
    "Go": "00add8",
    "JavaScript": "b7791f",
    "Python": "3776ab",
    "Rust": "b7410e",
    "PHP": "777bb4",
    "C": "00599c",
    "C++": "659ad2",
}
ECO_LOGO = {
    "Go": ("go", "white"),
    "JavaScript": ("javascript", "white"),
    "Python": ("python", "white"),
    "Rust": ("rust", "white"),
    "PHP": ("php", "white"),
    "C": ("c", "white"),
    "C++": ("cplusplus", "white"),
}
STAT_BADGES = [
    ("ADVISORIES", "total", "e63946", "#github-advisories"),
    ("ORGANIZATIONS", "orgs", "00a6a6", "#projects"),
    ("CVEs", "cves", "3a86ff", "#github-advisories"),
    ("SOLE REPORTER", "sole", "8338ec", "#github-advisories"),
    ("HIGH + CRITICAL", "hicrit", "ff6b35", "#github-advisories"),
]

PATCH_KINDS = {"authored_merged", "authored_merged_own_advisory"}
RECORD_KINDS = {
    "advisory_text",
    "changelog",
    "commit_credit",
    "errata",
    "issue_fixed",
    "release",
    "release_note",
    "thanks_file",
    "vendor_doc",
}
CONFIG_KEYS = {
    "featured",
    "incomplete_fixes",
    "coverage",
    "standalone_findings",
}


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def require_fields(record, fields, where):
    missing = [name for name in fields if not str(record.get(name) or "").strip()]
    if missing:
        raise ValueError(f"{where}: missing required fields: {', '.join(missing)}")


def validate_url(url, where):
    if not re.fullmatch(r"https://[^\s]+", str(url or "")):
        raise ValueError(f"{where}: expected an https URL, got {url!r}")


def ensure_unique(values, where):
    counts = collections.Counter(values)
    duplicates = sorted(value for value, count in counts.items() if count > 1)
    if duplicates:
        raise ValueError(f"{where}: duplicates: {duplicates}")


def load():
    rows = read_csv(ADVISORIES)
    rows.sort(key=lambda row: row["published"], reverse=True)
    upstream = read_csv(UPSTREAM)
    config = json.loads(README_DATA.read_text(encoding="utf-8"))
    validate(rows, upstream, config)
    return rows, upstream, config


def validate(rows, upstream, config):
    if set(config) != CONFIG_KEYS:
        missing = sorted(CONFIG_KEYS - set(config))
        extra = sorted(set(config) - CONFIG_KEYS)
        raise ValueError(f"readme-data.json keys: missing={missing}, extra={extra}")

    for row_number, row in enumerate(rows, start=2):
        where = f"advisories.csv:{row_number}"
        require_fields(
            row,
            ["ghsa", "severity", "published", "repo", "org", "advisory_url", "class"],
            where,
        )
        if row["severity"] not in SEV_LABEL:
            raise ValueError(f"{where}: unknown severity {row['severity']!r}")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["published"]):
            raise ValueError(f"{where}: malformed published date {row['published']!r}")
        validate_url(row["advisory_url"], f"{where} advisory_url")
        if row["cve"]:
            validate_url(row["cve_url"], f"{where} cve_url")
        if row.get("fix_pr") and not re.fullmatch(r"[^/#]+/[^/#]+#\d+", row["fix_pr"]):
            raise ValueError(f"{where}: malformed fix_pr {row['fix_pr']!r}")

    ghsa_ids = [row["ghsa"] for row in rows]
    ensure_unique(ghsa_ids, "advisories.csv ghsa")
    by_ghsa = {row["ghsa"]: row for row in rows}

    featured = config["featured"]
    if len(featured) != 8:
        raise ValueError(f"readme-data.json featured: expected 8 entries, got {len(featured)}")
    ensure_unique(featured, "readme-data.json featured")
    unknown = sorted(set(featured) - set(by_ghsa))
    if unknown:
        raise ValueError(f"readme-data.json featured: unknown advisories: {unknown}")

    incomplete = config["incomplete_fixes"]
    incomplete_ids = [entry.get("advisory") for entry in incomplete]
    ensure_unique(incomplete_ids, "readme-data.json incomplete_fixes")
    for index, entry in enumerate(incomplete):
        where = f"readme-data.json incomplete_fixes[{index}]"
        require_fields(entry, ["advisory", "relationship"], where)
        if entry["advisory"] not in by_ghsa:
            raise ValueError(f"{where}: unknown advisory {entry['advisory']!r}")
        predecessors = entry.get("predecessors")
        if not isinstance(predecessors, list) or not predecessors:
            raise ValueError(f"{where}: predecessors must be a non-empty list")
        predecessor_ids = []
        for predecessor_index, predecessor in enumerate(predecessors):
            predecessor_where = f"{where}.predecessors[{predecessor_index}]"
            require_fields(predecessor, ["id", "url"], predecessor_where)
            validate_url(predecessor["url"], predecessor_where)
            predecessor_ids.append(predecessor["id"])
        ensure_unique(predecessor_ids, f"{where} predecessors")

    coverage = config["coverage"]
    coverage_ids = [entry.get("advisory") for entry in coverage]
    ensure_unique(coverage_ids, "readme-data.json coverage")
    for index, entry in enumerate(coverage):
        where = f"readme-data.json coverage[{index}]"
        require_fields(entry, ["advisory"], where)
        if entry["advisory"] not in by_ghsa:
            raise ValueError(f"{where}: unknown advisory {entry['advisory']!r}")
        sources = entry.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ValueError(f"{where}: sources must be a non-empty list")
        source_urls = []
        for source_index, source in enumerate(sources):
            source_where = f"{where}.sources[{source_index}]"
            require_fields(source, ["label", "url"], source_where)
            validate_url(source["url"], source_where)
            source_urls.append(source["url"])
        ensure_unique(source_urls, f"{where} source URLs")

    standalone = config["standalone_findings"]
    standalone_ids = [entry.get("identifier") for entry in standalone]
    ensure_unique(standalone_ids, "readme-data.json standalone_findings")
    advisory_cves = {row["cve"] for row in rows if row["cve"]}
    overlap = sorted(set(standalone_ids) & advisory_cves)
    if overlap:
        raise ValueError(f"standalone findings already present in advisories.csv: {overlap}")
    for index, entry in enumerate(standalone):
        where = f"readme-data.json standalone_findings[{index}]"
        require_fields(
            entry,
            [
                "project",
                "identifier",
                "severity",
                "class",
                "summary",
                "credit",
                "record_url",
            ],
            where,
        )
        if entry["severity"] not in SEV_LABEL:
            raise ValueError(f"{where}: unknown severity {entry['severity']!r}")
        validate_url(entry["record_url"], f"{where} record_url")
        for source_name in ("report", "fix"):
            source = entry.get(source_name) or {}
            require_fields(source, ["label", "url"], f"{where}.{source_name}")
            validate_url(source["url"], f"{where}.{source_name}")

    recognized_kinds = PATCH_KINDS | RECORD_KINDS
    for row_number, row in enumerate(upstream, start=2):
        where = f"upstream.csv:{row_number}"
        require_fields(
            row,
            ["project", "org", "kind", "credit_text", "what", "url", "verified"],
            where,
        )
        if row["kind"] not in recognized_kinds:
            raise ValueError(f"{where}: unhandled kind {row['kind']!r}")
        validate_url(row["url"], f"{where} url")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["verified"]):
            raise ValueError(f"{where}: malformed verified date {row['verified']!r}")
        reference_label = str(row.get("reference_label") or "").strip()
        reference_url = str(row.get("reference_url") or "").strip()
        if bool(reference_label) != bool(reference_url):
            raise ValueError(f"{where}: reference_label and reference_url must appear together")
        if reference_url:
            validate_url(reference_url, f"{where} reference_url")


def facts(rows):
    severity = collections.Counter(row["severity"] for row in rows)
    ecosystems = collections.Counter(row["ecosystem"] for row in rows)
    first_year, first_month, _ = min(row["published"] for row in rows).split("-")
    month_names = [
        "",
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    result = {
        "total": len(rows),
        "orgs": len({row["org"] for row in rows}),
        "cves": sum(1 for row in rows if row["cve"]),
        "sole": sum(1 for row in rows if row["sole_reporter"] == "yes"),
        "hicrit": severity["critical"] + severity["high"],
        "global_n": sum(
            1 for row in rows if "/security/advisories/" not in row["advisory_url"]
        ),
        "sev": severity,
        "eco": ecosystems,
        "start": f"{month_names[int(first_month)]} {first_year}",
    }
    result["repo_n"] = result["total"] - result["global_n"]
    return result


def md_cell(value):
    return (
        str(value or "")
        .strip()
        .replace("\r", "")
        .replace("\n", "<br>")
        .replace("|", "\\|")
    )


def md_label(value):
    return md_cell(value).replace("[", "\\[").replace("]", "\\]")


def md_link(label, url):
    return f"[{md_label(label)}]({url})"


def shield_slug(value):
    value = str(value).replace("-", "--").replace(" ", "_")
    return quote(value, safe="_-")


def badge(
    label,
    message,
    colour,
    target=None,
    *,
    style="flat-square",
    label_colour="24292f",
    logo=None,
    logo_colour="white",
):
    alt = f"{label} {message}".strip()
    params = [f"style={style}"]
    if label_colour:
        params.append(f"labelColor={label_colour}")
    if logo:
        params.extend([f"logo={quote(logo)}", f"logoColor={quote(logo_colour)}"])
    image = (
        f"![{md_label(alt)}](https://img.shields.io/badge/"
        f"{shield_slug(label)}-{shield_slug(message)}-{colour}?{'&'.join(params)})"
    )
    return f"[{image}]({target})" if target else image


def solid_badge(
    text,
    colour,
    target=None,
    *,
    style="flat-square",
    logo=None,
    logo_colour="white",
):
    params = [f"style={style}"]
    if logo:
        params.extend([f"logo={quote(logo)}", f"logoColor={quote(logo_colour)}"])
    image = (
        f"![{md_label(text)}](https://img.shields.io/badge/"
        f"{shield_slug(text)}-{colour}?{'&'.join(params)})"
    )
    return f"[{image}]({target})" if target else image


def record_badge(identifier, url):
    if identifier.startswith("CVE-"):
        return badge(
            "CVE",
            identifier.removeprefix("CVE-"),
            "e63946",
            url,
            label_colour="9b1c31",
        )
    if identifier.startswith("GHSA-"):
        return badge(
            "GHSA",
            identifier.removeprefix("GHSA-"),
            "8b5cf6",
            url,
            label_colour="5b21b6",
        )
    if identifier.lower().startswith("commit "):
        return badge(
            "COMMIT",
            identifier.split(" ", 1)[1],
            "2da44e",
            url,
            label_colour="166534",
        )
    return solid_badge(identifier, "0969da", url)


def identifier_badges(row):
    links = []
    if row["cve"]:
        links.append(record_badge(row["cve"], row["cve_url"]))
    links.append(record_badge(row["ghsa"], row["advisory_url"]))
    return " ".join(links)


def severity_badge(row):
    score = str(row.get("cvss") or "").strip()
    if not score:
        return solid_badge(SEV_LABEL[row["severity"]], SEV_BADGE[row["severity"]])
    return badge(
        SEV_LABEL[row["severity"]],
        score,
        SEV_BADGE[row["severity"]],
        label_colour=SEV_LABEL_BADGE[row["severity"]],
    )


def render_stat_badges(f):
    return "\n".join(
        badge(label, f[key], colour, target, style="for-the-badge")
        for label, key, colour, target in STAT_BADGES
    )


def render_search_scope(f):
    scope = (
        f"Published {f['start']}–present. "
        f"**{f['global_n']}** advisories are indexed in GitHub's global database "
        f"and **{f['repo_n']}** are repository-scoped and linked directly below."
    )
    searches = " ".join(
        [
            solid_badge(
                "global index",
                "0969da",
                "https://github.com/advisories?query=credit%3Akodareef5",
                logo="github",
            ),
            solid_badge(
                "critical",
                SEV_BADGE["critical"],
                "https://github.com/advisories?query=credit%3Akodareef5+severity%3Acritical",
            ),
            solid_badge(
                "high",
                SEV_BADGE["high"],
                "https://github.com/advisories?query=credit%3Akodareef5+severity%3Ahigh",
            ),
        ]
    )
    return f"{scope}\n\n{searches}"


def render_featured(config, by_ghsa):
    lines = ["| Finding | Mechanism and impact |", "|---|---|"]
    for ghsa in config["featured"]:
        row = by_ghsa[ghsa]
        finding = (
            f"**{md_link(row['repo'], row['advisory_url'])}**<br>"
            f"{severity_badge(row)} "
            f"{solid_badge(row['class'], '0f766e')}<br>"
            f"{identifier_badges(row)}"
        )
        detail = md_cell(row.get("tldr") or row["summary"])
        lines.append(f"| {finding} | {detail} |")
    return "\n".join(lines)


def render_mix_badges(counter, labels=None, colours=None, logos=None):
    labels = labels or {}
    colours = colours or {}
    logos = logos or {}
    keys = (
        [key for key in SEV_ORDER if key in counter]
        if labels
        else [key for key, _ in counter.most_common()]
    )
    badges = []
    for key in keys:
        label = labels.get(key, key)
        colour = colours.get(key, "6c757d")
        logo, logo_colour = logos.get(key, (None, "white"))
        badges.append(
            badge(
                label,
                counter[key],
                colour,
                logo=logo,
                logo_colour=logo_colour,
            )
        )
    return " ".join(badges)


def render_cwe_table(rows):
    official = json.loads(CWE_NAMES.read_text(encoding="utf-8")) if CWE_NAMES.exists() else {}
    counts = collections.Counter()
    cwe_rows = collections.defaultdict(list)
    for row in rows:
        for cwe in (row.get("cwe") or "").split(";"):
            if cwe:
                counts[cwe] += 1
                cwe_rows[cwe].append(row)

    lines = ["| Pattern | Seen in |", "|---|---|"]
    shown = 0
    repeated = 0
    for cwe, count in counts.most_common():
        if count < 2:
            continue
        number = cwe.split("-", 1)[1]
        description = CWE_PLAIN.get(cwe) or official.get(cwe, "")
        seen = set()
        projects = []
        for row in sorted(
            cwe_rows[cwe], key=lambda item: SEV_ORDER.index(item["severity"])
        ):
            if row["org"] in seen:
                continue
            seen.add(row["org"])
            label, colour, logo, logo_colour = META.get(
                row["org"], (row["org"], "6c757d", None, "white")
            )
            label = label.replace("_", " ").replace("--", "-")
            projects.append(
                solid_badge(
                    label,
                    colour,
                    row["advisory_url"],
                    logo=logo,
                    logo_colour=logo_colour,
                )
            )
        cwe_url = f"https://cwe.mitre.org/data/definitions/{number}.html"
        weakness = (
            f"{badge('CWE', number, 'd97706', cwe_url, label_colour='92400e')}"
            f"<br>{md_cell(description)}"
        )
        lines.append(f"| {weakness} | {' '.join(projects)} |")
        shown += 1
        repeated += count

    singles = sum(1 for count in counts.values() if count == 1)
    lines.append("")
    lines.append(
        f"{shown} recurring classes cover {repeated} of {sum(counts.values())} "
        f"classifications. {singles} more appear once; {len(counts)} distinct classes total."
    )
    return "\n".join(lines)


def render_org_badges(rows):
    by_org = collections.defaultdict(list)
    for row in rows:
        by_org[row["org"]].append(row)

    grouped = {org for _, organizations in DOMAINS for org in organizations}
    missing = set(by_org) - grouped
    unknown = grouped - set(by_org)
    if missing:
        raise ValueError(f"orgs in advisories.csv but not grouped in orgs.py: {sorted(missing)}")
    if unknown:
        print(f"  note: grouped orgs with no advisory: {sorted(unknown)}", file=sys.stderr)

    lines = ["| | |", "|---|---|"]
    for title, organizations in DOMAINS:
        present = [org for org in organizations if org in by_org]
        if not present:
            continue
        if len(present) < 5:
            raise ValueError(
                f"domain {title!r} has only {len(present)} orgs; merge it into another"
            )
        present.sort(
            key=lambda org: (
                min(SEV_ORDER.index(row["severity"]) for row in by_org[org]),
                -max(
                    (float(row["cvss"]) for row in by_org[org] if row["cvss"]),
                    default=0,
                ),
            )
        )
        badges = []
        for org in present:
            label, colour, logo, logo_colour = META[org]
            best = min(
                by_org[org],
                key=lambda row: (
                    SEV_ORDER.index(row["severity"]),
                    -float(row["cvss"] or 0),
                ),
            )
            logo_query = f"&logo={logo}&logoColor={logo_colour}" if logo else ""
            alt = label.replace("_", " ").replace("--", "-")
            badges.append(
                f"[![{alt}](https://img.shields.io/badge/{label}-{colour}"
                f"?style=for-the-badge{logo_query})]({best['advisory_url']})"
            )
        lines.append(f"| **{md_cell(title)}** | {' '.join(badges)} |")
    return "\n".join(lines)


def render_incomplete_fixes(config, by_ghsa):
    lines = ["| Finding | Earlier issue | What remained |", "|---|---|---|"]
    for entry in config["incomplete_fixes"]:
        row = by_ghsa[entry["advisory"]]
        finding = (
            f"**{md_link(row['repo'], row['advisory_url'])}**<br>"
            f"{identifier_badges(row)}"
        )
        predecessors = " ".join(
            record_badge(item["id"], item["url"]) for item in entry["predecessors"]
        )
        lines.append(
            f"| {finding} | {predecessors} | {md_cell(entry['relationship'])} |"
        )
    return "\n".join(lines)


def render_upstream_table(rows, colour):
    lines = ["| Project | Change | Record |", "|---|---|---|"]
    for row in rows:
        change = md_cell(row["what"])
        if row.get("reference_url"):
            change += (
                f"<br>{solid_badge(row['reference_label'], '64748b', row['reference_url'])}"
            )
        lines.append(
            f"| {solid_badge(row['project'], colour, row['url'])} | {change} | "
            f"{md_cell(row['credit_text'])} |"
        )
    return "\n".join(lines)


def render_upstream(upstream):
    patches = [row for row in upstream if row["kind"] in PATCH_KINDS]
    records = [row for row in upstream if row["kind"] in RECORD_KINDS]
    if len(patches) + len(records) != len(upstream):
        raise ValueError("not every upstream.csv row was assigned to a table")
    return (
        render_upstream_table(patches, "2da44e"),
        render_upstream_table(records, "0969da"),
    )


def render_coverage(config, by_ghsa):
    lines = ["| Finding | Sources |", "|---|---|"]
    for entry in config["coverage"]:
        row = by_ghsa[entry["advisory"]]
        finding = (
            f"**{md_link(row['repo'], row['advisory_url'])}**<br>"
            f"{identifier_badges(row)}"
        )
        sources = " ".join(
            solid_badge(source["label"], "0969da", source["url"])
            for source in entry["sources"]
        )
        lines.append(f"| {finding} | {sources} |")
    return "\n".join(lines)


def render_standalone(config):
    lines = ["| Finding | Detail |", "|---|---|"]
    for entry in config["standalone_findings"]:
        finding = (
            f"**{md_cell(entry['project'])}**<br>"
            f"{record_badge(entry['identifier'], entry['record_url'])}<br>"
            f"{solid_badge(SEV_LABEL[entry['severity']], SEV_BADGE[entry['severity']])} "
            f"{solid_badge(entry['class'], '0f766e')}"
        )
        sources = " ".join(
            [
                solid_badge(entry["report"]["label"], "0969da", entry["report"]["url"]),
                solid_badge(entry["fix"]["label"], "2da44e", entry["fix"]["url"]),
            ]
        )
        lines.append(
            f"| {finding} | {md_cell(entry['summary'])}<br>"
            f"{md_cell(entry['credit'])}<br>{sources} |"
        )
    return "\n".join(lines)


def render_advisory_ledger(rows):
    lines = []
    for severity in SEV_ORDER:
        section = sorted(
            (row for row in rows if row["severity"] == severity),
            key=lambda row: row["published"],
            reverse=True,
        )
        lines.append(f"### {SEV_LABEL[severity]} · {len(section)} findings")
        lines.append("")
        for row in section:
            score = str(row.get("cvss") or "").strip()
            score_badge = (
                badge(
                    "CVSS",
                    score,
                    SEV_BADGE[severity],
                    label_colour=SEV_LABEL_BADGE[severity],
                )
                if score
                else ""
            )
            identifiers = identifier_badges(row)
            if row.get("fix_pr"):
                repository, number = row["fix_pr"].rsplit("#", 1)
                identifiers += (
                    " "
                    + badge(
                        "PR",
                        f"#{number}",
                        "2da44e",
                        f"https://github.com/{repository}/pull/{number}",
                        label_colour="166534",
                    )
                )
            detail = md_cell(row.get("tldr") or row["summary"].strip().rstrip("."))
            record_line = " ".join(part for part in (score_badge, identifiers) if part)
            lines.append(
                f"- **{md_link(row['repo'], row['advisory_url'])}** "
                f"· **{md_cell(row['class'])}** · `{md_cell(row['published'])}`"
                f"<br>{detail}"
                f"<br>{record_line}"
            )
            lines.append("")
    return "\n".join(lines)


def render(rows, upstream, config, template):
    f = facts(rows)
    by_ghsa = {row["ghsa"]: row for row in rows}
    patches, upstream_records = render_upstream(upstream)

    replacements = {
        "FEATURED_FINDINGS": render_featured(config, by_ghsa),
        "STAT_BADGES": render_stat_badges(f),
        "SEARCH_SCOPE": render_search_scope(f),
        "ORG_BADGES": render_org_badges(rows),
        "SEVERITY_MIX": render_mix_badges(f["sev"], SEV_LABEL, SEV_BADGE),
        "ECOSYSTEM_MIX": render_mix_badges(f["eco"], colours=ECO_BADGE, logos=ECO_LOGO),
        "CWE_TABLE": render_cwe_table(rows),
        "INCOMPLETE_FIXES": render_incomplete_fixes(config, by_ghsa),
        "MERGED_PATCHES": patches,
        "UPSTREAM_RECORDS": upstream_records,
        "COVERAGE": render_coverage(config, by_ghsa),
        "STANDALONE_FINDINGS": render_standalone(config),
        "ADVISORY_LEDGER": render_advisory_ledger(rows),
    }

    found = re.findall(r"\{\{([A-Z_]+)\}\}", template)
    if collections.Counter(found) != collections.Counter(replacements.keys()):
        missing = sorted(set(replacements) - set(found))
        unknown = sorted(set(found) - set(replacements))
        repeated = sorted(name for name, count in collections.Counter(found).items() if count > 1)
        raise ValueError(
            f"README.tmpl.md placeholders: missing={missing}, unknown={unknown}, "
            f"repeated={repeated}"
        )

    output = template
    for name, value in replacements.items():
        output = output.replace("{{" + name + "}}", value)
    if re.search(r"\{\{[A-Z_]+\}\}", output):
        raise ValueError("README output contains unresolved placeholders")
    return output, f


def main():
    rows, upstream, config = load()
    output, f = render(rows, upstream, config, TMPL.read_text(encoding="utf-8"))
    check = "--check" in sys.argv
    if check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != output:
            print(
                "DRIFT: README.md does not match its structured inputs. "
                "Run ./build-readme.py",
                file=sys.stderr,
            )
            sys.exit(1)
        print("ok: README.md matches its structured inputs")
    else:
        OUT.write_text(output, encoding="utf-8")
        print(f"wrote {OUT.name}")
    print(
        f"  {f['total']} advisories · {f['orgs']} orgs · {f['cves']} CVEs · "
        f"{f['sole']} sole · {f['hicrit']} high/critical"
    )
    print(f"  {f['global_n']} in global DB · {f['repo_n']} repo-scoped")
    print(f"  {len(upstream)} upstream records · {len(config['standalone_findings'])} standalone")
    print("  severity: " + dict(f["sev"]).__repr__())
    print("  ecosystem: " + dict(f["eco"]).__repr__())


if __name__ == "__main__":
    main()
