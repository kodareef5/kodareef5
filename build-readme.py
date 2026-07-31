#!/usr/bin/env python3
"""Render README.md from advisories.csv. Every number on the page is derived.

advisories.csv is the single source of truth. README.tmpl.md holds the prose
with {{PLACEHOLDER}} markers. Nothing numeric is ever typed by hand — that is
what produced the 43 -> 50 -> 51 drift across live outreach emails.

  ./build-readme.py            render README.md
  ./build-readme.py --check    verify the committed README matches the data
                               (exit 1 on drift — use this in CI / pre-commit)

Refresh the data first with credit-sweep.sh, which finds repo-scoped advisories
that the global database and every user-level API cannot see.
"""
import csv, sys, json, collections, pathlib, re

from orgs import DOMAINS, META, CWE_PLAIN

HERE = pathlib.Path(__file__).parent
CSV = HERE / "advisories.csv"
CWE_NAMES = HERE / "cwe_names.json"
TMPL = HERE / "README.tmpl.md"
OUT = HERE / "README.md"

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
SEV_ORDER = ["critical", "high", "medium", "low"]
BADGE_COLOR = "8b0000"
# Hues chosen for separation, not convention: dark red -> red -> yellow -> grey.
# The previous palette put High on a red and Medium on an orange, which read as
# the same colour at a glance.
SEV_BADGE = {
    "critical": "7f0000",   # near-black maroon — unmistakable
    "high":     "e63946",   # clear red, obviously lighter than critical
    "medium":   "f4d35e",   # true yellow, no orange
    "low":      "adb5bd",   # light grey
}
# Setting labelColor == color makes the badge one solid block instead of the
# default grey-label/coloured-value split, so severity reads at a glance.
# Shields picks the text colour by luminance on its own — verified: #fff on
# 7f0000 and e63946, #333 on f4d35e and adb5bd — so no manual override needed.
ONES = "zero one two three four five six seven eight nine ten eleven twelve " \
       "thirteen fourteen fifteen sixteen seventeen eighteen nineteen".split()
TENS = {20: "twenty", 30: "thirty", 40: "forty", 50: "fifty",
        60: "sixty", 70: "seventy", 80: "eighty", 90: "ninety"}


def spell(n):
    """Spell a number the way the surrounding prose does ('forty-five')."""
    if n < 20:
        return ONES[n]
    t, o = divmod(n, 10)
    base = TENS[t * 10]
    return base if o == 0 else f"{base}-{ONES[o]}"


def bar(n, unit=1):
    return "`" + "█" * max(1, round(n / unit)) + "`"


def phrase(name):
    """Lowercase a class name for mid-sentence use, but never an acronym.
    'Authorization bypass' -> 'authorization bypass';  'SSRF' -> 'SSRF'."""
    head = name.split()[0]
    if head.isupper() and len(head) > 1:
        return name
    return name[0].lower() + name[1:]


def load():
    rows = list(csv.DictReader(open(CSV)))
    rows.sort(key=lambda r: r["published"], reverse=True)
    return rows


def facts(rows):
    sev = collections.Counter(r["severity"] for r in rows)
    eco = collections.Counter(r["ecosystem"] for r in rows)
    f = {
        "total": len(rows),
        "orgs": len({r["org"] for r in rows}),
        "cves": sum(1 for r in rows if r["cve"]),
        "sole": sum(1 for r in rows if r["sole_reporter"] == "yes"),
        "hicrit": sev["critical"] + sev["high"],
        # a global-database advisory lives at /advisories/GHSA-...; a repo-scoped
        # one lives at /<org>/<repo>/security/advisories/GHSA-... and is invisible
        # to the global search
        "global_n": sum(1 for r in rows if "/security/advisories/" not in r["advisory_url"]),
        "sev": sev, "eco": eco,
    }
    f["repo_n"] = f["total"] - f["global_n"]
    return f


def render(rows, tmpl):
    f = facts(rows)
    sev, eco = f["sev"], f["eco"]

    badges = "\n".join(
        f"![{label}](https://img.shields.io/badge/{slug}-{f[key]}-{BADGE_COLOR}?style=flat-square)"
        for label, slug, key in [
            ("advisories", "advisories", "total"),
            ("organizations", "organizations", "orgs"),
            ("CVEs", "CVEs", "cves"),
            ("sole reporter", "sole_reporter", "sole"),
            ("high or critical", "high_or_critical", "hicrit"),
        ])

    sev_tbl = ("| " + " | ".join(SEV_LABEL[s] for s in SEV_ORDER) + " |\n"
               + "|" + "|".join([":--:"] * 4) + "|\n"
               + "| " + " | ".join(str(sev[s]) for s in SEV_ORDER) + " |\n"
               + "| " + " | ".join(bar(sev[s]) for s in SEV_ORDER) + " |")

    ecos = [e for e, _ in eco.most_common()]
    eco_tbl = ("| " + " | ".join(ecos) + " |\n"
               + "|" + "|".join([":--:"] * len(ecos)) + "|\n"
               + "| " + " | ".join(str(eco[e]) for e in ecos) + " |\n"
               + "| " + " | ".join(bar(eco[e]) for e in ecos) + " |")

    # Three columns instead of six. The old layout smushed GHSA, CVE and date
    # into narrow cells; here the identifiers stack in one column and the
    # summary gets room to be a sentence.
    tbl = ["| Severity | Finding | Detail |", "|:--:|---|---|"]
    for r in rows:
        sev = SEV_LABEL[r["severity"]]
        colour = SEV_BADGE[r["severity"]]
        # two-part badge: severity as the label, CVSS as the value, so the
        # score lives in the colour column instead of crowding the middle one
        score = (r.get("cvss") or "").strip()
        if score:
            path, alt = f"{sev}-{score}-{colour}", f"{sev} {score}"
        else:
            path, alt = f"{sev}-{colour}", sev
        badge = (f"![{alt}](https://img.shields.io/badge/{path}"
                 f"?style=flat-square&labelColor={colour})")
        ids = f"[{r['ghsa']}]({r['advisory_url']})"
        if r["cve"]:
            ids += f" · [{r['cve']}]({r['cve_url']})"
        # reported it AND wrote the merged fix — the pairing that nothing else
        # on the page makes visible
        if r.get("fix_pr"):
            repo_pr, num = r["fix_pr"].rsplit("#", 1)
            ids += f" · fix [#{num}](https://github.com/{repo_pr}/pull/{num})"
        # Show the TL;DR only. The advisory's own summary is dropped: the TL;DR
        # already carries more (mechanism + preconditions), and stacking both
        # doubled the row height.
        tldr = (r.get("tldr") or "").strip() or r["summary"].strip().rstrip(".")
        detail = tldr.replace("|", "\\|")
        tbl.append(f"| {badge} | **{r['repo']}**<br>{r['class']}<br><sub>{r['published']}</sub> | "
                   f"{detail}<br><sub>{ids}</sub> |")

    # weakness table: id, plain-English gloss, and who it was found in
    official = json.loads(CWE_NAMES.read_text()) if CWE_NAMES.exists() else {}
    cwe = collections.Counter()
    cwe_orgs = collections.defaultdict(list)
    for r in rows:
        for c in (r.get("cwe") or "").split(";"):
            if c:
                cwe[c] += 1
                cwe_orgs[c].append(r)
    lines = ["| Weakness | | Found in |", "|---|---|---|"]
    shown = 0
    for c, n in cwe.most_common():
        if n < 2:
            continue          # singletons are noise in a summary table
        num = c.split("-")[1]
        desc = CWE_PLAIN.get(c) or official.get(c, "")
        seen, links = set(), []
        for r in sorted(cwe_orgs[c], key=lambda r: SEV_ORDER.index(r["severity"])):
            if r["org"] in seen:
                continue
            seen.add(r["org"])
            label = META.get(r["org"], (r["org"],))[0].replace("_", " ").replace("--", "-")
            links.append(f"[{label}]({r['advisory_url']})")
        lines.append(f"| [{c}](https://cwe.mitre.org/data/definitions/{num}.html) | "
                     f"{desc} | {' · '.join(links)} |")
        shown += 1
    singles = sum(1 for _, n in cwe.items() if n == 1)
    cwe_tbl = "\n".join(lines)
    cwe_tbl += (f"\n\nThe {shown} classes above account for {sum(n for _, n in cwe.most_common() if n >= 2)} "
                f"of {sum(cwe.values())} classifications; a further {singles} classes appear once each, "
                f"across {len(cwe)} distinct weaknesses in total.")

    # --- org badges, grouped by domain -------------------------------------
    # Grouping is editorial (orgs.py); membership and links are generated, so
    # a new org can never be silently dropped from the page.
    by_org = collections.defaultdict(list)
    for r in rows:
        by_org[r["org"]].append(r)
    grouped = {o for _, os_ in DOMAINS for o in os_}
    missing = set(by_org) - grouped
    unknown = grouped - set(by_org)
    assert not missing, f"orgs in CSV but not grouped in orgs.py: {sorted(missing)}"
    if unknown:
        print(f"  note: grouped orgs with no advisory: {sorted(unknown)}", file=sys.stderr)

    # One table row per domain. A grid keeps this compact; ten separate
    # headed sections read as confetti.
    MIN_DOMAIN = 5
    table_rows, badged_n = [], 0
    for title, members in DOMAINS:
        present = [o for o in members if o in by_org]
        if not present:
            continue
        assert len(present) >= MIN_DOMAIN, (
            f"domain {title!r} has only {len(present)} orgs — merge it into "
            f"another (minimum {MIN_DOMAIN})")
        # strongest finding first within each domain
        present.sort(key=lambda o: (
            min(SEV_ORDER.index(r["severity"]) for r in by_org[o]),
            -max((float(r["cvss"]) for r in by_org[o] if r["cvss"]), default=0)))
        cells = []
        for o in present:
            label, colour, logo, logo_col = META[o]
            best = min(by_org[o], key=lambda r: (SEV_ORDER.index(r["severity"]),
                                                 -float(r["cvss"] or 0)))
            logo_q = f"&logo={logo}&logoColor={logo_col}" if logo else ""
            cells.append(
                f"[![{label.replace('_', ' ').replace('--', '-')}]"
                f"(https://img.shields.io/badge/{label}-{colour}?style=for-the-badge{logo_q})]"
                f"({best['advisory_url']})")
            badged_n += 1
        table_rows.append(f"| **{title}** | {' '.join(cells)} |")
    org_badges = "| | |\n|---|---|\n" + "\n".join(table_rows)

    badged = badged_n

    out = tmpl
    for k, v in {
        "STAT_BADGES": badges,
        "GLOBAL_N": f"**{f['global_n']}**",
        "REPO_N": f"**{f['repo_n']}**",
        "SEVERITY_TABLE": sev_tbl,
        "ECOSYSTEM_TABLE": eco_tbl,
        "ADVISORY_TABLE": "\n".join(tbl),
        "TOTAL": str(f["total"]),
        "CWE_TABLE": cwe_tbl,
        "ORG_BADGES": org_badges,
        "FOOTER_STATS": (f"**{f['total']} advisories · {f['orgs']} organizations · "
                         f"{f['cves']} CVEs · {f['sole']} as sole reporter · "
                         f"{f['hicrit']} high or critical**"),
    }.items():
        out = out.replace("{{" + k + "}}", v)

    left = re.findall(r"\{\{[A-Z_]+\}\}", out)
    assert not left, f"unfilled placeholders: {left}"
    return out, f


def main():
    rows = load()
    out, f = render(rows, TMPL.read_text())
    check = "--check" in sys.argv
    if check:
        cur = OUT.read_text() if OUT.exists() else ""
        if cur != out:
            print("DRIFT: README.md does not match advisories.csv. Run ./build-readme.py",
                  file=sys.stderr)
            sys.exit(1)
        print("ok: README.md matches advisories.csv")
    else:
        OUT.write_text(out)
        print(f"wrote {OUT.name}")
    print(f"  {f['total']} advisories · {f['orgs']} orgs · {f['cves']} CVEs · "
          f"{f['sole']} sole · {f['hicrit']} high/critical")
    print(f"  {f['global_n']} in global DB · {f['repo_n']} repo-scoped")
    print("  severity: " + dict(f["sev"]).__repr__())
    print("  ecosystem: " + dict(f["eco"]).__repr__())


if __name__ == "__main__":
    main()
