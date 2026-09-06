#!/usr/bin/env python3
"""Refresh published source snapshots, or rebuild the CSV offline.

python3 sync-records.py --source /path/to/private/data/advisories.json --refresh
python3 sync-records.py                 # reproduce CSV from committed snapshots

Only explicitly allowlisted fields of state=published records cross the export
boundary. Raw private records and advisory correspondence are never copied.
Repository severity/publication are canonical; global and CNA facts stay separate.
"""
import argparse
import concurrent.futures
import csv
import datetime
import json
import pathlib
import subprocess
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
FIELDS = ["ghsa", "cve", "severity", "cvss", "cvss_version", "cvss_source",
          "published", "global_published", "globally_indexed", "repo", "project_id",
          "org", "role", "co_credited", "summary", "advisory_url", "cve_url",
          "class", "ecosystem", "cwe", "last_checked", "tldr", "fixed_in", "fix_pr"]


def gh(path):
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if result.returncode:
        if "HTTP 404" in result.stderr:
            return None
        raise RuntimeError(f"GitHub lookup failed: {path}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def cve_url(identifier):
    number = identifier.rsplit("-", 1)[1]
    bucket = number[:-3] + "xxx" if len(number) > 3 else "0xxx"
    return f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{identifier.split('-')[1]}/{bucket}/{identifier}.json"


def get_cve(identifier):
    url = cve_url(identifier)
    try:
        with urllib.request.urlopen(url, timeout=40) as response:
            raw = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        return {"status": "not_found", "url": url}
    cna = raw["containers"]["cna"]
    return {"status": "found", "url": url, "record": {
        "metadata": raw["cveMetadata"],
        **{key: cna.get(key) for key in
           ("providerMetadata", "title", "descriptions", "affected", "metrics",
            "credits", "references", "datePublic", "problemTypes")}
    }}


def public_repository(record):
    if record.get("state") != "published":
        raise ValueError("Only published advisories may be exported")
    if not record.get("checked_at"):
        raise ValueError(f"Missing successful source check: {record['ghsa']}")
    return {key: record.get(key) for key in (
        "ghsa", "repo", "state", "url", "severity", "cve", "summary",
        "description", "published", "updated", "withdrawn", "cwes",
        "cvss_details", "cvss_severities", "credits", "vulnerabilities", "checked_at")}


def refresh(source, config, existing):
    raw = json.loads(source.read_text())
    published = [public_repository(r) for r in raw if r.get("state") == "published"]
    ids = [r["ghsa"] for r in published]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate source advisories")
    for section in ("advisory_details", "cve_mappings"):
        if set(config.get(section, {})) - set(ids):
            raise ValueError(f"{section}: unknown advisory references")
    if not set(existing).issubset(ids):
        raise ValueError("Previously exported advisory missing or no longer public; review before removal")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    def enrich(repo):
        identifier = repo["ghsa"]
        global_record = gh(f"advisories/{identifier}")
        global_data = {"status": "found" if global_record else "not_found", "checked_at": now}
        if global_record:
            global_data["record"] = {key: global_record.get(key) for key in (
                "ghsa_id", "cve_id", "severity", "cvss", "cvss_severities",
                "published_at", "updated_at", "withdrawn_at", "credits", "cwes",
                "vulnerabilities", "html_url", "repository_advisory_url", "summary")}
        cve = repo.get("cve") or (global_record or {}).get("cve_id") or config.get("cve_mappings", {}).get(identifier)
        cna = get_cve(cve) if cve else {"status": "not_assigned"}
        if identifier in config.get("cve_mappings", {}) and cna["status"] == "found":
            if not any(identifier in ref.get("url", "") for ref in cna["record"].get("references") or []):
                raise ValueError(f"CNA record does not corroborate mapping for {identifier}")
        cna["checked_at"] = now
        return {"ghsa": identifier, "repository": repo, "global": global_data,
                "cve": {"identifier": cve, **cna}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(enrich, published))
    return {"schema_version": 1, "advisories": sorted(records, key=lambda r: r["ghsa"])}


def scores(source):
    """Structured published scores only, never proposed values in body prose."""
    result = []
    for key in ("cvss_v4", "cvss_v3"):
        value = (source.get("cvss_severities") or {}).get(key) or {}
        if value.get("score") is not None:
            vector = value.get("vector_string") or ""
            version = vector.split("/")[0].removeprefix("CVSS:") if vector else ("4.0" if key == "cvss_v4" else "3.x")
            result.append({"score": value["score"], "version": version, "vector": vector})
    value = source.get("cvss_details") or source.get("cvss") or {}
    if isinstance(value, dict) and value.get("score") is not None:
        vector = value.get("vector_string") or ""
        entry = {"score": value["score"], "version": vector.split("/")[0].removeprefix("CVSS:") if vector else "unspecified", "vector": vector}
        if entry not in result:
            result.append(entry)
    return result


def cna_scores(source):
    result = []
    for metric in source.get("metrics") or []:
        for key, value in metric.items():
            if key.startswith("cvssV") and isinstance(value, dict):
                result.append({"score": value["baseScore"], "version": value["version"],
                               "vector": value.get("vectorString", "")})
    return sorted(result, key=lambda r: r["version"], reverse=True)


def primary_score(record):
    for name, values in (
        ("maintainer advisory", scores(record["repository"])),
        ("GitHub global database", scores(record["global"].get("record", {}))),
        ("CVE CNA record", cna_scores(record["cve"].get("record", {})))):
        if values:
            return {**values[0], "source": name}
    return {"score": "", "version": "", "source": ""}


def csv_rows(snapshot, config):
    result = []
    for record in snapshot["advisories"]:
        repo = record["repository"]
        if repo.get("state") != "published":
            raise ValueError("Non-public record in export")
        editorial = config.get("advisory_details", {}).get(record["ghsa"], {})
        score = primary_score(record)
        credits = repo.get("credits") or []
        packages = repo.get("vulnerabilities") or []
        fixes = [f"{p['package']['name']}: {p['patched_versions']}"
                 for p in packages if p.get("patched_versions")]
        identifier = record["cve"]["identifier"] or ""
        result.append(dict(
            ghsa=record["ghsa"], cve=identifier, severity=repo["severity"],
            cvss=score["score"], cvss_version=score["version"], cvss_source=score["source"],
            published=(repo["published"] or "")[:10],
            global_published=(record["global"].get("record", {}).get("published_at") or "")[:10],
            globally_indexed="yes" if record["global"]["status"] == "found" else "no",
            repo=repo["repo"], project_id=repo["repo"], org=repo["repo"].split("/")[0],
            role=";".join(c["type"] for c in credits if c["login"] == "kodareef5"),
            co_credited=";".join(f"{c['login']} ({c['type']})" for c in credits if c["login"] != "kodareef5"),
            summary=repo["summary"], advisory_url=repo["url"],
            cve_url=f"https://www.cve.org/CVERecord?id={identifier}" if identifier else "",
            **{"class": editorial.get("class", "")},
            ecosystem=editorial.get("ecosystem", ""),
            cwe=";".join(repo.get("cwes") or []),
            last_checked=repo["checked_at"][:10],
            tldr=editorial.get("summary") or repo["summary"],
            fixed_in="; ".join(fixes), fix_pr=editorial.get("fix_pr", "")))
    return sorted(result, key=lambda r: (r["published"], r["ghsa"]), reverse=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=pathlib.Path)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config = json.loads((HERE / "readme-data.json").read_text())
    path = HERE / "advisory-sources.json"
    if args.refresh:
        if args.check or not args.source:
            parser.error("--refresh requires --source and cannot use --check")
        old = json.loads(path.read_text())["advisories"] if path.exists() else []
        snapshot = refresh(args.source, config, [r["ghsa"] for r in old])
        standalone = {"records": [
            {"identifier": r["identifier"], "checked": datetime.date.today().isoformat(),
             **get_cve(r["identifier"])} for r in config["standalone_findings"]]}
        if any(r["status"] != "found" for r in standalone["records"]):
            raise SystemExit("Standalone CVE verification failed; existing export preserved")
    else:
        snapshot = json.loads(path.read_text())
    import io
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(csv_rows(snapshot, config))
    csv_path = HERE / "advisories.csv"
    if args.check:
        if csv_path.read_text() != output.getvalue():
            raise SystemExit("advisories.csv is stale; run python3 sync-records.py")
        print("Advisory export is current.")
        return
    if args.refresh:
        path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n")
        (HERE / "standalone-sources.json").write_text(
            json.dumps(standalone, ensure_ascii=False, indent=2) + "\n")
    csv_path.write_text(output.getvalue())
    print(f"Exported {len(snapshot['advisories'])} published advisory records.")


if __name__ == "__main__":
    main()
