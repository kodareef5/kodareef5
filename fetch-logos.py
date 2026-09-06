#!/usr/bin/env python3
"""Download unchanged official logo assets and record provenance/checksums.

Only explicit projects.json sources are fetched. This is an opt-in refresh, not
part of README generation. Logos retain their owners' trademark/license terms.
"""
import concurrent.futures
import datetime
import hashlib
import json
import pathlib
import re
import struct
import urllib.request
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent

def fetch(item):
    repo, project = item
    if not project.get("logo"):
        return
    logo = project["logo"]
    target = ROOT / logo["file"]
    if target.parent != ROOT / "assets/logos":
        raise ValueError("Logo target must be directly inside assets/logos")
    request = urllib.request.Request(logo["source"], headers={"User-Agent": "KodaReef-README-assets"})
    with urllib.request.urlopen(request, timeout=40) as response:
        content = response.read()
    if target.suffix == ".svg":
        root = ET.fromstring(content)
        if not root.tag.endswith("svg"):
            raise ValueError(f"Not SVG: {repo}")
        if b"<script" in content.lower():
            raise ValueError(f"Unexpected active content: {repo}")
        box = root.get("viewBox", "").replace(",", " ").split()
        if len(box) == 4:
            width, height = float(box[2]), float(box[3])
        else:
            width = float(re.sub("[^0-9.]", "", root.get("width", "24")))
            height = float(re.sub("[^0-9.]", "", root.get("height", "24")))
    elif content[:8] == b"\x89PNG\r\n\x1a\n":
        width, height = struct.unpack(">II", content[16:24])
    else:
        raise ValueError(f"Not a supported logo image: {repo}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    logo.update(sha256=hashlib.sha256(content).hexdigest(),
                verified=datetime.date.today().isoformat(),
                width=round(width), height=round(height))
    return repo

def main():
    path = ROOT / "projects.json"
    projects = json.loads(path.read_text())
    items = [(repo, {"logo": project[key]})
             for repo, project in projects.items()
             for key in ("logo", "logo_dark") if project.get(key)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        names = list(pool.map(fetch, items))
    path.write_text(json.dumps(projects, ensure_ascii=False, indent=2) + "\n")
    lines = ["# Project marks", "",
             "Unmodified assets from project repositories, official websites, and CNCF artwork.",
             "These marks identify the software; they do not imply affiliation or endorsement.",
             "Ownership and trademark/license terms remain with each project.",
             "Exact URLs, retrieval dates, dimensions, and SHA-256 hashes are in [projects.json](../../projects.json).",
             "", "| Project | Local asset | Source |", "|---|---|---|"]
    for repo, project in sorted(projects.items(), key=lambda x: x[1]["name"].casefold()):
        if project.get("logo"):
            logo = project["logo"]
            lines.append(f"| {project['name']} | [asset]({pathlib.Path(logo['file']).name}) | [official source]({logo['provenance']}) |")
        else:
            lines.append(f"| {project['name']} | Text only | [project]({project['url']}) |")
    (ROOT / "assets/logos/README.md").write_text("\n".join(lines) + "\n")
    print(f"Downloaded {len([n for n in names if n])} official marks.")

if __name__ == "__main__":
    main()
