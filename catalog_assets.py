"""Code-native gallery labels built around the unmodified official logo files.

No logos are redrawn or recolored. Each tile embeds the original file and adds
a readable name. Light/dark variants keep the same layout. Everything is local.
"""
import base64
import html
import pathlib
import re
import textwrap

ROOT = pathlib.Path(__file__).resolve().parent
WIDTH, HEIGHT = 112, 76


def stem(project_id):
    return re.sub(r"[^a-z0-9]+", "-", project_id.lower()).strip("-")


def label_lines(name):
    return textwrap.wrap(name, width=17, break_long_words=False, break_on_hyphens=True)


def tile(project, theme):
    item = project.get("logo_dark", project["logo"]) if theme == "dark" else project["logo"]
    path = ROOT / item["file"]
    mime = "image/svg+xml" if path.suffix == ".svg" else "image/png"
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    ratio = item["width"] / item["height"]
    width = min(76, 32 * ratio)
    height = width / ratio
    x, y = (WIDTH - width) / 2, 4 + (32 - height) / 2
    color = "#58a6ff" if theme == "dark" else "#0969da"
    labels = label_lines(project["name"])
    if len(labels) > 2:
        raise ValueError(f"Gallery name needs shorter display text: {project['name']}")
    text = "".join(
        f'<text x="{WIDTH / 2:g}" y="{53 + i * 16}" text-anchor="middle">{html.escape(line)}</text>'
        for i, line in enumerate(labels))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}">'
        f'<title>{html.escape(project["name"])}</title>'
        f'<image x="{x:g}" y="{y:g}" width="{width:g}" height="{height:g}" href="data:{mime};base64,{data}"/>'
        f'<g fill="{color}" font-family="Arial,Helvetica,sans-serif" font-size="13">{text}</g></svg>\n'
    )


def paths(project_id):
    return {theme: f"assets/catalog/{stem(project_id)}-{theme}.svg" for theme in ("light", "dark")}


def generated(projects):
    output = {}
    for project_id, project in projects.items():
        if project.get("logo") and not project.get("text_only"):
            for theme, path in paths(project_id).items():
                output[path] = tile(project, theme)
    return output


def sync(projects, check=False):
    for name, content in generated(projects).items():
        path = ROOT / name
        if check:
            if not path.exists() or path.read_text() != content:
                raise ValueError(f"Stale gallery asset: {name}; run ./build-readme.py")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
