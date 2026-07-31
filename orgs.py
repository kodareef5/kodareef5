"""Organization display metadata for the profile README badge section.

Keyed by the `org` column in advisories.csv. Each entry is:
    (display name, hex colour, simple-icons logo slug or None, logo colour)

Domain grouping is editorial — it is the one thing on the page that cannot be
derived from the data, because "what kind of software is this" is a judgement.
Everything else about the badges (which orgs appear, which advisory each links
to, the counts) is generated, so an org can never be silently dropped.

If a new org appears in the CSV and is missing here, build-readme.py raises
rather than quietly omitting it.
"""

DOMAINS = [
    ("Cloud native and orchestration",
     ["rancher", "cilium", "kata-containers", "tektoncd", "projectcontour",
      "external-secrets", "open-telemetry"]),
    ("Supply chain and packaging",
     ["in-toto", "composer", "sigstore", "theupdateframework", "go-git",
      "GitoxideLabs", "python-poetry"]),
    ("Identity and access",
     ["zitadel", "goauthentik", "authorizerdev", "oauth2-proxy", "pocket-id"]),
    ("Data, AI and parsers",
     ["dgraph-io", "nasa", "bentoml", "Giskard-AI", "rustfs", "filebrowser",
      "py-pdf", "strukturag"]),
    ("Web, proxy and applications",
     ["nats-io", "traefik", "statamic", "coollabsio", "OneUptime", "activepieces",
      "novuhq", "freescout-help-desk", "wekan", "siyuan-note", "henrygd",
      "pyload", "gotenberg", "withastro", "cure53", "WWBN", "StableLib",
      "phpseclib", "charmbracelet"]),
]

META = {
    "rancher":            ("Rancher",          "0075A8", "rancher",       "white"),
    "cilium":             ("Cilium",           "F8C517", "cilium",        "black"),
    "kata-containers":    ("Kata_Containers",  "1E2761", None,            "white"),
    "tektoncd":           ("Tekton",           "42A5F5", "tekton",        "white"),
    "projectcontour":     ("Contour",          "483D8B", None,            "white"),
    "external-secrets":   ("External_Secrets", "326CE5", "kubernetes",    "white"),
    "open-telemetry":     ("OpenTelemetry",    "425CC7", "opentelemetry", "white"),

    "in-toto":            ("in--toto",         "6E4C9E", None,            "white"),
    "composer":           ("Composer",         "885630", "composer",      "white"),
    # no simple-icons slug exists for sigstore — verified 2026-07-30 by
    # comparing the rendered SVG against a deliberately bogus slug. Requesting
    # logo=sigstore silently produces a logo-less badge, so don't ask for one.
    "sigstore":           ("Sigstore",         "003366", None,            "white"),
    "theupdateframework": ("python--tuf",      "3776AB", "python",        "white"),
    "go-git":             ("go--git",          "00ADD8", "go",            "white"),
    "GitoxideLabs":       ("gitoxide",         "CE422B", "rust",          "white"),
    "python-poetry":      ("Poetry",           "60A5FA", "poetry",        "white"),

    "zitadel":            ("ZITADEL",          "3AB8BF", None,            "white"),
    "goauthentik":        ("authentik",        "FD4B2D", "authentik",     "white"),
    "authorizerdev":      ("Authorizer",       "3B82F6", None,            "white"),
    "oauth2-proxy":       ("oauth2--proxy",    "4B32C3", None,            "white"),
    "pocket-id":          ("Pocket_ID",        "0F172A", None,            "white"),

    "dgraph-io":          ("Dgraph",           "E50695", None,            "white"),
    "rustfs":             ("RustFS",           "CE422B", "rust",          "white"),
    "filebrowser":        ("File_Browser",     "455A64", None,            "white"),
    "py-pdf":             ("pypdf",            "3776AB", "python",        "white"),
    "strukturag":         ("libheif",          "5C6BC0", None,            "white"),

    "bentoml":            ("BentoML",          "000000", None,            "white"),
    "Giskard-AI":         ("Giskard",          "6D28D9", None,            "white"),

    "traefik":            ("Traefik",          "24A1C1", "traefikproxy",  "white"),
    "nats-io":            ("NATS",             "27AAE1", "natsdotio",     "white"),

    "StableLib":          ("StableLib",        "1B5E20", None,            "white"),
    "phpseclib":          ("phpseclib",        "777BB4", "php",           "white"),

    "statamic":           ("Statamic",         "FF269E", "statamic",      "white"),
    "withastro":          ("Astro",            "BC52EE", "astro",         "white"),
    "cure53":             ("DOMPurify",        "CC0000", None,            "white"),
    "WWBN":               ("AVideo",           "E53935", None,            "white"),

    "coollabsio":         ("Coolify",          "8B5CF6", None,            "white"),
    "OneUptime":          ("OneUptime",        "000000", None,            "white"),
    "activepieces":       ("Activepieces",     "6E41E2", None,            "white"),
    "novuhq":             ("Novu",             "FF4757", None,            "white"),
    "freescout-help-desk":("FreeScout",        "00A8E8", None,            "white"),
    "wekan":              ("Wekan",            "1565C0", None,            "white"),
    "siyuan-note":        ("SiYuan",           "D23F31", None,            "white"),
    "henrygd":            ("Beszel",           "0EA5E9", None,            "white"),
    "pyload":             ("pyLoad",           "4A90D9", None,            "white"),
    "gotenberg":          ("Gotenberg",        "546E7A", None,            "white"),
    "charmbracelet":      ("Soft_Serve",       "FF5FD1", None,            "white"),

    "nasa":               ("NASA",             "0B3D91", "nasa",          "white"),
}


# Plain-English gloss for the weakness table. MITRE's official names are
# accurate but unreadable ("Improper Limitation of a Pathname to a Restricted
# Directory"); these are what a human would actually say. Anything not listed
# falls back to the official name from the advisory metadata.
CWE_PLAIN = {
    "CWE-863": "Authorization check exists but is wrong",
    "CWE-918": "Server-side request forgery",
    "CWE-862": "Authorization check missing entirely",
    "CWE-22":  "Path traversal",
    "CWE-287": "Authentication can be bypassed",
    "CWE-296": "Certificate chain not properly followed",
    "CWE-78":  "OS command injection",
    "CWE-178": "Case sensitivity mishandled",
    "CWE-200": "Sensitive information exposed",
    "CWE-208": "Timing side channel",
    "CWE-20":  "Input not validated",
    "CWE-59":  "Symlink followed before file access",
    "CWE-285": "Improper authorization",
    "CWE-613": "Session or token outlives its validity",
    "CWE-94":  "Code injection",
    "CWE-77":  "Command injection",
    "CWE-352": "Cross-site request forgery",
    "CWE-601": "Open redirect",
    "CWE-1333":"Regex denial of service",
    "CWE-400": "Uncontrolled resource consumption",
    "CWE-770": "Allocation without limits",
    "CWE-116": "Output not escaped",
    "CWE-79":  "Cross-site scripting",
    "CWE-89":  "SQL injection",
    "CWE-125": "Out-of-bounds read",
    "CWE-190": "Integer overflow",
    "CWE-269": "Privilege management error",
    "CWE-306": "Authentication missing for critical function",
    "CWE-434": "Unrestricted file upload",
    "CWE-444": "HTTP request smuggling",
    "CWE-471": "Modification of assumed-immutable data",
    "CWE-347": "Signature not properly verified",
    "CWE-330": "Insufficiently random values",
    "CWE-522": "Credentials insufficiently protected",
    "CWE-1288":"Improper validation of specified type of input",
}
