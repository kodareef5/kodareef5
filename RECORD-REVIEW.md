# Record refresh — 2026-09-06

## Factual changes

- Refreshed the private advisory pipeline, then exported only published,
  allowlisted fields: 70 repository advisories with structured credit.
- Added Flowise GHSA-9cvr-5wv9-2gxr, Nango GHSA-2j37-g5f6-h55p, and
  Envoy GHSA-jp5f-qr64-c9vw. Added F5 CVE-2026-77180 as a standalone
  NGINX Ingress Controller finding, distinct from NGINX.
- Added CNA-confirmed gitoxide mappings CVE-2026-82253 and CVE-2026-82254.
- Reclassified Vim as authored work. Added bitbang-cli PR 12 and
  bitbang-server PR 2; 28 upstream records now include 12 authored patches.
- Repository publication dates replace mixed repository/global dates.
  Global indexing is a verified lookup (47 found), not a URL-shape heuristic.
  Merge dates come from merged_at, not PR creation or verification dates.
- Maintainer severity is primary. Seven alternative global labels are retained.
  Structured CVSS v3/v4 scores retain version, vector and source; missing scores
  stay missing rather than borrowing proposed numbers from description prose.
- Contributor names and roles remain available; the sole-reporter metric is gone.
- Repository, GitHub-global and CNA package/version statements remain separate.
  In particular, gitoxide's gix 0.82.0 versus 0.83.0 fix disagreement is visible.
- Reviewed all 70 visible summaries. Corrected External Secrets DNS egress,
  Beszel's two identifier prerequisites, Statamic's API configuration conditions,
  KubePi's conditional impact, and Prefect's sparse-checkout arguments.
- Added eight follow-up relationships. Coolify is labeled related work, not an
  asserted bypass of the identical patched path.
- Linked exact jsrsasign and NATS releases. Preserved prior source links.
  Added the August 31 HackerNoon article only to the corresponding Activepieces
  finding, not the other findings discussed in that article.

## Verification limits

The September 6 CVE-list lookup returned 404 for five advisory-supplied IDs:
CVE-2026-35511, CVE-2026-77308, CVE-2026-55701, CVE-2026-9316 and
CVE-2026-73549. The last two belong to newly added advisories. These IDs
remain attributed to the published advisories, not independently verified CVE
records. Missing records are not evidence that the advisory or assignment is invalid.

The Lyrie coverage page could not be retrieved. Its link is retained with an
unavailable-source note, without advancing a successful verification date.

Dates not established for an upstream acknowledgement remain blank; a verification
date is never presented as a publication date. Apache's authored patch landed
under another committer and explicitly credits Koda Reef as submitter.

## Reproduction

The private worklog's sync-advisories.sh preserves failed/unsampled repository
records without changing their check dates. Its export wrapper invokes this
repository's sync-records.py with an explicit public-field allowlist.

Offline:

```sh
python3 sync-records.py --check
python3 -m unittest discover -v
./build-readme.py --check
python3 -m py_compile *.py
```

advisory-sources.json and standalone-sources.json retain published API/CNA facts.
readme-data.json owns authored summaries and relationships, not synced ratings.
upstream.csv records contributions with explicit project and advisory associations.
No private evidence or unpublished record is included.
