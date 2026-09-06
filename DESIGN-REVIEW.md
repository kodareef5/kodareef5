# README design review — 2026-09-06

The README is now the complete project ledger: 73 alphabetical project sections,
70 structured-credit GitHub advisories, 28 upstream records (including 12
authored patches), and two standalone vendor/CVE findings.

- Static name and one-line introduction; no banner, animated header, testimonials,
  class badges, repeated highlights, or hiring language.
- Locally stored official marks with readable project names. GitHub-native
  compact link containers keep each mark attached to its name while wrapping.
  Text-only fallbacks are deliberate. Theme variants are used where available.
- Newest dated work first within each project; undated acknowledgements last.
  Short descriptions stay visible. Credits, versions, ratings, follow-ups and
  coverage expand under their own project.
- Independent advisory distributions live in expandable bottom notes.
  Contributor roles remain visible without a sole-reporter metric.

## Checks

- 14 automated tests pass, including original-source-link preservation,
  reference validation, source disagreements, standalone exclusions, multiple
  package fixes, contributor roles, Markdown escaping and a future-project test.
- README and advisory-export checks pass; all Python files compile.
- GitHub's Markdown renderer and GitHub's stylesheets were inspected in Chromium
  at 1120×1000 and 390×844, in light and dark themes.
- All 73 project anchors resolve, all displayed images load, and expanding every
  detail section produces no page-wide horizontal overflow.
- The index fits above the work section on desktop. The complete index requires
  a short scroll on phone widths; no projects are hidden to shorten it.

Only the existing private preview branch is published for review. Public-profile
promotion is a separate step. Source verification limits remain in RECORD-REVIEW.md.
