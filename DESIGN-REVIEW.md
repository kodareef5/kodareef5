# Catalogue design preview

This alternative lives on `readme-catalog-preview`. The previous design remains
unchanged on `readme-cleanup-preview` at `6ab7459`; public `main` is untouched.

## Design

- Centered, static introduction with direct jumps to projects, work, and notes.
- An open gallery of larger official marks with names underneath. No keycap-style
  buttons. The generated label tiles embed the existing, unmodified logo bytes;
  theme-specific labels and existing dark variants are included.
- Ordinary text links for projects without a suitable mark.
- A–Z navigation and letter sections, preserving alphabetical project order.
- Bordered project panels: identity in the header, identifiers/date/severity in
  a metadata row, and the description in a merged row spanning both columns.
- All short descriptions remain visible. Longer source details still expand
  within the project. Advisory-linked patches stay with their finding.
- Same factual data, contributor roles, source notes, coverage, and records as the
  previous preview. This is a presentation experiment, not another source refresh.

## Verification

17 tests cover source and record preservation, reference validation, automatic
new-project handling, markup escaping, wide description rows, unchanged embedded
logos, and stale gallery detection.

README and advisory-export checks pass; Python compilation passes.
The GitHub-rendered layout is checked in light/dark themes at desktop
(1120×1000) and phone (390×844) widths, including expanded source details.

The larger gallery intentionally takes more room. A Work link appears before it
so readers can skip directly to the ledger.
