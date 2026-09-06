# Catalogue design

This design is promoted to public `main`, with GNOME GLib kept text-only pending
logo permission. The private logo preview remains on `readme-catalog-preview`
at `5d380bd`; the earlier layout remains on `readme-cleanup-preview` at `6ab7459`.
The former public profile is preserved in history at `d1e7730`.

## Design

- Centered, static introduction with direct jumps to projects, work, and notes.
- An open gallery of larger official marks with names underneath. No keycap-style
  buttons. The generated label tiles embed the existing, unmodified logo bytes;
  theme-specific labels and existing dark variants are included.
- Ordinary text links for projects without a suitable mark.
- A–Z navigation and letter sections, preserving alphabetical project order.
- Bordered project panels: identity in the header, identifiers/date/severity in
  a metadata row, and the description in a merged row spanning both columns.
  A GitHub-compatible cell width hint keeps short panels full-width too; the
  table still shrinks to the available space on phones.
- All short descriptions remain visible. Longer source details still expand
  within the project. Advisory-linked patches stay with their finding.
- Same factual data, contributor roles, source notes, coverage, and records as the
  previous preview. This is a presentation experiment, not another source refresh.

## Verification

20 tests cover source and record preservation, reference validation, automatic
new-project handling, markup escaping, wide description rows, unchanged embedded
logos, parent-mark/project identity, the public GLib text-only presentation,
and stale gallery detection.

README and advisory-export checks pass; Python compilation passes.
The GitHub-rendered layout is checked in light/dark themes at desktop
(1120×1000) and phone (390×844 and 320×800) widths, including expanded source
details. All 73 collapsed panels and their description rows fill the README
content width. Expanding details leaves no undersized panels or page-wide
overflow; wide package/source tables retain their existing internal scrolling.

The larger gallery intentionally takes more room. A Work link appears before it
so readers can skip directly to the ledger.
