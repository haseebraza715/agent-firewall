#!/usr/bin/env python3
"""Make a svg-term recording render identically outside macOS.

svg-term emits each terminal run as a single <text> element positioned at a
column offset, then relies on the viewer's font to advance exactly one cell per
character. It hardcodes `font-family="Monaco,Consolas,Menlo,..."`, none of which
exist on the Linux renderers that serve GitHub READMEs, so the fallback font
decides the spacing. Any font whose advance width is not 0.6 x font-size drifts,
and column-aligned output (the decision table, the indented reasons) shears
apart.

This script pins the geometry instead of hoping for a font:

* every <text> run gets textLength set to (characters x cell width) with
  lengthAdjust="spacing", so the run occupies exactly its cells in any font;
* the font stack gains families that actually ship on Linux and Windows.

Usage: polish-demo-svg.py FILE [FILE ...]  (edits in place)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Families that exist on the platforms that render GitHub READMEs, ordered from
# best to most generic. The original macOS-only stack is kept as a prefix.
FONT_STACK = (
    "ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"
    "&apos;DejaVu Sans Mono&apos;,&apos;Liberation Mono&apos;,"
    "&apos;Noto Sans Mono&apos;,&apos;Courier New&apos;,monospace"
)

TEXT_RE = re.compile(r"<text\b([^>]*?)(/?)>([^<]*)</text>")
XML_ENTITIES = {
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&#39;": "'",
}


def cell_width(svg: str) -> float:
    """Recover the per-column advance svg-term used, in viewBox units.

    font-size is emitted as 0.6 x the cell width, which is the assumption this
    script exists to stop relying on at render time.
    """
    match = re.search(r'font-size="([\d.]+)"', svg)
    if not match:
        raise SystemExit("error: no font-size found; is this a svg-term output?")
    return float(match.group(1)) * 0.6


def visible_length(text: str) -> int:
    """Character count as the terminal counted it, not as XML spells it."""
    for entity, char in XML_ENTITIES.items():
        text = text.replace(entity, char)
    return len(text)


def pin_run(match: re.Match[str], advance: float, pinned: list[int]) -> str:
    attrs, self_closing, text = match.group(1), match.group(2), match.group(3)
    count = visible_length(text)
    if not count or "textLength" in attrs:
        return match.group(0)
    width = round(count * advance, 4)
    pinned.append(1)
    return (
        f'<text{attrs} textLength="{width}" lengthAdjust="spacing"'
        f"{self_closing}>{text}</text>"
    )


def polish(path: Path) -> tuple[int, int]:
    """Pin an svg-term output in place. Returns (runs pinned, fonts rewritten).

    Re-running on an already-pinned file is a no-op, so the recorder can call
    it unconditionally.
    """
    svg = path.read_text(encoding="utf-8")
    advance = cell_width(svg)
    pinned: list[int] = []

    fonts = 0
    if FONT_STACK not in svg:
        svg, fonts = re.subn(
            r'font-family="[^"]*"',
            f'font-family="{FONT_STACK}"',
            svg,
        )
    svg = TEXT_RE.sub(lambda m: pin_run(m, advance, pinned), svg)

    path.write_text(svg, encoding="utf-8")
    return len(pinned), fonts


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    for name in argv:
        path = Path(name)
        runs, fonts = polish(path)
        print(f"{path}: pinned {runs} text runs, rewrote {fonts} font stack(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
