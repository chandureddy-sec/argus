"""A small, dependency-light PDF writer for ThreatLens documents (case
reports, intelligence products).

Callers describe a document as a list of blocks; this module lays them out
with fpdf2 and the bundled Inter font (SIL OFL, ``fonts/OFL-Inter.txt``).
Every page carries the TLP marking at the top and the page number at the
bottom, so a printed page can't lose its marking.

Feed text is untrusted: it is written as plain text (fpdf2's markdown and
HTML modes are never used), control characters are dropped and very long
unbroken tokens are split so a hostile value cannot push content off the page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

FONT_DIR = Path(__file__).parent / "fonts"
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_LONG = re.compile(r"(\S{60})(?=\S)")

# Ink colours per TLP 2.0 (FIRST's palette, on white paper).
TLP_RGB: dict[str, tuple[int, int, int]] = {
    "TLP:CLEAR": (60, 60, 60),
    "TLP:GREEN": (51, 160, 44),
    "TLP:AMBER": (204, 136, 0),
    "TLP:AMBER+STRICT": (204, 136, 0),
    "TLP:RED": (204, 0, 51),
}


def clean(text: object, limit: int = 20_000) -> str:
    """Plain, printable text: no control/bidi characters, long tokens broken."""
    s = _CTRL.sub("", str(text if text is not None else ""))[:limit]
    return _LONG.sub(r"\1 ", s)


@dataclass
class Block:
    kind: Literal["h1", "h2", "p", "small", "bullets", "kv", "table", "rule"]
    text: str = ""
    items: list[str] = field(default_factory=list)
    pairs: list[tuple[str, str]] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    widths: list[int] = field(default_factory=list)  # relative column widths


def h1(t: str) -> Block:
    return Block("h1", text=t)


def h2(t: str) -> Block:
    return Block("h2", text=t)


def p(t: str) -> Block:
    return Block("p", text=t)


def small(t: str) -> Block:
    return Block("small", text=t)


def bullets(items: list[str]) -> Block:
    return Block("bullets", items=items)


def kv(pairs: list[tuple[str, str]]) -> Block:
    return Block("kv", pairs=pairs)


def table(headers: list[str], rows: list[list[str]], widths: list[int] | None = None) -> Block:
    return Block("table", headers=headers, rows=rows, widths=widths or [])


def rule() -> Block:
    return Block("rule")


class _Doc(FPDF):
    def __init__(self, title: str, marking: str, product: str) -> None:
        super().__init__(orientation="portrait", unit="mm", format="A4")
        self.doc_title = clean(title, 200)
        self.marking = marking
        self.product = product
        self.add_font("Inter", "", str(FONT_DIR / "Inter-Regular.ttf"))
        self.add_font("Inter", "B", str(FONT_DIR / "Inter-Bold.ttf"))
        self.set_margins(16, 18, 16)
        self.set_auto_page_break(True, margin=18)
        self.set_title(self.doc_title)
        self.set_creator(product)
        self.set_creation_date(datetime.now(UTC))

    def header(self) -> None:
        r, g, b = TLP_RGB.get(self.marking, TLP_RGB["TLP:RED"])
        self.set_font("Inter", "B", 8)
        self.set_text_color(r, g, b)
        self.set_y(8)
        self.cell(0, 4, self.marking, align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_y(18)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Inter", "", 7.5)
        self.set_text_color(110, 110, 110)
        self.cell(0, 4, f"{self.product} · {self.doc_title[:90]}", align="L")
        self.set_x(self.l_margin)
        self.cell(0, 4, f"{self.marking} · page {self.page_no()}/{{nb}}", align="R")
        self.set_text_color(0, 0, 0)


def render(title: str, blocks: list[Block], *, marking: str = "TLP:CLEAR", product: str = "Argus") -> bytes:
    """The PDF bytes for ``blocks`` under ``title`` and ``marking``."""
    doc = _Doc(title, marking, product)
    doc.alias_nb_pages()
    doc.add_page()
    width = doc.w - doc.l_margin - doc.r_margin
    for b in blocks:
        doc.set_x(doc.l_margin)
        if b.kind == "h1":
            doc.set_font("Inter", "B", 17)
            doc.multi_cell(width, 8, clean(b.text, 300), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            doc.ln(2)
        elif b.kind == "h2":
            doc.ln(3)
            doc.set_font("Inter", "B", 12)
            doc.multi_cell(width, 6, clean(b.text, 300), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            doc.ln(1)
        elif b.kind in ("p", "small"):
            doc.set_font("Inter", "", 9.5 if b.kind == "p" else 8)
            if b.kind == "small":
                doc.set_text_color(90, 90, 90)
            doc.multi_cell(width, 4.8 if b.kind == "p" else 4, clean(b.text) or "—",
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)  # fmt: skip
            doc.set_text_color(0, 0, 0)
            doc.ln(1.5)
        elif b.kind == "bullets":
            doc.set_font("Inter", "", 9.5)
            for it in b.items:
                doc.set_x(doc.l_margin)
                doc.cell(5, 4.8, "•")
                doc.multi_cell(width - 5, 4.8, clean(it), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            doc.ln(1.5)
        elif b.kind == "kv":
            for k, v in b.pairs:
                doc.set_x(doc.l_margin)
                doc.set_font("Inter", "B", 9)
                doc.cell(38, 4.8, clean(k, 60))
                doc.set_font("Inter", "", 9)
                doc.multi_cell(width - 38, 4.8, clean(v, 2000) or "—", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            doc.ln(1.5)
        elif b.kind == "table":
            if not b.rows:
                doc.set_font("Inter", "", 9)
                doc.multi_cell(width, 4.8, "None.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                continue
            doc.set_font("Inter", "", 8)
            widths = tuple(b.widths) if len(b.widths) == len(b.headers) else None
            with doc.table(
                col_widths=widths,
                line_height=4.2,
                text_align="LEFT",
                headings_style=FontFace(family="Inter", emphasis="BOLD", fill_color=(238, 238, 238)),
                borders_layout="HORIZONTAL_LINES",
                width=width,
            ) as t:
                head = t.row()
                for hd in b.headers:
                    head.cell(clean(hd, 80))
                for r in b.rows:
                    row = t.row()
                    for c in r:
                        row.cell(clean(c, 600))  # a row must fit on one page
            doc.ln(2)
        elif b.kind == "rule":
            doc.ln(1)
            doc.set_draw_color(200, 200, 200)
            doc.line(doc.l_margin, doc.get_y(), doc.w - doc.r_margin, doc.get_y())
            doc.ln(3)
    return bytes(doc.output())
