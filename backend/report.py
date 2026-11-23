"""Word and PDF audit-planning reports built from a saved AIMsquare project."""
import io
from xml.sax.saxutils import escape
from docx import Document
from docx.shared import Pt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer

DISCLAIMER = ("This report suggests audit procedures and prioritises risk from the figures supplied. "
              "It does not conclude on fraud or give a legal opinion. Figures extracted from PDFs are approximate and must be verified.")


def _fmt(n):
    try:
        return f"{round(float(n)):,}"
    except Exception:
        return "-"


def _yoy(y):
    return "new" if y is None else f"{y*100:+.0f}%"


def _sections(data):
    out = []
    for title, key in (("Balance sheet", "matchedB"), ("Profit and loss", "matchedP")):
        items = sorted(data.get(key) or [], key=lambda x: -(x.get("score") or 0))
        rows = [[i.get("name", ""), _fmt(i.get("cur")), _yoy(i.get("yoy")), i.get("band", ""), i.get("chk", "")] for i in items]
        out.append((title, rows))
    return out


def _summary(data):
    allit = (data.get("matchedB") or []) + (data.get("matchedP") or [])
    hi = sum(1 for i in allit if i.get("band") == "High")
    return (f"{len(data.get('matchedB') or [])} balance-sheet items and {len(data.get('matchedP') or [])} P&L lines mapped; "
            f"{hi} rated High priority; {len(data.get('unmatched') or [])} lines not recognised.")


HEAD = ["Item", "Amount", "YoY", "Priority", "Suggested procedure"]


def build_docx(project, data, head_hash):
    d = Document()
    st = d.styles["Normal"]; st.font.name = "Times New Roman"; st.font.size = Pt(11)
    d.add_heading(f"AIMsquare audit planning report: {project['name']}", 1)
    d.add_paragraph(_summary(data))
    for title, rows in _sections(data):
        d.add_heading(title, 2)
        if not rows:
            d.add_paragraph("No lines recognised."); continue
        t = d.add_table(rows=1, cols=5); t.style = "Light Grid Accent 1"
        for i, h in enumerate(HEAD):
            t.rows[0].cells[i].text = h
        for r in rows:
            cells = t.add_row().cells
            for i, v in enumerate(r):
                cells[i].text = str(v)
    d.add_heading("Basis and limits", 2)
    d.add_paragraph(DISCLAIMER)
    d.add_paragraph(f"Audit-log head at export: {head_hash}")
    buf = io.BytesIO(); d.save(buf); return buf.getvalue()


def build_pdf(project, data, head_hash):
    ss = getSampleStyleSheet(); cell = ss["BodyText"]; cell.fontSize = 8; cell.leading = 10
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    el = [Paragraph(escape(f"AIMsquare audit planning report: {project['name']}"), ss["Title"]), Paragraph(escape(_summary(data)), ss["BodyText"]), Spacer(1, 8)]
    for title, rows in _sections(data):
        el.append(Paragraph(escape(title), ss["Heading2"]))
        if not rows:
            el.append(Paragraph("No lines recognised.", ss["BodyText"])); continue
        body = [HEAD] + [[Paragraph(escape(str(v)), cell) for v in r] for r in rows]
        t = Table(body, colWidths=[170, 70, 45, 55, 440], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, 0), 8)]))
        el += [t, Spacer(1, 8)]
    el += [Paragraph(escape(DISCLAIMER), ss["BodyText"]), Paragraph(escape(f"Audit-log head at export: {head_hash}"), ss["BodyText"])]
    doc.build(el); return buf.getvalue()
