"""PDF vulnerability report (ReportLab / Platypus)."""
from __future__ import annotations

from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import SEVERITY_ORDER, SEVERITY_RANK, ScanReport

SEV_COLOR = {"Critical": colors.HexColor("#7a1020"), "High": colors.HexColor("#c0392b"),
             "Medium": colors.HexColor("#d9822b"), "Low": colors.HexColor("#2f6fb3"),
             "Unscored": colors.HexColor("#6b7280")}
INK, MUTED, LINE, TINT = colors.HexColor("#1f2933"), colors.HexColor("#6b7280"), colors.HexColor("#d5dae1"), colors.HexColor("#f3f5f8")
MAX_CVES_PER_PORT = 15

_REPL = {"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2013": "-", "\u2014": "-",
         "\u2026": "...", "\u00a0": " ", "\u2022": "-"}


def _t(value) -> str:
    """Make text safe for ReportLab: built-in fonts are Latin-1 only and Paragraph parses markup."""
    s = str(value if value is not None else "")
    for k, v in _REPL.items():
        s = s.replace(k, v)
    return escape(s.encode("latin-1", "replace").decode("latin-1"))


def _styles():
    ss = getSampleStyleSheet()
    base = ParagraphStyle("base", parent=ss["Normal"], fontName="Helvetica", fontSize=9, leading=12, textColor=INK)
    return {
        "base": base,
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=10),
        "muted": ParagraphStyle("muted", parent=base, fontSize=8, leading=10.5, textColor=MUTED),
        "title": ParagraphStyle("title", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=26, spaceAfter=4),
        "h1": ParagraphStyle("h1", parent=base, keepWithNext=1, fontName="Helvetica-Bold", fontSize=14, leading=18, spaceBefore=14, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base, keepWithNext=1, fontName="Helvetica-Bold", fontSize=11, leading=14, spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("h3", parent=base, keepWithNext=1, fontName="Helvetica-Bold", fontSize=9.5, leading=12, spaceBefore=8, spaceAfter=3),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8, leading=10),
        "cellb": ParagraphStyle("cellb", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=10),
        "pill": ParagraphStyle("pill", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=10,
                               textColor=colors.white, alignment=TA_CENTER),
        "big": ParagraphStyle("big", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=22, alignment=TA_CENTER),
        "bigl": ParagraphStyle("bigl", parent=base, fontSize=8, leading=10, alignment=TA_CENTER, textColor=MUTED),
    }


def _grid(data, widths, header=True, extra=()):
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), TINT), ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK)]
    t.setStyle(TableStyle(style + list(extra)))
    return t


def _sev_cell(sev, S):
    return Paragraph(_t(sev), S["pill"])


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "Network Vulnerability Assessment - Confidential")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(report: ScanReport, path: str) -> None:
    S = _styles()
    W = A4[0] - 36 * mm
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title="Network Vulnerability Assessment", author="netvulnscan")
    story: list = []

    # ---- cover / header ----------------------------------------------------
    story += [Paragraph("Network Vulnerability Assessment", S["title"]),
              Paragraph(f"Targets: {_t(', '.join(report.targets) or 'imported nmap results')}", S["base"]),
              Paragraph(f"Scan started {_t(report.started)}"
                        + (f" &middot; finished {_t(report.finished)}" if report.finished else "")
                        + f" &middot; report generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", S["muted"]),
              Paragraph(f"nmap {_t(report.nmap_version)} &middot; CVE data: NVD API 2.0"
                        if report.cve_lookup == "enabled" else f"nmap {_t(report.nmap_version)} &middot; CVE lookup skipped", S["muted"]),
              Spacer(1, 8)]

    # ---- executive summary -------------------------------------------------
    hosts = report.hosts
    open_ports = sum(len(h.ports) for h in hosts)
    versioned = sum(1 for h in hosts for p in h.ports if p.product)
    counts = report.severity_counts()
    unique: dict[str, tuple] = {}
    for h in hosts:
        for p in h.ports:
            for v in p.vulns:
                unique.setdefault(v.cve_id, (v, []))[1].append(f"{h.address}:{p.port}")
    kev = sum(1 for v, _ in unique.values() if v.kev)

    story.append(Paragraph("Executive summary", S["h1"]))
    stats = [[Paragraph(str(n), S["big"]) for n in (len(hosts), open_ports, versioned, len(unique), kev)],
             [Paragraph(l, S["bigl"]) for l in ("hosts up", "open ports", "versions identified", "unique CVEs", "known exploited (CISA KEV)")]]
    story.append(_grid(stats, [W / 5] * 5, header=False, extra=[("BACKGROUND", (0, 0), (-1, -1), TINT), ("LINEBELOW", (0, 0), (-1, 0), 0, TINT)]))
    story.append(Spacer(1, 8))
    sev_row = [[Paragraph(f"{counts[s]}", ParagraphStyle("n", parent=S["pill"], fontSize=14, leading=16)) for s in SEVERITY_ORDER],
               [Paragraph(s, S["pill"]) for s in SEVERITY_ORDER]]
    story.append(_grid(sev_row, [W / 5] * 5, header=False,
                       extra=[("BACKGROUND", (i, 0), (i, 1), SEV_COLOR[s]) for i, s in enumerate(SEVERITY_ORDER)]
                       + [("LINEBELOW", (0, 0), (-1, -1), 0, colors.white)]))
    story.append(Paragraph("Unique CVEs by CVSS severity. A CVE affecting several hosts is counted once.", S["muted"]))

    if unique:
        story.append(Paragraph("Top findings", S["h2"]))
        ranked = sorted(unique.values(), key=lambda x: (not x[0].kev, SEVERITY_RANK[x[0].severity], -(x[0].score or 0), x[0].cve_id))[:10]
        rows = [[Paragraph(h, S["cellb"]) for h in ("CVE", "CVSS", "Severity", "Affected", "Summary")]]
        extra = []
        for i, (v, where) in enumerate(ranked, start=1):
            rows.append([Paragraph(_t(v.cve_id) + (" <b>[KEV]</b>" if v.kev else ""), S["cell"]),
                         Paragraph(f"{v.score:.1f}" if v.score is not None else "n/a", S["cell"]), _sev_cell(v.severity, S),
                         Paragraph(_t(", ".join(sorted(set(where))[:3])) + (f" +{len(set(where)) - 3}" if len(set(where)) > 3 else ""), S["cell"]),
                         Paragraph(_t(v.description[:170]) + ("..." if len(v.description) > 170 else ""), S["cell"])])
            extra.append(("BACKGROUND", (2, i), (2, i), SEV_COLOR[v.severity]))
        story.append(_grid(rows, [30 * mm, 12 * mm, 19 * mm, 32 * mm, W - 93 * mm], extra=extra))
        story.append(Paragraph("KEV = listed in CISA's Known Exploited Vulnerabilities catalog; prioritise these first.", S["muted"]))
    elif report.cve_lookup == "enabled":
        story.append(Paragraph("No CVEs were matched to the detected service versions.", S["base"]))

    # ---- per-host detail ---------------------------------------------------
    story.append(Paragraph("Host details", S["h1"]))
    for h in hosts:
        head = _t(h.address) + (f" ({_t(h.hostname)})" if h.hostname else "")
        block = [Paragraph(head, S["h2"])]
        if h.os_guess:
            block.append(Paragraph(f"OS guess: {_t(h.os_guess)}", S["muted"]))
        if not h.ports:
            block.append(Paragraph("No open ports found in the scanned port range.", S["base"]))
            story.append(KeepTogether(block))
            continue
        rows = [[Paragraph(x, S["cellb"]) for x in ("Port", "Service", "Detected version", "CVEs", "Worst")]]
        extra = []
        for i, p in enumerate(h.ports, start=1):
            worst = min((v.severity for v in p.vulns), key=lambda s: SEVERITY_RANK[s]) if p.vulns else "-"
            rows.append([Paragraph(f"{p.port}/{p.protocol}", S["cell"]), Paragraph(_t(p.service), S["cell"]),
                         Paragraph(_t(p.banner) or "<i>not detected</i>", S["cell"]), Paragraph(str(len(p.vulns)), S["cell"]),
                         _sev_cell(worst, S) if worst != "-" else Paragraph("-", S["cell"])])
            if worst != "-":
                extra.append(("BACKGROUND", (4, i), (4, i), SEV_COLOR[worst]))
        block.append(_grid(rows, [22 * mm, 26 * mm, W - 22 * mm - 26 * mm - 16 * mm - 24 * mm, 16 * mm, 24 * mm], extra=extra))
        story.append(KeepTogether(block[:3]))
        story += block[3:]

        for p in h.ports:
            if not p.vulns and not p.notes:
                continue
            story.append(Paragraph(f"{_t(h.address)}:{p.port}/{p.protocol} &ndash; {_t(p.banner or p.service)}", S["h3"]))
            if p.vulns:
                rows = [[Paragraph(x, S["cellb"]) for x in ("CVE", "CVSS", "Severity", "Description")]]
                extra = []
                for i, v in enumerate(p.vulns[:MAX_CVES_PER_PORT], start=1):
                    desc = _t(v.description) + (" <i>(keyword match, low confidence)</i>" if v.confidence.startswith("Keyword") else "")
                    rows.append([Paragraph(_t(v.cve_id) + (" <b>[KEV]</b>" if v.kev else ""), S["cell"]),
                                 Paragraph(f"{v.score:.1f}" if v.score is not None else "n/a", S["cell"]), _sev_cell(v.severity, S),
                                 Paragraph(desc, S["cell"])])
                    extra.append(("BACKGROUND", (2, i), (2, i), SEV_COLOR[v.severity]))
                story.append(_grid(rows, [34 * mm, 12 * mm, 19 * mm, W - 65 * mm], extra=extra))
                if len(p.vulns) > MAX_CVES_PER_PORT:
                    story.append(Paragraph(f"+{len(p.vulns) - MAX_CVES_PER_PORT} more CVEs for this service; see the JSON/CSV export.", S["muted"]))
            for n in p.notes:
                story.append(Paragraph(f"Note: {_t(n)}", S["muted"]))

    # ---- methodology -------------------------------------------------------
    story += [Paragraph("Method and limitations", S["h1"]),
              Paragraph("Open ports and service versions were identified with nmap version detection (no exploitation, no NSE "
                        "scripts). Each detected application CPE was queried against the NVD CVE API 2.0; severity is the CVSS base "
                        "severity (v3.x preferred, then v4.0, then v2).", S["base"]), Spacer(1, 4),
              Paragraph("<b>Treat results as leads, not confirmed vulnerabilities.</b> Matching is based on the version a service "
                        "reports. Distribution packages often back-port security fixes without changing the version string (false "
                        "positives), and services that hide or alter their banners will be missed (false negatives). Configuration, "
                        "authentication and UDP services are outside the scope of this scan. Validate findings before remediation "
                        "and re-scan afterwards.", S["base"])]

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
