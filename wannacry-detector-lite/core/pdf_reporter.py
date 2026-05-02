"""PDF report generation via reportlab (optional dependency)."""

from datetime import datetime, timezone
from pathlib import Path

from core.logger_setup import get_logger
from core.report_generator import ScanResult

logger = get_logger(__name__)


def generate_pdf(results: list[ScanResult], output_path: Path | None = None) -> Path:
    """Generate a PDF report from scan results.

    Args:
        results: List of scan results.
        output_path: Optional path for output. Auto-generated if None.

    Returns:
        Path to generated PDF.

    Raises:
        ImportError: If reportlab is not installed.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as e:
        raise ImportError("reportlab is required for PDF generation") from e

    if output_path is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = Path("reports") / f"wannacry_scan_{timestamp}.pdf"

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        title="WannaCry Detection Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#1a1a2e"),
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=colors.grey,
    )

    elements: list = []

    elements.append(Paragraph("WannaCry Detector Lite", title_style))
    elements.append(Paragraph("Scan Report", subtitle_style))
    elements.append(Spacer(1, 0.3 * inch))

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(f"Scan Time: {scan_time}", styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))

    total = len(results)
    wannacry = sum(1 for r in results if r.verdict == "wannacry")
    suspicious = sum(1 for r in results if r.verdict == "suspicious")
    benign = sum(1 for r in results if r.verdict == "benign")

    summary_data = [
        ["Category", "Count"],
        ["WannaCry Detected", str(wannacry)],
        ["Suspicious", str(suspicious)],
        ["Benign", str(benign)],
        ["Total", str(total)],
    ]
    summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f5f5f5")),
        ])
    )
    elements.append(Paragraph("Summary", styles["Heading2"]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3 * inch))

    if results:
        elements.append(Paragraph("Detections", styles["Heading2"]))
        detected = [r for r in results if r.verdict != "benign"]
        if detected:
            table_data = [["File", "Verdict", "ML Score", "YARA"]]
            for r in detected[:50]:
                table_data.append([
                    Path(r.file_path).name,
                    r.verdict,
                    f"{r.ml_score:.3f}",
                    ", ".join(r.yara_matches) if r.yara_matches else "-",
                ])
            detail_table = Table(table_data, colWidths=[2.5 * inch, 1 * inch, 1 * inch, 2 * inch])
            detail_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ])
            )
            elements.append(detail_table)
        else:
            elements.append(Paragraph("No threats detected.", styles["Normal"]))

    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph(
        "<i>Disclaimer: This tool is for academic and research purposes only. "
        "Use responsibly and only on systems you own or have permission to analyze.</i>",
        styles["Italic"],
    ))

    try:
        doc.build(elements)
        logger.info("PDF report written to %s", output_path)
        return output_path
    except Exception as e:
        logger.error("Failed to generate PDF: %s", e)
        raise
