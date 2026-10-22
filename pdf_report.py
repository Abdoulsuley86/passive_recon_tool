import json
import os
import sys
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    HRFlowable,
    Preformatted,
)

def generate_pdf(json_file):
    with open(json_file, "r", encoding="utf-8") as file:
        findings = json.load(file)

    if not isinstance(findings, list):
        raise ValueError("Expected a list of report findings.")

    os.makedirs("reports", exist_ok=True)

    filename = os.path.splitext(os.path.basename(json_file))[0]
    output = os.path.join("reports", filename + ".pdf")

    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=45,
        leftMargin=45,
        topMargin=50,
        bottomMargin=50,
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ProTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#123456"),
        alignment=TA_CENTER,
        spaceAfter=15,
    ))

    styles.add(ParagraphStyle(
        name="FindingTitle",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#007C91"),
        spaceBefore=15,
        spaceAfter=8,
    ))

    story = []

    story.append(Paragraph(
        "MARMOUSH SENTINEL RECON",
        styles["ProTitle"]
    ))

    story.append(Paragraph(
        "OSINT &amp; Domain Intelligence Report",
        styles["Heading2"]
    ))

    story.append(Spacer(1, 15))

    story.append(Paragraph(
        "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M"),
        styles["Normal"]
    ))

    story.append(Spacer(1, 15))

    story.append(HRFlowable(
        width="100%",
        thickness=1,
        color=colors.HexColor("#007C91")
    ))

    story.append(Spacer(1, 15))

    for finding in findings:
        title = escape(str(finding.get("title", "Finding")))
        result = str(finding.get("result", "No data"))

        story.append(Paragraph(
            title,
            styles["FindingTitle"]
        ))

        # Wrap long lines so they stay inside the PDF page.
        for line in result.splitlines():
            if not line.strip():
                story.append(Spacer(1, 5))
                continue

            safe_line = escape(line)
            story.append(Paragraph(
                safe_line,
                styles["Normal"]
            ))

        story.append(Spacer(1, 10))

    story.append(Spacer(1, 20))

    story.append(Paragraph(
        "This report contains informational findings. "
        "It is not a complete security audit.",
        styles["Italic"]
    ))

    doc.build(story)

    print(f"\nPDF report generated successfully: {output}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pdf_report.py reports/report.json")
        sys.exit(1)

    try:
        generate_pdf(sys.argv[1])
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Report generation failed: {error}")
        sys.exit(1)

