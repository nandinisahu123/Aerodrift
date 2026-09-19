from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def create_report(findings, remediation_text, result):
    out = Path(__file__).resolve().parents[1] / "reports"
    out.mkdir(exist_ok=True)
    pdf = out / "aerodrift_incident_report.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(pdf), pagesize=A4)
    story = [
        Paragraph("AeroDrift Incident Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Findings detected: {len(findings)}", styles["BodyText"]),
        Spacer(1, 8),
    ]
    for f in findings:
        story.append(Paragraph(
            f"CRITICAL/HIGH drift: {f['security_group']} port {f['port']} from {f['source']}",
            styles["BodyText"]))
        story.append(Spacer(1, 5))
    story += [
        Paragraph("Generated remediation:", styles["Heading2"]),
        Paragraph(remediation_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
                  styles["Code"]),
        Paragraph(f"Execution result: {result}", styles["BodyText"])
    ]
    doc.build(story)
    return pdf
