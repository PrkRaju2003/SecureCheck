import json
import os
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.graphics.shapes import Drawing, Rect, String, Wedge
from app.models import ScanResult

def draw_gauge(c, score, x, y):
    # Draw a simple risk gauge
    c.setLineWidth(1)
    # Background
    c.setFillColor(colors.lightgrey)
    c.wedge(x-50, y-50, x+50, y+50, 0, 180, fill=1)
    
    # Colored segments
    c.setFillColor(colors.green)
    c.wedge(x-50, y-50, x+50, y+50, 120, 60, fill=1)
    c.setFillColor(colors.orange)
    c.wedge(x-50, y-50, x+50, y+50, 60, 60, fill=1)
    c.setFillColor(colors.red)
    c.wedge(x-50, y-50, x+50, y+50, 0, 60, fill=1)
    
    # Needle
    angle = 180 - (score * 18) # 10 score = 180 degrees
    c.setStrokeColor(colors.black)
    c.setLineWidth(2)
    import math
    nx = x + 40 * math.cos(math.radians(angle))
    ny = y + 40 * math.sin(math.radians(angle))
    c.line(x, y, nx, ny)
    c.circle(x, y, 5, fill=1)
    c.drawCentredString(x, y-20, f"Risk Score: {score:.1f}/10")

def generate_reports(result: ScanResult, output_dir: str = "."):
    # JSON Dump
    json_path = os.path.join(output_dir, "secureflow_report.json")
    with open(json_path, "w") as f:
        f.write(result.model_dump_json(indent=4))
        
    # PDF Report
    pdf_path = os.path.join(output_dir, "secureflow_report.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("SecureFlow Security Audit Report", styles['Title']))
    elements.append(Spacer(1, 12))
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", styles['Heading2']))
    summary_data = [
        ["Metric", "Value"],
        ["Repository", result.repo_path],
        ["Timestamp", result.timestamp],
        ["Total SAST Findings", len(result.sast_findings)],
        ["Total IaC Findings", len(result.iac_findings)],
        ["Risk Score", f"{result.threat_model.total_risk_score:.2f}/10.0" if result.threat_model else "N/A"]
    ]
    t = Table(summary_data, colWidths=[150, 300])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(t)
    elements.append(Spacer(1, 20))

    # Findings Table
    elements.append(Paragraph("Top Findings", styles['Heading2']))
    findings_data = [["Severity", "Category", "Finding"]]
    
    all_findings = []
    for f in result.sast_findings: all_findings.append(["SAST", f.severity, f.stride_category, f.issue_text[:60]])
    for f in result.iac_findings: all_findings.append(["IaC", f.severity, f.stride_category, f.check_id])
    for f in result.cloud_findings: all_findings.append(["Cloud", f.severity, f.stride_category, f.description])
    
    # Sort by severity (simplistic)
    sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_map.get(x[1].upper(), 9))
    
    for f in all_findings[:15]: # Top 15
        findings_data.append([f[1], f[2], f[3]])
        
    ft = Table(findings_data, colWidths=[80, 100, 300])
    ft.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTSIZE', (0, 0), (-1, -1), 8)
    ]))
    elements.append(ft)

    # Build and add gauge manually with canvas after
    def header_footer(canvas, doc):
        canvas.saveState()
        if result.threat_model:
            draw_gauge(canvas, result.threat_model.total_risk_score, 500, 700)
        canvas.restoreState()

    doc.build(elements, onFirstPage=header_footer)
    return json_path, pdf_path