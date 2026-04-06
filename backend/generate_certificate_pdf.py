"""
TrustCode AI Compliance Certificate Generator (PDF)
Generates a professional PDF certificate from audit results.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.platypus.flowables import HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
except ImportError:
    print("Error: reportlab is required. Install with: pip install reportlab")
    sys.exit(1)


class PDFCertificateGenerator:
    """Generates a professional PDF certificate from audit results."""
    
    # Color scheme - Corporate Dark / Minimalist Academic
    COLORS = {
        'primary': colors.HexColor('#020617'),  # Deep Slate
        'accent': colors.HexColor('#22d3ee'),   # Cyan
        'danger': colors.HexColor('#f43f5e'),   # Rose
        'success': colors.HexColor('#10b981'),  # Emerald
        'warning': colors.HexColor('#f59e0b'),  # Amber
        'white': colors.white,
        'light_gray': colors.HexColor('#94a3b8'),
        'dark_gray': colors.HexColor('#475569'),
        'background': colors.HexColor('#f8fafc'),
    }
    
    def __init__(self, audit_json_path: str):
        self.audit_data = self._load_audit_data(audit_json_path)
        self.styles = self._create_styles()
    
    def _load_audit_data(self, path: str) -> dict:
        """Load and validate audit JSON data."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if 'TrustScore' not in data:
            raise ValueError("Invalid audit data: missing 'TrustScore'")
        
        return data
    
    def _create_styles(self):
        """Create custom styles for the certificate."""
        styles = getSampleStyleSheet()
        
        # Title style
        styles.add(ParagraphStyle(
            name='CertificateTitle',
            parent=styles['Heading1'],
            fontSize=28,
            spaceAfter=12,
            textColor=self.COLORS['primary'],
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
        ))
        
        # Subtitle style
        styles.add(ParagraphStyle(
            name='CertificateSubtitle',
            parent=styles['Heading2'],
            fontSize=18,
            spaceAfter=20,
            textColor=self.COLORS['accent'],
            alignment=TA_CENTER,
            fontName='Helvetica',
        ))
        
        # Section header
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading3'],
            fontSize=14,
            spaceAfter=10,
            spaceBefore=20,
            textColor=self.COLORS['primary'],
            fontName='Helvetica-Bold',
        ))
        
        # Normal text
        styles.add(ParagraphStyle(
            name='CertificateNormal',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=self.COLORS['dark_gray'],
            fontName='Helvetica',
        ))
        
        # Recommendation style
        styles.add(ParagraphStyle(
            name='Recommendation',
            parent=styles['CertificateNormal'],
            fontSize=11,
            leading=16,
            textColor=self.COLORS['dark_gray'],
            fontName='Helvetica-Oblique',
            leftIndent=20,
        ))
        
        return styles
    
    def generate(self, output_path: str = "TrustCode_Certificate.pdf"):
        """Generate the complete certificate PDF."""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm,
            title="TrustCode AI Compliance Certificate",
            author="TrustCode AI Engine"
        )
        
        story = []
        
        # Header
        self._add_header(story)
        
        # Horizontal line
        story.append(HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLORS['primary'],
            spaceBefore=10,
            spaceAfter=20,
        ))
        
        # Audit Summary
        self._add_audit_summary(story)
        
        # Findings Table (if any)
        if self.audit_data.get('Findings'):
            self._add_findings_table(story)
        
        # Recommendation
        self._add_recommendation(story)
        
        # Footer
        self._add_footer(story)
        
        # Build PDF
        doc.build(story)
        print(f"[OK] Certificate saved to {output_path}")
        return output_path
    
    def _add_header(self, story):
        """Add the certificate header."""
        story.append(Spacer(1, 20))
        
        # Main title
        story.append(Paragraph("TRUSTCODE AI", self.styles['CertificateTitle']))
        story.append(Paragraph("COMPLIANCE CERTIFICATE", self.styles['CertificateSubtitle']))
        
        # Certificate ID
        cert_id = f"Certificate ID: TC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        story.append(Paragraph(cert_id, self.styles['CertificateNormal']))
        
        story.append(Spacer(1, 30))
    
    def _add_audit_summary(self, story):
        """Add the audit summary section."""
        story.append(Paragraph("AUDIT SUMMARY", self.styles['SectionHeader']))
        
        trust_score = self.audit_data.get('TrustScore', 0)
        metadata = self.audit_data.get('AuditMetadata', {})
        
        # Determine score color and label
        if trust_score >= 80:
            score_color = self.COLORS['success']
            score_label = "EXCELLENT"
        elif trust_score >= 60:
            score_color = self.COLORS['accent']
            score_label = "GOOD"
        elif trust_score >= 40:
            score_color = self.COLORS['warning']
            score_label = "MODERATE"
        else:
            score_color = self.COLORS['danger']
            score_label = "CRITICAL"
        
        # Create summary table
        summary_data = [
            ['TrustScore', f'{trust_score}/100 - {score_label}'],
            ['Audit Date', metadata.get('audit_date', 'N/A')],
            ['File Analyzed', metadata.get('file', 'N/A')],
            ['Total Findings', str(metadata.get('total_findings', 0))],
        ]
        
        table = Table(summary_data, colWidths=[4*cm, 10*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_gray']),
            ('TEXTCOLOR', (0, 0), (0, -1), self.COLORS['primary']),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, -1), 10),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.COLORS['light_gray']),
            ('BOX', (0, 0), (-1, -1), 1, self.COLORS['primary']),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        
        # Color the score cell
        table.setStyle(TableStyle([
            ('TEXTCOLOR', (1, 0), (1, 0), score_color),
            ('FONTSIZE', (1, 0), (1, 0), 14),
            ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 20))
    
    def _add_findings_table(self, story):
        """Add the detailed findings table."""
        story.append(Paragraph("DETAILED FINDINGS", self.styles['SectionHeader']))
        
        findings = self.audit_data.get('Findings', [])
        
        # Table headers
        headers = ['Severity', 'Category', 'Issue', 'Line']
        table_data = [headers]
        
        severity_colors = {
            'critical': self.COLORS['danger'],
            'high': self.COLORS['danger'],
            'medium': self.COLORS['warning'],
            'low': self.COLORS['accent'],
        }
        
        for finding in findings:
            severity = finding.get('severity', 'low').upper()
            message = finding.get('message', '')
            # Truncate long messages
            if len(message) > 50:
                message = message[:47] + '...'
            
            table_data.append([
                Paragraph(f'<font color="white">{severity}</font>', 
                         ParagraphStyle('Severity', fontSize=8, textColor=colors.white)),
                finding.get('category', 'N/A'),
                message,
                str(finding.get('line', 'N/A')),
            ])
        
        table = Table(table_data, colWidths=[2.5*cm, 4*cm, 7*cm, 1.5*cm])
        
        # Build style list
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (0, -1), colors.white),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.COLORS['light_gray']),
            ('BOX', (0, 0), (-1, -1), 1, self.COLORS['primary']),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]
        
        # Add severity-specific row colors
        for idx, finding in enumerate(findings, start=1):
            severity = finding.get('severity', 'low').lower()
            bg_color = severity_colors.get(severity, self.COLORS['light_gray'])
            table_style.append(('BACKGROUND', (0, idx), (0, idx), bg_color))
        
        table.setStyle(TableStyle(table_style))
        story.append(table)
        story.append(Spacer(1, 20))
    
    def _add_recommendation(self, story):
        """Add the PhD-level recommendation."""
        recommendation = self.audit_data.get('PhD_Level_Recommendation', '')
        
        if not recommendation:
            return
        
        story.append(Paragraph("PHD-LEVEL RECOMMENDATION", self.styles['SectionHeader']))
        
        # Create a styled paragraph with border
        rec_para = Paragraph(recommendation, self.styles['Recommendation'])
        story.append(rec_para)
        story.append(Spacer(1, 20))
    
    def _add_footer(self, story):
        """Add the certification footer."""
        story.append(Spacer(1, 20))
        story.append(HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLORS['primary'],
            spaceBefore=10,
            spaceAfter=10,
        ))
        
        # Footer text
        story.append(Paragraph(
            "CERTIFIED BY TRUSTCODE AI ENGINE",
            ParagraphStyle(
                'FooterMain',
                fontSize=10,
                textColor=self.COLORS['primary'],
                alignment=TA_CENTER,
                fontName='Helvetica-Bold',
            )
        ))
        
        # PhD badge
        story.append(Paragraph(
            "PHD RESEARCH STANDARDS",
            ParagraphStyle(
                'FooterBadge',
                fontSize=8,
                textColor=self.COLORS['accent'],
                alignment=TA_CENTER,
                fontName='Helvetica',
            )
        ))
        
        story.append(Spacer(1, 12))
        
        # Creator credit
        story.append(Paragraph(
            "Created by Ali Hasan",
            ParagraphStyle(
                'CreatorCredit',
                fontSize=8,
                textColor=self.COLORS['dark_gray'],
                alignment=TA_CENTER,
                fontName='Helvetica',
            )
        ))
        
        story.append(Paragraph(
            "https://alool266.github.io/portfolio-website/",
            ParagraphStyle(
                'CreatorPortfolio',
                fontSize=7,
                textColor=self.COLORS['accent'],
                alignment=TA_CENTER,
                fontName='Helvetica',
            )
        ))
        
        story.append(Spacer(1, 12))
        
        # Disclaimer
        disclaimer = (
            "This certificate is generated automatically by TrustCode AI Audit Engine v1.0.0. "
            "It represents a static analysis assessment and should be used as a guideline, "
            "not a guarantee of code quality."
        )
        story.append(Paragraph(
            disclaimer,
            ParagraphStyle(
                'Disclaimer',
                fontSize=7,
                textColor=self.COLORS['light_gray'],
                alignment=TA_CENTER,
                fontName='Helvetica',
            )
        ))


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python generate_certificate_pdf.py <audit_results.json> [output.pdf]")
        sys.exit(1)
    
    audit_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "TrustCode_Certificate.pdf"
    
    generator = PDFCertificateGenerator(audit_path)
    generator.generate(output_path)


if __name__ == "__main__":
    main()