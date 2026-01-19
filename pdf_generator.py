#!/usr/bin/env python3
"""
PDF Report Generator for fSOC APK Forensics
Generates professional-looking PDF reports from text forensic reports
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
from reportlab.platypus import KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas


class PDFReportGenerator:
    """Generate professional PDF reports from forensic analysis text files."""
    
    # fSOC Brand Colors
    FSOC_RED = HexColor('#DC143C')  # Crimson red
    FSOC_GREEN = HexColor('#00FF00')  # Matrix green
    FSOC_DARK = HexColor('#1a1a1a')  # Dark background
    FSOC_GRAY = HexColor('#333333')  # Dark gray
    FSOC_LIGHT_GRAY = HexColor('#CCCCCC')  # Light gray
    
    def __init__(self, text_report_path: str, output_pdf_path: str = None):
        """Initialize PDF generator with text report path."""
        self.text_report_path = text_report_path
        
        if output_pdf_path is None:
            # Generate PDF path from text path
            base_path = os.path.splitext(text_report_path)[0]
            self.output_pdf_path = f"{base_path}.pdf"
        else:
            self.output_pdf_path = output_pdf_path
        
        self.apk_name = self._extract_apk_name()
        self.styles = self._create_styles()
    
    def _extract_apk_name(self) -> str:
        """Extract APK name from report path."""
        # Get directory name which is the APK name
        dir_name = os.path.basename(os.path.dirname(self.text_report_path))
        return dir_name if dir_name else "Unknown APK"
    
    def _create_styles(self):
        """Create custom paragraph styles for the PDF."""
        styles = getSampleStyleSheet()
        
        # Title style
        styles.add(ParagraphStyle(
            name='FSocTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=self.FSOC_RED,
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtitle style
        styles.add(ParagraphStyle(
            name='FSocSubtitle',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=self.FSOC_GRAY,
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))
        
        # Section header
        styles.add(ParagraphStyle(
            name='FSocSection',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=self.FSOC_RED,
            spaceBefore=20,
            spaceAfter=12,
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=self.FSOC_RED,
            borderPadding=5
        ))
        
        # Subsection header
        styles.add(ParagraphStyle(
            name='FSocSubsection',
            parent=styles['Heading3'],
            fontSize=13,
            textColor=self.FSOC_DARK,
            spaceBefore=12,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        # Code/Technical style
        styles.add(ParagraphStyle(
            name='FSocCode',
            parent=styles['Code'],
            fontSize=9,
            textColor=self.FSOC_GREEN,
            fontName='Courier',
            leftIndent=20,
            rightIndent=20,
            spaceBefore=6,
            spaceAfter=6,
            backColor=HexColor('#f5f5f5')
        ))
        
        # Body text
        styles.add(ParagraphStyle(
            name='FSocBody',
            parent=styles['BodyText'],
            fontSize=10,
            textColor=black,
            alignment=TA_JUSTIFY,
            spaceBefore=6,
            spaceAfter=6
        ))
        
        # Critical/Warning style
        styles.add(ParagraphStyle(
            name='FSocCritical',
            parent=styles['BodyText'],
            fontSize=11,
            textColor=self.FSOC_RED,
            fontName='Helvetica-Bold',
            spaceBefore=8,
            spaceAfter=8,
            leftIndent=10,
            borderWidth=2,
            borderColor=self.FSOC_RED,
            borderPadding=8
        ))
        
        return styles
    
    def _add_header_footer(self, canvas_obj, doc):
        """Add header and footer to each page."""
        canvas_obj.saveState()
        
        # Header
        canvas_obj.setFillColor(self.FSOC_DARK)
        canvas_obj.rect(0, letter[1] - 0.75*inch, letter[0], 0.75*inch, fill=True, stroke=False)
        
        canvas_obj.setFillColor(self.FSOC_RED)
        canvas_obj.setFont('Helvetica-Bold', 16)
        canvas_obj.drawString(0.75*inch, letter[1] - 0.5*inch, "fSOC APK FORENSICS")
        
        canvas_obj.setFillColor(white)
        canvas_obj.setFont('Helvetica', 10)
        canvas_obj.drawString(0.75*inch, letter[1] - 0.65*inch, f"Analysis Report: {self.apk_name}")
        
        # Footer
        canvas_obj.setFillColor(self.FSOC_GRAY)
        canvas_obj.setFont('Helvetica', 8)
        page_num = canvas_obj.getPageNumber()
        footer_text = f"Page {page_num} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Classification: TLP:WHITE"
        canvas_obj.drawCentredString(letter[0]/2, 0.5*inch, footer_text)
        
        canvas_obj.restoreState()
    
    def _parse_report_content(self) -> list:
        """Parse text report and convert to PDF elements."""
        elements = []
        
        try:
            with open(self.text_report_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            raise Exception(f"Failed to read report file: {e}")
        
        # Add cover page
        elements.extend(self._create_cover_page())
        elements.append(PageBreak())
        
        # Parse content
        lines = content.split('\n')
        in_code_block = False
        code_buffer = []
        
        for line in lines:
            # Skip separator lines
            if line.strip() and all(c == '=' for c in line.strip()):
                elements.append(Spacer(1, 0.2*inch))
                continue
            
            if line.strip() and all(c == '-' for c in line.strip()):
                elements.append(Spacer(1, 0.1*inch))
                continue
            
            # Detect sections (all caps lines)
            if line.strip() and line.strip().isupper() and len(line.strip()) > 5:
                if code_buffer:
                    elements.append(Paragraph('<br/>'.join(code_buffer), self.styles['FSocCode']))
                    code_buffer = []
                    in_code_block = False
                
                elements.append(Paragraph(line.strip(), self.styles['FSocSection']))
                continue
            
            # Detect critical/warning lines
            if any(keyword in line.upper() for keyword in ['CRITICAL', 'HIGH-RISK', 'MALICIOUS', 'DANGER']):
                if code_buffer:
                    elements.append(Paragraph('<br/>'.join(code_buffer), self.styles['FSocCode']))
                    code_buffer = []
                    in_code_block = False
                
                elements.append(Paragraph(line.strip(), self.styles['FSocCritical']))
                continue
            
            # Detect code blocks (indented lines or technical content)
            if line.startswith('    ') or line.startswith('\t') or any(c in line for c in ['$', '{', '}', ':', '//']):
                in_code_block = True
                code_buffer.append(line.replace('<', '&lt;').replace('>', '&gt;'))
                continue
            
            # Regular text
            if line.strip():
                if code_buffer:
                    elements.append(Paragraph('<br/>'.join(code_buffer), self.styles['FSocCode']))
                    code_buffer = []
                    in_code_block = False
                
                # Detect subsections (lines ending with :)
                if line.strip().endswith(':') and len(line.strip()) < 80:
                    elements.append(Paragraph(line.strip(), self.styles['FSocSubsection']))
                else:
                    # Escape HTML characters
                    safe_line = line.strip().replace('<', '&lt;').replace('>', '&gt;')
                    elements.append(Paragraph(safe_line, self.styles['FSocBody']))
            else:
                if code_buffer:
                    elements.append(Paragraph('<br/>'.join(code_buffer), self.styles['FSocCode']))
                    code_buffer = []
                    in_code_block = False
                elements.append(Spacer(1, 0.1*inch))
        
        # Flush remaining code buffer
        if code_buffer:
            elements.append(Paragraph('<br/>'.join(code_buffer), self.styles['FSocCode']))
        
        return elements
    
    def _create_cover_page(self) -> list:
        """Create professional cover page."""
        elements = []
        
        # Spacer
        elements.append(Spacer(1, 2*inch))
        
        # Main title
        elements.append(Paragraph("fSOC APK FORENSICS", self.styles['FSocTitle']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Subtitle
        elements.append(Paragraph("Mobile Malware Analysis Report", self.styles['FSocSubtitle']))
        elements.append(Spacer(1, 1*inch))
        
        # APK Info Box
        apk_info = [
            ['<b>Target APK:</b>', self.apk_name],
            ['<b>Report Generated:</b>', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['<b>Analysis Type:</b>', 'Deep Manual Forensic Analysis'],
            ['<b>Classification:</b>', 'TLP:WHITE - Unrestricted Distribution']
        ]
        
        info_table = Table(apk_info, colWidths=[2.5*inch, 3.5*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f5f5f5')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, self.FSOC_GRAY)
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 1.5*inch))
        
        # Warning notice
        warning = Paragraph(
            "<b>SECURITY NOTICE:</b> This report contains technical analysis of potentially malicious software. "
            "Handle with appropriate security measures and only share with authorized personnel.",
            self.styles['FSocCritical']
        )
        elements.append(warning)
        
        return elements
    
    def generate(self) -> str:
        """Generate the PDF report."""
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                self.output_pdf_path,
                pagesize=letter,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=1*inch,
                bottomMargin=0.75*inch
            )
            
            # Parse content
            elements = self._parse_report_content()
            
            # Build PDF with header/footer
            doc.build(elements, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
            
            return self.output_pdf_path
            
        except Exception as e:
            raise Exception(f"Failed to generate PDF: {e}")


def convert_report_to_pdf(text_report_path: str, output_pdf_path: str = None) -> str:
    """
    Convert a text forensic report to professional PDF.
    
    Args:
        text_report_path: Path to the text report file
        output_pdf_path: Optional output PDF path (defaults to same name with .pdf extension)
    
    Returns:
        Path to generated PDF file
    """
    generator = PDFReportGenerator(text_report_path, output_pdf_path)
    return generator.generate()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pdf_generator.py <text_report_path> [output_pdf_path]")
        sys.exit(1)
    
    text_path = sys.argv[1]
    pdf_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        output = convert_report_to_pdf(text_path, pdf_path)
        print(f"✅ PDF report generated: {output}")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
