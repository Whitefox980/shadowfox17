# shadowfox/agents/pdf_exporter.py

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os
from pathlib import Path
import json
import logging
from typing import Dict, List, Any

class PDFExporter:
    """
    PDFExporter - Kreira profesionalne PDF izveÅ¡taje za ShadowFox rezultate
    Sa potpisom 'ShadowFox and Chupko'
    """
    
    def __init__(self, operator):
        self.operator = operator
        self.logger = logging.getLogger('PDFExporter')
        
        # Setup stilova
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Kreira custom stilove za PDF"""
        # Glavni naslov
        self.styles.add(ParagraphStyle(
            name='ShadowFoxTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a1a'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Podnaslov
        self.styles.add(ParagraphStyle(
            name='ShadowFoxSubtitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.HexColor('#333333'),
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))
        
        # Sekcijski naslov
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2c3e50'),
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=10,
            backColor=colors.HexColor('#ecf0f1')
        ))
        
        # Vulnerability naslov (crveni)
        self.styles.add(ParagraphStyle(
            name='VulnHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.HexColor('#e74c3c'),
            fontName='Helvetica-Bold'
        ))
        
        # Success naslov (zeleni)
        self.styles.add(ParagraphStyle(
            name='SuccessHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.HexColor('#27ae60'),
            fontName='Helvetica-Bold'
        ))
        
        # Code style
        self.styles.add(ParagraphStyle(
            name='CodeStyle',
            parent=self.styles['Code'],
            fontSize=9,
            fontName='Courier',
            backColor=colors.HexColor('#f8f9fa'),
            borderWidth=1,
            borderColor=colors.HexColor('#dee2e6'),
            borderPadding=8,
            leftIndent=10,
            rightIndent=10
        ))
        
        # Footer style
        self.styles.add(ParagraphStyle(
            name='FooterStyle',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#666666'),
            alignment=TA_CENTER,
            fontName='Helvetica-Oblique'
        ))
    
    def create_report(self, mission_id: str, output_path: str = None) -> str:
        """
        Kreira kompletan PDF izveÅ¡taj za misiju
        """
        self.logger.info(f"Kreiranje PDF izveÅ¡taja za misiju: {mission_id}")
        
        # Dobij podatke o misiji
        results = self.operator.get_mission_results(mission_id)
        if not results or not results.get("mission"):
            raise ValueError(f"Nisu pronaÄ‘eni rezultati za misiju {mission_id}")
        
        # Putanja za PDF
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ShadowFox_Report_{mission_id[:8]}_{timestamp}.pdf"
            output_path = self.operator.reports_dir / filename
        
        # Kreiraj PDF
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # SadrÅ¾aj PDF-a
        story = []
        
        # Header sa logom i naslovom
        story.extend(self._create_header(results["mission"]))
        
        # Executive summary
        story.extend(self._create_executive_summary(results))
        
        # Mission details
        story.extend(self._create_mission_details(results["mission"]))
        
        # Vulnerability findings
        story.extend(self._create_vulnerability_section(results))
        
        # Technical details
        story.extend(self._create_technical_details(results))
        
        # Recommendations
        story.extend(self._create_recommendations(results))
        
        # Appendix sa raw podacima
        story.extend(self._create_appendix(results))
        
        # Footer sa potpisom
        story.extend(self._create_footer())
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_watermark, onLaterPages=self._add_watermark)
        
        self.logger.info(f"PDF izveÅ¡taj kreiran: {output_path}")
        
        # Loguj u bazu
        self.operator.log_agent_action("PDFExporter", "report_created", {
            "mission_id": mission_id,
            "output_path": str(output_path),
            "proofs_count": len(results.get("proofs", [])),
            "vulns_found": len([p for p in results.get("proofs", []) if p.get("status") == "confirmed"])
        })
        
        return str(output_path)
    
    def _create_header(self, mission_data: Dict) -> List:
        """Kreira header sa naslovom i osnovnim info"""
        elements = []
        
        # Glavni naslov
        elements.append(Paragraph("ðŸ¦Š SHADOWFOX SECURITY ASSESSMENT", self.styles['ShadowFoxTitle']))
        
        # Podnaslov
        elements.append(Paragraph("Professional Penetration Testing Report", self.styles['ShadowFoxSubtitle']))
        
        elements.append(Spacer(1, 20))
        
        # Info tabela
        info_data = [
            ["Target:", mission_data.get("target_url", "N/A")],
            ["Mission ID:", mission_data.get("mission_id", "N/A")],
            ["Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Status:", mission_data.get("status", "completed").upper()]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#ecf0f1')),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#ecf0f1'), colors.white])
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 30))
        
        return elements
    
    def _create_executive_summary(self, results: Dict) -> List:
        """Executive Summary sekcija"""
        elements = []
        
        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        
        proofs = results.get("proofs", [])
        confirmed_vulns = [p for p in proofs if p.get("status") == "confirmed"]
        potential_vulns = [p for p in proofs if p.get("status") == "potential"]
        
        summary_text = f"""
        This report presents the findings of a comprehensive security assessment performed on the target system. 
        During the engagement, ShadowFox identified <b>{len(confirmed_vulns)} confirmed vulnerabilities</b> and 
        <b>{len(potential_vulns)} potential security issues</b> that require immediate attention.
        
        The assessment was conducted using automated penetration testing techniques combined with AI-driven 
        payload generation and analysis. All findings have been thoroughly validated and documented with 
        proof-of-concept demonstrations.
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Risk summary tabela
        risk_data = [
            ["Risk Level", "Count", "Description"],
            ["ðŸ”´ Critical", str(len([v for v in confirmed_vulns if "SQLi" in v.get("payload_type", "")])), "SQL Injection, RCE"],
            ["ðŸŸ  High", str(len([v for v in confirmed_vulns if "XSS" in v.get("payload_type", "")])), "Cross-Site Scripting"],
            ["ðŸŸ¡ Medium", str(len(potential_vulns)), "Potential vulnerabilities"],
            ["ðŸ“Š Total", str(len(proofs)), "All findings"]
        ]
        
        risk_table = Table(risk_data, colWidths=[2*inch, 1*inch, 3*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#ecf0f1'), colors.white])
        ]))
        
        elements.append(risk_table)
        elements.append(Spacer(1, 20))
        
        return elements
    
    def _create_mission_details(self, mission_data: Dict) -> List:
        """Mission Details sekcija"""
        elements = []
        
        elements.append(Paragraph("MISSION DETAILS", self.styles['SectionHeader']))
        
        details_text = f"""
        <b>Target URL:</b> {mission_data.get('target_url', 'N/A')}<br/>
        <b>Mission ID:</b> {mission_data.get('mission_id', 'N/A')}<br/>
        <b>Description:</b> {mission_data.get('description', 'Automated security assessment')}<br/>
        <b>Started:</b> {mission_data.get('created_at', 'N/A')}<br/>
        <b>Completed:</b> {mission_data.get('completed_at', 'N/A')}<br/>
        <b>Status:</b> {mission_data.get('status', 'N/A').upper()}
        """
        
        elements.append(Paragraph(details_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        return elements
    
    def _create_vulnerability_section(self, results: Dict) -> List:
        """Vulnerability Findings sekcija"""
        elements = []
        
        elements.append(Paragraph("VULNERABILITY FINDINGS", self.styles['SectionHeader']))
        
        proofs = results.get("proofs", [])
        if not proofs:
            elements.append(Paragraph("No vulnerabilities found during this assessment.", self.styles['Normal']))
            return elements
        
        # GrupiÅ¡i po tipu
        vuln_types = {}
        for proof in proofs:
            ptype = proof.get("payload_type", "Unknown")
            if ptype not in vuln_types:
                vuln_types[ptype] = []
            vuln_types[ptype].append(proof)
        
        for vuln_type, vulns in vuln_types.items():
            confirmed = [v for v in vulns if v.get("status") == "confirmed"]
            potential = [v for v in vulns if v.get("status") == "potential"]
            
            if confirmed:
                elements.append(Paragraph(f"ðŸ”´ {vuln_type} - CONFIRMED ({len(confirmed)})", self.styles['VulnHeader']))
                
                for vuln in confirmed[:3]:  # Top 3
                    vuln_text = f"""
                    <b>URL:</b> {vuln.get('url', 'N/A')}<br/>
                    <b>Payload:</b> <font name="Courier">{vuln.get('payload', 'N/A')[:100]}...</font><br/>
                    <b>Response Code:</b> {vuln.get('response_code', 'N/A')}<br/>
                    <b>Impact:</b> Successful exploitation confirmed
                    """
                    elements.append(Paragraph(vuln_text, self.styles['Normal']))
                    elements.append(Spacer(1, 10))
            
            if potential:
                elements.append(Paragraph(f"ðŸŸ¡ {vuln_type} - POTENTIAL ({len(potential)})", self.styles['SuccessHeader']))
                elements.append(Paragraph(f"Found {len(potential)} potential issues requiring manual verification.", self.styles['Normal']))
                elements.append(Spacer(1, 10))
        
        return elements
    
    def _create_technical_details(self, results: Dict) -> List:
        """Technical Details sekcija"""
        elements = []
        
        elements.append(Paragraph("TECHNICAL DETAILS", self.styles['SectionHeader']))
        
        # Agent logs summary
        agent_logs = results.get("agent_logs", [])
        agent_summary = {}
        for log in agent_logs:
            agent = log.get("agent_name", "Unknown")
            if agent not in agent_summary:
                agent_summary[agent] = 0
            agent_summary[agent] += 1
        
        tech_text = f"""
        <b>Assessment Methodology:</b><br/>
        â€¢ AI-driven payload generation and mutation<br/>
        â€¢ Automated vulnerability scanning<br/>
        â€¢ Real-time response analysis<br/>
        â€¢ Proof-of-concept validation<br/><br/>
        
        <b>Agent Activity Summary:</b><br/>
        """
        
        for agent, count in agent_summary.items():
            tech_text += f"â€¢ {agent}: {count} actions<br/>"
        
        elements.append(Paragraph(tech_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        return elements
    
    def _create_recommendations(self, results: Dict) -> List:
        """Recommendations sekcija"""
        elements = []
        
        elements.append(Paragraph("RECOMMENDATIONS", self.styles['SectionHeader']))
        
        proofs = results.get("proofs", [])
        confirmed_vulns = [p for p in proofs if p.get("status") == "confirmed"]
        
        recommendations = []
        
        # Bazirano na tipovima ranjivosti
        vuln_types = set([v.get("payload_type", "") for v in confirmed_vulns])
        
        if "XSS" in vuln_types:
            recommendations.append("Implement proper input validation and output encoding to prevent Cross-Site Scripting attacks.")
        
        if "SQLi" in vuln_types:
            recommendations.append("Use parameterized queries and prepared statements to prevent SQL Injection vulnerabilities.")
        
        if "SSRF" in vuln_types:
            recommendations.append("Implement strict URL validation and whitelist allowed destinations for server requests.")
        
        # GeneriÄki preporuke
        recommendations.extend([
            "Conduct regular security assessments and penetration testing.",
            "Implement a Web Application Firewall (WAF) for additional protection.",
            "Keep all software components updated to the latest versions.",
            "Implement proper logging and monitoring for security events.",
            "Provide security awareness training for development teams."
        ])
        
        rec_text = ""
        for i, rec in enumerate(recommendations, 1):
            rec_text += f"{i}. {rec}<br/><br/>"
        
        elements.append(Paragraph(rec_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        return elements
    
    def _create_appendix(self, results: Dict) -> List:
        """Appendix sa raw podacima"""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Paragraph("APPENDIX - RAW DATA", self.styles['SectionHeader']))
        
        # Sample payload data (skraÄ‡eno)
        proofs = results.get("proofs", [])[:5]  # Samo prvih 5
        
        for i, proof in enumerate(proofs, 1):
            elements.append(Paragraph(f"Finding #{i}", self.styles['VulnHeader']))
            
            raw_data = f"""
URL: {proof.get('url', 'N/A')}
Payload Type: {proof.get('payload_type', 'N/A')}
Payload: {proof.get('payload', 'N/A')[:200]}...
Response Code: {proof.get('response_code', 'N/A')}
Status: {proof.get('status', 'N/A')}
            """
            
            elements.append(Paragraph(raw_data, self.styles['CodeStyle']))
            elements.append(Spacer(1, 15))
        
        return elements
    
    def _create_footer(self) -> List:
        """Footer sa potpisom"""
        elements = []
        
        elements.append(Spacer(1, 50))
        
        # Separator linija
        elements.append(Paragraph("_" * 80, self.styles['FooterStyle']))
        elements.append(Spacer(1, 20))
        
        # Glavni potpis
        signature_text = """
        <b>ðŸ¦Š ShadowFox Security Assessment</b><br/>
        Professional Penetration Testing & Security Analysis<br/><br/>
        
        <i>Powered by ShadowFox AI-Driven Security Platform</i><br/>
        <b>Created by: ShadowFox and Chupko</b><br/><br/>
        
        This report contains confidential information and is intended solely for the use of the client.<br/>
        Unauthorized distribution or reproduction is strictly prohibited.<br/><br/>
        
        For questions or clarifications, please contact the ShadowFox security team.
        """
        
        elements.append(Paragraph(signature_text, self.styles['FooterStyle']))
        
        # Timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"Report generated on: {timestamp}", self.styles['FooterStyle']))
        
        return elements
    
    def _add_watermark(self, canvas, doc):
        """Dodaje watermark na svaku stranicu"""
        canvas.saveState()
        
        # Page number
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#666666'))
        canvas.drawRightString(doc.pagesize[0] - 72, 30, f"Page {doc.page}")
        
        # Watermark
        canvas.setFont('Helvetica-Bold', 40)
        canvas.setFillColor(colors.HexColor('#f0f0f0'))
        canvas.rotate(45)
        canvas.drawString(200, -100, "ðŸ¦Š SHADOWFOX")
        
        canvas.restoreState()

# Test funkcionalnosti
if __name__ == "__main__":
    from shadowfox.core.operator import ShadowFoxOperator
    
    # Test kreiranja PDF-a
    op = ShadowFoxOperator()
    pdf_exporter = PDFExporter(op)
    
    # Kreiraj test misiju
    mission_id = op.create_mission("https://example.com", "Test PDF export")
    
    # Dodaj neki mock proof
    op.store_proof(
        payload="<script>alert('XSS')</script>",
        url="https://example.com/search?q=test",
        payload_type="XSS",
        response_code=200,
        response_raw="HTML response with reflected payload"
    )
    
    # GeneriÅ¡i PDF
    pdf_path = pdf_exporter.create_report(mission_id)
    print(f"PDF kreiran: {pdf_path}")
