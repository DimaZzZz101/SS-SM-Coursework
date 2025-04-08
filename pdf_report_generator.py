from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.piecharts import Pie as PieChart
from reportlab.lib.units import mm
from datetime import datetime
from check_metadata import CheckMetadata

class PDFReportGenerator:
    def __init__(self, checks_data, filename):
        self.checks_data = checks_data
        self.filename = filename
        self.styles = getSampleStyleSheet()
        self.custom_styles()

    def custom_styles(self):
        self.styles.add(ParagraphStyle(name='CheckTitle', fontSize=12, leading=14, textColor=colors.black, fontName='Helvetica-Bold'))
        self.styles.add(ParagraphStyle(name='Success', fontSize=10, leading=12, textColor=colors.green, fontName='Helvetica'))
        self.styles.add(ParagraphStyle(name='Warning', fontSize=10, leading=12, textColor=colors.red, fontName='Helvetica'))
        self.styles.add(ParagraphStyle(name='Label', fontSize=10, leading=12, textColor=colors.black, fontName='Helvetica-Bold'))

    def build(self):
        doc = SimpleDocTemplate(self.filename, pagesize=A4,
                              topMargin=12.7*mm, bottomMargin=12.7*mm,
                              leftMargin=12.7*mm, rightMargin=12.7*mm)
        story = []
        
        story.append(self.create_header())
        story.append(Spacer(1, 5*mm))
        
        story.append(self.create_summary_section())
        story.append(Spacer(1, 7.6*mm))
        
        story.extend(self.create_check_sections())
        
        if any("Router Uptime" in check.result for check in self.checks_data):
            story.extend(self.create_uptime_section())
        
        doc.build(story, onFirstPage=self.add_page_elements, onLaterPages=self.add_page_elements)

    def create_header(self):
        timestamp = next((check.result.split("at ")[1] for check in self.checks_data if "Scan started at" in check.result), datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        header_data = [
            [Paragraph("RouterOS Security Inspection Report", self.styles['Heading1']),
             Paragraph(timestamp, self.styles['Normal'])]
        ]
        return Table(header_data, colWidths=[110*mm, 70*mm], style=[
            ('ALIGN', (1,0), (1,0), 'RIGHT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP')
        ])

    def create_summary_section(self):
        connection_line = next((check.result for check in self.checks_data if "Connecting to RouterOS at" in check.result), "")
        host = connection_line.split("at ")[1] if "at " in connection_line else "Unknown"
        
        checks = self.get_check_results()
        total_checks = len(checks)
        passed = sum(1 for result in checks.values() if result['passed'])
        
        d = Drawing(35*mm, 35*mm)
        pc = PieChart()
        pc.width = pc.height = 30*mm
        pc.x = 2.5*mm
        pc.y = 2.5*mm
        pc.data = [passed, total_checks - passed]
        pc.labels = ['Passed', 'Failed']
        pc.slices.strokeWidth = 0.5
        pc.slices[0].fillColor = colors.green
        pc.slices[1].fillColor = colors.red
        pc.innerRadiusFraction = 0.4
        d.add(pc)
        
        fraction_text = f"{passed}/{total_checks}"
        percent_text = f"{(passed/total_checks*100) if total_checks > 0 else 0:.1f}%"
        d.add(String(17.5*mm, 19*mm, fraction_text, fontSize=10, textAnchor='middle', fillColor=colors.black, fontName='Helvetica'))
        d.add(String(17.5*mm, 15*mm, percent_text, fontSize=10, textAnchor='middle', fillColor=colors.black, fontName='Helvetica'))
        
        summary_data = [
            [Paragraph(f"Host: {host}", self.styles['Normal']), d]
        ]
        return Table(summary_data, colWidths=[90*mm, 90*mm], style=[
            ('ALIGN', (1,0), (1,0), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOX', (0,0), (-1,-1), 0.5, colors.black)
        ])

    def get_check_results(self):
        checks = {}
        current_check = None
        for check in self.checks_data:
            if "[*]" in check.result and not any(x in check.result for x in ["Connecting to", "Disconnected from", "All checks completed", "Router Uptime", "Connection successful!"]):
                current_check = check.result.split("[*] ")[1].strip()
                checks[current_check] = {'passed': True, 'results': []}
            elif current_check and ("[+]" in check.result or "[!]" in check.result):
                passed = "[+]" in check.result
                checks[current_check]['passed'] = checks[current_check]['passed'] and passed
                checks[current_check]['results'].append((check, passed))
        return checks

    def get_cve_list(self):
        cve_list = []
        cve_found = False
        for check in self.checks_data:
            if "[!] CAUTION: Found" in check.result and "CVEs affecting RouterOS" in check.result:
                cve_found = True
                num_cves = int(check.result.split("Found ")[1].split(" CVEs")[0])
                index = self.checks_data.index(check)
                for subsequent_check in self.checks_data[index + 1:]:
                    if subsequent_check.result.strip().startswith("- "):
                        cve_list.append(subsequent_check.result.strip()[2:])
                    else:
                        break
                if not cve_list and num_cves > 0:
                    cve_list.append(f"Details for {num_cves} CVE(s) not available in report.")
                break
        return cve_list if cve_found else []

    def create_check_sections(self):
        story = []
        checks = self.get_check_results()
        
        for check_name, data in checks.items():
            story.append(Paragraph(check_name, self.styles['CheckTitle']))
            story.append(Spacer(1, 2*mm))
            
            for check_obj, passed in data['results']:
                style = self.styles['Success'] if passed else self.styles['Warning']
                table_data = [
                    [Paragraph("Result:", self.styles['Label']), Paragraph(check_obj.result, style)],
                    [Paragraph("Description:", self.styles['Label']), Paragraph(check_obj.description or "No description", self.styles['Normal'])],
                    [Paragraph("Fix:", self.styles['Label']), Paragraph(check_obj.fix or "Not required", self.styles['Normal'])]
                ]
                table = Table(table_data, colWidths=[40*mm, 140*mm], style=[
                    ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('ALIGN', (0,0), (0,-1), 'LEFT'),
                    ('ALIGN', (1,0), (1,-1), 'LEFT')
                ])
                story.append(table)
                story.append(Spacer(1, 3*mm))
                
                if check_name == "Checking RouterOS Version" and "[!] CAUTION: Found" in check_obj.result:
                    cve_list = self.get_cve_list()
                    if cve_list:
                        story.append(Paragraph("Found CVEs:", self.styles['Label']))
                        story.append(Spacer(1, 1*mm))
                        cve_table_data = [[Paragraph(cve, self.styles['Warning'])] for cve in cve_list]
                        cve_table = Table(cve_table_data, colWidths=[180*mm], style=[
                            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                            ('VALIGN', (0,0), (-1,-1), 'TOP'),
                            ('ALIGN', (0,0), (-1,-1), 'LEFT')
                        ])
                        story.append(cve_table)
                        story.append(Spacer(1, 3*mm))
            
            story.append(Spacer(1, 5*mm))
        
        return story

    def create_uptime_section(self):
        story = []
        uptime_check = next((check for check in self.checks_data if "Router Uptime" in check.result), 
                           CheckMetadata("[-] ERROR: Could not retrieve uptime.", "", ""))
        style = self.styles['Success'] if "[*]" in uptime_check.result else self.styles['Warning']
        
        story.append(Paragraph("Router Uptime", self.styles['CheckTitle']))
        story.append(Spacer(1, 2*mm))
        
        table_data = [
            [Paragraph("Result:", self.styles['Label']), Paragraph(uptime_check.result, style)]
        ]
        table = Table(table_data, colWidths=[40*mm, 140*mm], style=[
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ALIGN', (0,0), (0,-1), 'LEFT'),
            ('ALIGN', (1,0), (1,-1), 'LEFT')
        ])
        story.append(table)
        
        return story

    def add_page_elements(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 10)
        canvas.drawString(12.7*mm, A4[1] - 7.6*mm, "RouterOS Security Inspection Report")
        
        duration = next((check.result.split("in ")[1] for check in self.checks_data if "All checks completed in" in check.result), "Unknown")
        canvas.drawString(12.7*mm, 7.6*mm, "Generated by RouterOS Inspector")
        canvas.drawRightString(A4[0] - 12.7*mm, 7.6*mm, f"Scan Duration: {duration}")
        canvas.restoreState()