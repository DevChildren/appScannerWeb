from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
import os
import textwrap

def create_pdf_report(vulnerabilities, visual_elements_analysis, additional_findings, analyst_name):
    sdcard_path = "/sdcard/Documents/"
    if not os.path.exists(sdcard_path):
        os.makedirs(sdcard_path)
    
    file_name = input("Document Name: ")
    file_path = os.path.join(sdcard_path, file_name + ".pdf")
    
    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter
    
    # Draw logo
    logo_path = '/sdcard/Download/de.png'
    c.drawImage(logo_path, width / 2 - 50, height - 100, width=100, height=50)
    
    # Draw title
    c.setFont('Helvetica-Bold', 16)
    c.drawCentredString(width / 2, height - 150, 'Data Scanner')
    c.setFont('Helvetica', 12)
    c.drawCentredString(width / 2, height - 170, '=============================')
    c.drawCentredString(width / 2, height - 190, f'oleh: {analyst_name}')
    
    # Set up text object for the body
    c.setFont('Helvetica', 12)
    textobject = c.beginText(40, height - 220)
    
    max_line_length = 80  # Maximum line length before wrapping
    footer_height = 50    # Height of the footer
    padding_bottom = 30   # Padding from the bottom of the page

    # Calculate the maximum Y position for the text body
    max_y_position = footer_height + padding_bottom
    
    for i, vuln in enumerate(vulnerabilities):
        print(f"Processing vulnerability {i + 1}: {vuln}")
        if textobject.getY() < max_y_position:
            c.drawText(textobject)
            c.showPage()
            textobject = c.beginText(40, height - 40)
        
        textobject.textLine(f"{i + 1}. URL: {vuln['url']}")
        textobject.textLine(f"   Kerentanan: {vuln['type']}")
        textobject.textLine(f"   Tingkat Kerentanan: {vuln['severity']}")
        
        description_lines = textwrap.wrap(vuln['description'], max_line_length)
        textobject.textLine("   Penjelasan:")
        for line in description_lines:
            textobject.textLine(f"      {line}")
        
        textobject.textLine("")
    
    if visual_elements_analysis:
        for analysis_type, analysis_list in visual_elements_analysis.items():
            print(f"Processing visual elements analysis {analysis_type}: {analysis_list}")
            textobject.textLine(f"{analysis_type.capitalize()}:")
            for analysis in analysis_list:
                if textobject.getY() < max_y_position:
                    c.drawText(textobject)
                    c.showPage()
                    textobject = c.beginText(40, height - 40)

                textobject.textLine(f"   Tipe: {analysis['type']}")
                textobject.textLine(f"   Tingkat: {analysis['severity']}")
                description_lines = textwrap.wrap(analysis['description'], max_line_length)
                for line in description_lines:
                    textobject.textLine(f"      {line}")
                textobject.textLine("")

    if additional_findings:
        for finding_type, finding_list in additional_findings.items():
            print(f"Processing additional findings {finding_type}: {finding_list}")
            textobject.textLine(f"{finding_type.capitalize()}:")
            if isinstance(finding_list, dict):
                for sub_finding_type, sub_finding_list in finding_list.items():
                    textobject.textLine(f"   {sub_finding_type.capitalize()}:")
                    for sub_finding in sub_finding_list:
                        if isinstance(sub_finding, str):
                            textobject.textLine(f"      {sub_finding}")
                        else:
                            if textobject.getY() < max_y_position:
                                c.drawText(textobject)
                                c.showPage()
                                textobject = c.beginText(40, height - 40)

                            textobject.textLine(f"      Tipe: {sub_finding['type']}")
                            textobject.textLine(f"      Tingkat: {sub_finding['severity']}")
                            description_lines = textwrap.wrap(sub_finding['description'], max_line_length)
                            for line in description_lines:
                                textobject.textLine(f"         {line}")
                            textobject.textLine("")
            else:
                for finding in finding_list:
                    if textobject.getY() < max_y_position:
                        c.drawText(textobject)
                        c.showPage()
                        textobject = c.beginText(40, height - 40)
                    
                    textobject.textLine(f"   Tipe: {finding['type']}")
                    textobject.textLine(f"   Tingkat: {finding['severity']}")
                    description_lines = textwrap.wrap(finding['description'], max_line_length)
                    for line in description_lines:
                        textobject.textLine(f"      {line}")
                    textobject.textLine("")

    c.drawText(textobject)
    
    # Draw footer background
    c.setFillColor(HexColor("#444"))
    c.rect(0, 0, width, footer_height, stroke=0, fill=1)
    
    # Draw footer text
    c.setFont("Helvetica", 10)
    c.setFillColor(HexColor("#FFFFFF"))
    c.drawCentredString(width / 2, 20, 'Kontak: Yayat Mahardika | Telepon: 338 | Email: ildren@gmail.com')
    
    c.save()
