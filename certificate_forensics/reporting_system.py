from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
import datetime

class ForensicReporter:
    def __init__(self, data, ela_img_bytes):
        self.data = data
        self.ela_img = ela_img_bytes
        self.buffer = BytesIO()

    def create_pdf(self):
        p = canvas.Canvas(self.buffer, pagesize=letter)
        w, h = letter

        # 1. Header Design
        p.setFillColor(colors.HexColor("#1E3A8A"))
        p.rect(0, h-100, w, 100, fill=1)
        p.setFillColor(colors.white)
        p.setFont("Helvetica-Bold", 20)
        p.drawString(0.5*inch, h-60, "VERICERT AI: FORENSIC DOSSIER")
        
        # 2. Summary Statistics
        p.setFillColor(colors.black)
        p.setFont("Helvetica-Bold", 14)
        p.drawString(0.5*inch, h-140, "Executive Summary")
        p.setFont("Helvetica", 12)
        p.drawString(0.7*inch, h-165, f"Authenticity Index: {self.data['score']}%")
        p.drawString(0.7*inch, h-185, f"Database Status: {self.data['db_status']}")
        p.drawString(0.7*inch, h-205, f"Linguistic Match: {self.data['ocr_match']}%")

        # 3. Embed ELA Heatmap
        from reportlab.lib.utils import ImageReader
        p.setFont("Helvetica-Bold", 14)
        p.drawString(0.5*inch, h-260, "Visual Forensic Analysis (ELA)")
        img = ImageReader(BytesIO(self.ela_img))
        p.drawImage(img, 0.5*inch, h-520, width=5*inch, height=2.5*inch, preserveAspectRatio=True)

        # 4. Legal Disclaimer & Footer
        p.setFont("Helvetica-Oblique", 8)
        p.drawString(0.5*inch, 0.5*inch, f"Generated: {datetime.datetime.now()} | Proprietary Forensic Framework")
        
        p.showPage()
        p.save()
        return self.buffer.getvalue()