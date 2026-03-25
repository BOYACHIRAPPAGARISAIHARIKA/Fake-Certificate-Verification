import streamlit as st
import hashlib
from forensic_engine import ForensicEngine
from database_manager import DBManager
from PIL import Image
from io import BytesIO

# Initialize System
st.set_page_config(page_title="VeriCert AI", layout="wide")
engine = ForensicEngine()
db = DBManager()

st.sidebar.title("🔐 VeriCert AI v3.0")
mode = st.sidebar.radio("Navigation", ["Laboratory", "Registry"])

if mode == "Laboratory":
    st.header("🔬 Forensic Laboratory")
    file = st.file_uploader("Upload Document", type=['jpg', 'png'])
    if file:
        img_bytes = file.read()
        img = Image.open(BytesIO(img_bytes))
        
        # Run Forensics
        ela_img = engine.perform_ela(img)
        score, kurt, sk = engine.analyze_stats(ela_img)
        file_hash = hashlib.sha256(img_bytes).hexdigest()
        owner = db.verify(file_hash)
        
        col1, col2 = st.columns(2)
        with col1:
            st.image(ela_img, caption="Quantization Error Heatmap")
        with col2:
            st.metric("Authenticity Score", f"{score}%")
            if owner: st.success(f"Verified Owner: {owner}")
            else: st.error("No Match Found in Registry")
            st.write(f"**Kurtosis:** {kurt}")

elif mode == "Registry":
    st.header("⚙️ Admin Registry")
    name = st.text_input("Candidate Name")
    reg_file = st.file_uploader("Master Document", type=['jpg', 'png'])
    if st.button("Register Asset") and name and reg_file:
        h = hashlib.sha256(reg_file.read()).hexdigest()
        db.register(name, h)
        st.success(f"Encrypted record created for {name}")
        
        
from ocr_processor import OCRProcessor
from reporting_system import ForensicReporter

# In the analysis block:

from ocr_processor import OCRProcessor
from reporting_system import ForensicReporter

ocr = OCRProcessor()

if file:
    match_perc, status, text = ocr.verify_text(img_bytes, owner)

    st.metric("OCR Name Match", f"{match_perc}%")
    st.write(f"OCR Status: {status}")

    # Generate Report
    ela_bytes = BytesIO()
    ela_img.save(ela_bytes, format="PNG")
    ela_bytes = ela_bytes.getvalue()

    report_data = {
        'score': score,
        'db_status': "Verified" if owner else "Not Found",
        'ocr_match': match_perc
    }

    reporter = ForensicReporter(report_data, ela_bytes)
    pdf = reporter.create_pdf()

    st.download_button(
        label="Download Forensic Report",
        data=pdf,
        file_name="forensic_report.pdf",
        mime="application/pdf"
    )
