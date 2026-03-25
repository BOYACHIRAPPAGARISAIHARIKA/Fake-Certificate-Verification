import streamlit as st
import sqlite3
import hashlib
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import datetime
import logging
import pytesseract
import cv2
import os
from io import BytesIO
from PIL import Image, ImageChops, ImageEnhance
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from scipy.stats import kurtosis, skew

# --- 1. SYSTEM CONFIGURATION ---
logging.basicConfig(filename='forensic_audit.log', level=logging.INFO)
st.set_page_config(page_title="VeriCert AI Forensic Suite", layout="wide", page_icon="🔐")

# Fix Tesseract path for local vs cloud
if os.path.exists(r"C:\Program Files\Tesseract-OCR\tesseract.exe"):
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# --- 2. DATABASE ARCHITECTURE ---
def init_db():
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS certificates 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hash TEXT, reg_date TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, user TEXT, timestamp TIMESTAMP)''')
    conn.commit()
    conn.close()

def log_event(event, user="System"):
    try:
        conn = sqlite3.connect('vericert_enterprise.db')
        c = conn.cursor()
        c.execute("INSERT INTO logs (event, user, timestamp) VALUES (?, ?, ?)", 
                  (event, user, datetime.datetime.now()))
        conn.commit()
        conn.close()
    except Exception as e:
        st.error(f"Logging failed: {e}")

# --- 3. FORENSIC ANALYTICS ENGINE ---
def perform_ela(image, quality=90, enhancement=8.0):
    """Detects digital tampering via Error Level Analysis."""
    original = image.convert('RGB')
    temp_buffer = BytesIO()
    original.save(temp_buffer, 'JPEG', quality=quality)
    temp_buffer.seek(0)
    resaved = Image.open(temp_buffer)
    
    diff = ImageChops.difference(original, resaved)
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0: max_diff = 1
    scale = (255.0 / max_diff) * enhancement
    return ImageEnhance.Brightness(diff).enhance(scale)

def analyze_noise(ela_image):
    """Statistical evaluation of the ELA map."""
    pixels = np.array(ela_image.convert('L')).flatten()
    std = np.std(pixels)
    kurt = kurtosis(pixels)
    
    score = 100.0
    if std > 5.0: score -= (std * 2)
    if kurt > 10.0: score -= 20.0
    
    return round(max(0.0, min(100.0, score)), 2), np.mean(pixels), std, kurt

# --- 4. OCR & VERIFICATION ---
def extract_text(image):
    try:
        open_cv_image = np.array(image.convert('RGB'))
        gray = cv2.cvtColor(open_cv_image, cv2.COLOR_BGR2GRAY)
        processed_img = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        return pytesseract.image_to_string(processed_img)
    except Exception:
        return ""

# PDF Report
        ela_buf = BytesIO()
        ela_img.save(ela_buf, format="PNG")
        report_data = {
            'score': score, 'status': 'PASS' if score > 80 else 'FAIL',
            'orig_bytes': file_bytes, 'ela_bytes': ela_buf.getvalue()
        }
        
        if st.button("Generate Report"):
            pdf = generate_pdf_report(report_data)
            st.download_button("Download PDF", pdf, file_name="Forensic_Report.pdf")

def verify_hash(file_bytes):
    h = hashlib.sha256(file_bytes).hexdigest()
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (h,))
    res = c.fetchone()
    conn.close()
    return res[0] if res else None

def bulk_auditor():
    st.title("📂 Bulk Auditor")
    files = st.file_uploader("Upload multiple documents", accept_multiple_files=True)
    if files:
        results = []
        for f in files:
            f_bytes = f.getvalue()
            img = Image.open(BytesIO(f_bytes))
            score, _, _, _ = analyze_noise(perform_ela(img))
            results.append({"Filename": f.name, "Score": score, "Status": "Genuine" if score > 80 else "Suspicious"})
        st.table(pd.DataFrame(results))
        
def system_settings():
    st.title("⚙️ System Settings")
    st.subheader("Registry Management")
    with st.form("reg_form"):
        new_name = st.text_input("Owner Name")
        new_file = st.file_uploader("Document to Register")
        if st.form_submit_button("Register in Database"):
            if new_name and new_file:
                h = compute_hash(new_file.getvalue())
                conn = sqlite3.connect('vericert_enterprise.db')
                conn.execute("INSERT INTO certificates (name, hash, reg_date) VALUES (?,?,?)", 
                             (new_name, h, datetime.datetime.now()))
                conn.commit()
                conn.close()
                st.success(f"Registered {new_name} successfully!")

# --- 5. UI COMPONENTS ---
def draw_sidebar():
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/1067/1067357.png", width=80)
        st.title("VeriCert Admin")
        nav = st.radio("Workspace", ["Dashboard", "Forensic Lab", "System Logs"])
        st.divider()
        sens = st.slider("ELA Sensitivity", 1.0, 20.0, 8.0)
        return nav, sens

# --- 6. MAIN APP LOGIC ---
def main():
    init_db()
    nav, ela_sensitivity = draw_sidebar()

    if nav == "Dashboard":
        st.title("🏛️ System Overview")
        conn = sqlite3.connect('vericert_enterprise.db')
        c1, c2 = st.columns(2)
        total_certs = pd.read_sql_query("SELECT COUNT(*) FROM certificates", conn).iloc[0,0]
        c1.metric("Registered Certificates", total_certs)
        c2.metric("System Status", "Secure")
        conn.close()

    elif nav == "Forensic Lab":
        st.header("🔬 Advanced Forensic Laboratory")
        up_file = st.file_uploader("Upload Document", type=["jpg", "png", "jpeg"])
        
        if up_file:
            # Persistent processing to avoid re-running on every click
            file_bytes = up_file.getvalue()
            img = Image.open(BytesIO(file_bytes))
            
            # Layout Columns
            col1, col2 = st.columns([1, 1])

            with col1:
                st.subheader("Original Document")
                st.image(img, use_container_width=True)
                
                # Hash Check
                owner = verify_hash(file_bytes)
                if owner:
                    st.success(f"✅ Verified Registry Match: {owner}")
                else:
                    st.error("⚠️ Unregistered Document Detected")

            with col2:
                st.subheader("Forensic Analysis")
                with st.spinner("Analyzing compression..."):
                    ela_img = perform_ela(img, enhancement=ela_sensitivity)
                    score, m_val, s_val, k_val = analyze_noise(ela_img)
                    
                    # Display ELA Heatmap
                    fig, ax = plt.subplots()
                    ax.imshow(np.array(ela_img.convert('L')), cmap='magma')
                    ax.axis('off')
                    st.pyplot(fig)
                    plt.close(fig)

            # Metrics Row
            st.divider()
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Authenticity Score", f"{score}%")
            m2.metric("Noise StdDev", f"{s_val:.2f}")
            m3.metric("Kurtosis", f"{k_val:.2f}")
            
            # OCR Section
            with st.expander("OCR Content Extraction"):
                text = extract_text(img)
                if text.strip():
                    st.code(text)
                else:
                    st.info("No legible text detected.")

            # Report Generation
            if st.button("Generate Forensic PDF Report"):
                # Simplified PDF trigger
                st.info("PDF Engine Ready. (Connect generate_forensic_report here)")

    elif nav == "System Logs":
        st.header("📜 Audit Trail")
        conn = sqlite3.connect('vericert_enterprise.db')
        logs = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20", conn)
        st.dataframe(logs, use_container_width=True)
        conn.close()

if __name__ == "__main__":
    main()