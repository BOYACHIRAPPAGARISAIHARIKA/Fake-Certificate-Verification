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

# Tesseract Path Configuration
if os.path.exists(r"C:\Program Files\Tesseract-OCR\tesseract.exe"):
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# --- 2. DATABASE & STATE MANAGEMENT ---
def init_db():
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS certificates 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hash TEXT, reg_date TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, user TEXT, timestamp TIMESTAMP)''')
    conn.commit()
    conn.close()

def log_event(event, user="Admin"):
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs (event, user, timestamp) VALUES (?, ?, ?)", 
              (event, user, datetime.datetime.now()))
    conn.commit()
    conn.close()

# --- 3. CORE FORENSIC ENGINE ---
def perform_ela(image, quality=90, enhancement=8.0):
    original = image.convert('RGB')
    temp_buffer = BytesIO()
    original.save(temp_buffer, 'JPEG', quality=quality)
    temp_buffer.seek(0)
    resaved = Image.open(temp_buffer)
    diff = ImageChops.difference(original, resaved)
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema]) or 1
    scale = (255.0 / max_diff) * enhancement
    return ImageEnhance.Brightness(diff).enhance(scale)

def analyze_noise(ela_image):
    pixels = np.array(ela_image.convert('L')).flatten()
    pixels_clean = pixels[pixels > 5] # Filter background noise
    if len(pixels_clean) == 0: return 100.0, 0, 0, 0
    
    std = np.std(pixels_clean)
    kurt = kurtosis(pixels_clean)
    score = max(0.0, min(100.0, 100.0 - (std * 1.5) - (abs(kurt) * 2)))
    return round(score, 2), np.mean(pixels_clean), std, kurt

def compute_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

# --- 4. REPORT GENERATION ---
def generate_pdf_report(data):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    w, h = letter
    
    # Header
    p.setFillColor(colors.navy)
    p.rect(0, h-80, w, 80, fill=1)
    p.setFillColor(colors.white)
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, h-50, "FORENSIC VERIFICATION REPORT")
    
    # Body
    p.setFillColor(colors.black)
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, h-120, f"Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    p.drawString(50, h-140, f"Document Status: {data['status']}")
    p.drawString(50, h-160, f"Authenticity Score: {data['score']}%")
    
    # Images
    orig_img = ImageReader(BytesIO(data['orig_bytes']))
    ela_img = ImageReader(BytesIO(data['ela_bytes']))
    p.drawImage(orig_img, 50, h-400, width=240, height=200, preserveAspectRatio=True)
    p.drawImage(ela_img, 310, h-400, width=240, height=200, preserveAspectRatio=True)
    
    p.showPage()
    p.save()
    return buffer.getvalue()

# --- 5. UI COMPONENTS ---
def show_dashboard():
    st.title("📊 System Dashboard")
    conn = sqlite3.connect('vericert_enterprise.db')
    c1, c2, c3 = st.columns(3)
    
    total = pd.read_sql_query("SELECT COUNT(*) FROM certificates", conn).iloc[0,0]
    logs = pd.read_sql_query("SELECT COUNT(*) FROM logs", conn).iloc[0,0]
    
    c1.metric("Assets Registered", total)
    c2.metric("Audit Logs", logs)
    c3.metric("Engine Version", "2.0.4")
    
    st.subheader("Recent Registry")
    df = pd.read_sql_query("SELECT name, reg_date FROM certificates ORDER BY id DESC LIMIT 5", conn)
    st.table(df)
    conn.close()

def forensic_lab(sens):
    st.title("🔬 Forensic Lab")
    up_file = st.file_uploader("Upload Document", type=['jpg','png','jpeg'])
    
    if up_file:
        file_bytes = up_file.getvalue()
        img = Image.open(BytesIO(file_bytes))
        
        col1, col2 = st.columns(2)
        with col1:
            st.image(img, caption="Original", use_container_width=True)
        
        with col2:
            ela_img = perform_ela(img, enhancement=sens)
            fig, ax = plt.subplots()
            ax.imshow(ela_img, cmap='magma')
            ax.axis('off')
            st.pyplot(fig)
            plt.close(fig)
            
        score, m, s, k = analyze_noise(ela_img)
        
        # Stats
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Authenticity", f"{score}%")
        m2.metric("Std Dev", f"{s:.2f}")
        m3.metric("Kurtosis", f"{k:.2f}")
        m4.metric("Mean Noise", f"{m:.2f}")
        
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

# --- 6. MAIN EXECUTION ---
def main():
    init_db()
    with st.sidebar:
        st.header("VeriCert AI")
        nav = st.radio("Navigation", ["Dashboard", "Forensic Lab", "Bulk Auditor", "System Settings"])
        sens = st.slider("ELA Intensity", 1.0, 20.0, 10.0)
    
    if nav == "Dashboard": show_dashboard()
    elif nav == "Forensic Lab": forensic_lab(sens)
    elif nav == "Bulk Auditor": bulk_auditor()
    elif nav == "System Settings": system_settings()

if __name__ == "__main__":
    main()