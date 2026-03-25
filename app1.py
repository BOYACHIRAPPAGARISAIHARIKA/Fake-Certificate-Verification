import streamlit as st
import sqlite3
import hashlib
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import datetime
import logging
import plotly.figure_factory as ff
import pytesseract
import cv2
import zipfile
from io import BytesIO
from PIL import Image, ImageChops, ImageEnhance
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from scipy.stats import kurtosis, skew

# Configure Tesseract OCR path
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# --- 1. SYSTEM CONFIGURATION & LOGGING ---
logging.basicConfig(filename='forensic_audit.log', level=logging.INFO)
st.set_page_config(page_title="VeriCert AI Forensic Suite", layout="wide", page_icon="🔐")

SYSTEM_VERSION = "2.1.0-Enterprise"

# --- 2. DATABASE ARCHITECTURE ---
def init_db():
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS certificates 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hash TEXT, reg_date TIMESTAMP, meta_info TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, user TEXT, timestamp TIMESTAMP)''')
    conn.commit()
    conn.close()

def log_event(event, user="System"):
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs (event, user, timestamp) VALUES (?, ?, ?)", 
              (event, user, datetime.datetime.now()))
    conn.commit()
    conn.close()

# --- 3. FORENSIC ANALYTICS ENGINE ---
def perform_ela(image, quality=90, enhancement=7.0):
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

def analyze_noise_distribution(ela_image):
    pixels = np.array(ela_image.convert('L')).flatten()
    mean, std = np.mean(pixels), np.std(pixels)
    score = max(0.0, min(100.0, 100.0 - (std * 2)))
    return round(score, 2), mean, std, kurtosis(pixels)

def verify_document(file_bytes):
    h = hashlib.sha256(file_bytes).hexdigest()
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (h,))
    res = c.fetchone()
    conn.close()
    return res[0] if res else None

# --- 4. OCR & REPORTING ---
def extract_text_from_image(image):
    gray = cv2.cvtColor(np.array(image.convert('RGB')), cv2.COLOR_BGR2GRAY)
    processed_img = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    return pytesseract.image_to_string(processed_img)

def cross_reference_text(text, name):
    if not name: return "N/A", 0
    return ("✅ Match Confirmed", 100) if name.lower() in text.lower() else ("⚠️ Mismatch", 0)

def generate_forensic_report(filename, owner, score, metadata, ela_img_bytes, orig_img_bytes):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 20); p.drawString(100, 750, "FORENSIC AUTHENTICATION REPORT")
    p.setFont("Helvetica", 12); p.drawString(100, 730, f"Target: {filename} | Score: {score}%")
    p.drawString(100, 715, f"Verified Owner: {owner}")
    
    # Draw Images
    p.drawImage(ImageReader(BytesIO(orig_img_bytes)), 100, 450, width=200, height=250, preserveAspectRatio=True)
    p.drawImage(ImageReader(BytesIO(ela_img_bytes)), 320, 450, width=200, height=250, preserveAspectRatio=True)
    p.drawString(150, 440, "Original"); p.drawString(380, 440, "ELA Heatmap")
    
    p.showPage(); p.save()
    return buffer.getvalue()

# --- 5. WORKSPACES ---
def show_bulk_auditor(ela_sensitivity):
    st.header("📂 Bulk Forensic Auditor")
    up_files = st.file_uploader("Upload Batch", type=["jpg","png","jpeg"], accept_multiple_files=True)
    if up_files:
        results, reports = [], []
        for f in up_files:
            b = f.read(); img = Image.open(BytesIO(b))
            owner = verify_document(b)
            ela = perform_ela(img, enhancement=ela_sensitivity)
            score, m, s, k = analyze_noise_distribution(ela)
            reports.append((f.name, generate_forensic_report(f.name, owner or "Unknown", score, [], BytesIO().getvalue(), b)))
            results.append({"File": f.name, "Score": f"{score}%", "Status": "PASS" if score > 85 else "CHECK"})
        
        st.table(pd.DataFrame(results))
        zip_buf = BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            for name, data in reports: z.writestr(f"Report_{name}.pdf", data)
        st.download_button("📥 Download All Reports (ZIP)", zip_buf.getvalue(), "batch_results.zip", "application/zip")

def show_registration():
    st.header("📜 Digital Notary: Asset Registration")
    st.info("Upload an original document to store its unique digital fingerprint in the secure registry.")
    with st.form("reg_form"):
        name = st.text_input("Full Name of Recipient / Certificate Holder")
        cert_file = st.file_uploader("Upload Original Document", type=["jpg","png","jpeg"])
        submit = st.form_submit_button("Register to Database")
        if submit and cert_file and name:
            f_bytes = cert_file.read()
            h = hashlib.sha256(f_bytes).hexdigest()
            conn = sqlite3.connect('vericert_enterprise.db')
            conn.execute("INSERT INTO certificates (name, hash, reg_date) VALUES (?, ?, ?)", (name, h, datetime.datetime.now()))
            conn.commit(); conn.close()
            st.success(f"✅ Successfully Registered: {name}")

# --- 6. MAIN ---
def main():
    init_db()
    nav, ela_sensitivity = draw_sidebar()

    if nav == "Dashboard": show_dashboard()
    elif nav == "Forensic Lab": 
        # (Existing single-file lab code goes here)
        st.warning("Switch to 'Bulk Auditor' for mass analysis or 'Digital Notary' to register assets.")
    elif nav == "Bulk Auditor": show_bulk_auditor(ela_sensitivity)
    elif nav == "Digital Notary": show_registration()
    elif nav == "System Settings":
        st.header("⚙️ System Management")
        st.subheader("🖼️ Forensic Reference Library")
        
        c1, c2 = st.columns(2)
        with c1:
            st.image("https://raw.githubusercontent.com/everestpipkin/ela-analysis/master/example_images/original_ela.jpg", caption="GENUINE: Uniform Noise")
        with c2:
            st.image("https://raw.githubusercontent.com/everestpipkin/ela-analysis/master/example_images/modified_ela.jpg", caption="TAMPERED: High-Intensity Hotspots")
        
        if st.button("Reset Database Logs"):
            log_event("Logs cleared"); st.success("Logs reset.")

if __name__ == "__main__": main()