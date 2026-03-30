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
from io import BytesIO
from PIL import Image, ImageChops, ImageEnhance
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from scipy.stats import kurtosis, skew

# --- SYSTEM CONFIGURATION ---
logging.basicConfig(filename='forensic_audit.log', level=logging.INFO)
st.set_page_config(page_title="VeriCert AI Forensic Suite", layout="wide", page_icon="🔐")

# Configure Tesseract path - adjust this to your local environment
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

SYSTEM_VERSION = "2.1.0-Streamlined"

# --- DATABASE ARCHITECTURE ---
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

# --- FORENSIC ENGINE ---
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
    std = np.std(pixels)
    pixel_kurtosis = kurtosis(pixels)
    
    score = 100.0
    if std > 5.0: score -= (std * 2)
    if pixel_kurtosis > 10.0: score -= 20.0
    
    return round(max(0.0, min(100.0, score)), 2), np.mean(pixels), std, pixel_kurtosis

def verify_document(file_bytes):
    h = hashlib.sha256(file_bytes).hexdigest()
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (h,))
    res = c.fetchone()
    conn.close()
    return res[0] if res else None

def extract_text_from_image(image):
    try:
        open_cv_image = np.array(image.convert('RGB'))
        gray = cv2.cvtColor(open_cv_image, cv2.COLOR_BGR2GRAY)
        processed_img = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        return pytesseract.image_to_string(processed_img)
    except:
        return "OCR Engine Unavailable"

# --- PDF GENERATION ---
def generate_forensic_report(filename, owner, score, metadata, ela_img_bytes, orig_img_bytes):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica-Bold", 22)
    p.setFillColor(colors.navy)
    p.drawString(100, height - 50, "FORENSIC AUTHENTICATION REPORT")
    
    p.setFont("Helvetica", 10)
    p.setFillColor(colors.black)
    p.drawString(100, height - 70, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p.line(100, height - 75, 500, height - 75)

    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, height - 110, "1. Executive Summary")
    p.setFont("Helvetica", 12)
    status = "GENUINE" if score > 85 else "SUSPICIOUS"
    p.drawString(120, height - 130, f"Status: {status}")
    p.drawString(120, height - 150, f"Identity: {owner}")
    p.drawString(120, height - 170, f"Confidence: {score}%")

    orig_img = ImageReader(BytesIO(orig_img_bytes))
    p.drawImage(orig_img, 100, height - 400, width=180, height=200, preserveAspectRatio=True)
    ela_img = ImageReader(BytesIO(ela_img_bytes))
    p.drawImage(ela_img, 300, height - 400, width=180, height=200, preserveAspectRatio=True)

    p.showPage()
    p.save()
    return buffer.getvalue()

# --- MAIN APP ---
def main():
    init_db()
    
    with st.sidebar:
        st.title("Admin Controls")
        nav = st.radio("Workspace", ["Dashboard", "Forensic Lab", "System Settings"])
        sens = st.slider("ELA Sensitivity", 1.0, 20.0, 8.0)

    if nav == "Dashboard":
        st.header("System Overview")
        # Logic for dashboard stats here...
        st.info("Select 'Forensic Lab' to begin analysis.")

    elif nav == "Forensic Lab":
        st.markdown("## 🔬 Advanced Forensic Laboratory")
        up_file = st.file_uploader("Upload Document", type=["jpg", "png", "jpeg"])
        
        if up_file:
            if 'results' not in st.session_state or st.session_state.get('last_file') != up_file.name:
                st.session_state.results = {}
                st.session_state.last_file = up_file.name

            f_bytes = up_file.getvalue()
            img = Image.open(BytesIO(f_bytes))
            
            # Step 1-6: Analysis (Simplified for flow)
            owner = verify_document(f_bytes)
            ela_img = perform_ela(img, enhancement=sens)
            score, m, s, k = analyze_noise_distribution(ela_img)
            ocr_text = extract_text_from_image(img)
            
            col1, col2 = st.columns(2)
            with col1: st.image(img, caption="Original")
            with col2: st.image(ela_img, caption="Error Map")

            # --- SIMPLIFIED STEP 7: VERDICT ---
            st.subheader("📊 Step 7: Forensic Verdict")
            health_color = "green" if score > 85 else "orange" if score > 60 else "red"
            
            st.markdown(f"""
                <div style="border: 2px solid {health_color}; border-radius: 10px; padding: 20px; text-align: center;">
                    <h2 style="color: {health_color}; margin: 0;">Integrity Score: {score}%</h2>
                    <p style="font-size: 1.2em;">Verdict: <b>{"AUTHENTIC" if score > 85 else "PROBABLE TAMPERING"}</b></p>
                </div>
            """, unsafe_allow_html=True)

            # --- AUTOMATED STEP 8: PDF REPORT ---
            st.divider()
            st.subheader("📄 Step 8: Export Official Report")
            
            try:
                ela_buf = BytesIO()
                ela_img.save(ela_buf, format="PNG")
                
                pdf_data = generate_forensic_report(
                    up_file.name, owner if owner else "Unregistered", 
                    score, ["Analysis Complete"], ela_buf.getvalue(), f_bytes
                )
                
                st.download_button(
                    label="📥 Download Forensic PDF Report",
                    data=pdf_data,
                    file_name=f"Report_{up_file.name}.pdf",
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"Report error: {e}")

    elif nav == "System Settings":
        st.write(f"Version: {SYSTEM_VERSION}")

if __name__ == "__main__":
    main()