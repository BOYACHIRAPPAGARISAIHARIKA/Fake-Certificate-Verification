import streamlit as st
import sqlite3
import hashlib
import numpy as np
import pandas as pd
import datetime
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
import plotly.figure_factory as ff
import plotly.express as px

# --- 1. SYSTEM INITIALIZATION ---
TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.path.exists(TESSERACT_PATH):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

st.set_page_config(page_title="VeriCert AI Forensic Suite", layout="wide", page_icon="🔐")

def init_db():
    conn = sqlite3.connect('vericert_enterprise.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS certificates 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hash TEXT, reg_date TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, timestamp TIMESTAMP)''')
    conn.commit()
    conn.close()

def log_event(event):
    conn = sqlite3.connect('vericert_enterprise.db', check_same_thread=False)
    conn.execute("INSERT INTO logs (event, timestamp) VALUES (?, ?)", (event, datetime.datetime.now()))
    conn.commit()
    conn.close()

# --- 2. FORENSIC ENGINE ---
def perform_ela(image, enhancement=10.0):
    original = image.convert('RGB')
    temp_buf = BytesIO()
    original.save(temp_buf, 'JPEG', quality=90)
    resaved = Image.open(BytesIO(temp_buf.getvalue()))
    diff = ImageChops.difference(original, resaved)
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema]) or 1
    scale = (255.0 / max_diff) * enhancement
    return ImageEnhance.Brightness(diff).enhance(scale)

def analyze_forensics(ela_image):
    pixels = np.array(ela_image.convert('L')).flatten()
    std_val = np.std(pixels)
    kurt_val = kurtosis(pixels)
    score = max(0.0, min(100.0, 100.0 - (std_val * 1.8) - (abs(kurt_val) * 2)))
    return round(score, 2), round(np.mean(pixels), 2), round(std_val, 2), round(kurt_val, 2)

# --- 3. UTILITIES ---
def get_file_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def check_registry(file_hash):
    conn = sqlite3.connect('vericert_enterprise.db', check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (file_hash,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def generate_pdf_report(name, score, owner, ela_img):
    buf = BytesIO()
    p = canvas.Canvas(buf, pagesize=letter)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(100, 750, "VERICERT FORENSIC AUDIT REPORT")
    p.setFont("Helvetica", 12)
    p.drawString(100, 720, f"File: {name} | Score: {score}%")
    p.drawString(100, 705, f"Verified Owner: {owner if owner else 'UNREGISTERED'}")
    
    ela_buf = BytesIO()
    ela_img.save(ela_buf, format="PNG")
    p.drawImage(ImageReader(ela_buf), 100, 400, width=300, height=250)
    p.drawString(100, 385, "Error Level Analysis Map")
    p.showPage()
    p.save()
    return buf.getvalue()

# --- 4. STREAMLIT UI ---
def main():
    init_db()
    st.sidebar.title("🛡️ Forensic Control")
    mode = st.sidebar.selectbox("Workspace", ["Forensic Lab", "Registry Admin", "System Logs"])
    ela_boost = st.sidebar.slider("ELA Boost", 1.0, 30.0, 10.0)

    if mode == "Forensic Lab":
        st.header("🔬 Forensic Laboratory")
        up_file = st.file_uploader("Upload Image", type=["jpg", "jpeg", "png"])
        
        if up_file:
            img_bytes = up_file.getvalue()
            img = Image.open(BytesIO(img_bytes))
            
            c1, c2 = st.columns(2)
            with c1: st.image(img, caption="Original", use_container_width=True)
            
            if st.button("🚀 Run Full Audit"):
                # 1. Logic
                owner = check_registry(get_file_hash(img_bytes))
                ela_img = perform_ela(img, enhancement=ela_boost)
                score, m, s, k = analyze_forensics(ela_img)
                
                # 2. Results
                with c2: st.image(ela_img, caption="ELA Result", use_container_width=True)
                
                st.divider()
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Authenticity Score", f"{score}%")
                m2.metric("Registry Match", "✅ Verified" if owner else "❌ None")
                m3.metric("Noise Std Dev", s)
                m4.metric("Kurtosis", k)

                
                

                # 4. Report
                pdf = generate_pdf_report(up_file.name, score, owner, ela_img)
                st.download_button("📥 Download Official Report", pdf, f"Report_{up_file.name}.pdf", "application/pdf")
                log_event(f"Audit: {up_file.name} | Score: {score}")

    elif mode == "Registry Admin":
        st.header("📝 Registration")
        reg_name = st.text_input("Owner Name")
        reg_file = st.file_uploader("Document", type=["jpg", "jpeg", "png"])
        if st.button("Register") and reg_file and reg_name:
            h = get_file_hash(reg_file.getvalue())
            conn = sqlite3.connect('vericert_enterprise.db')
            conn.execute("INSERT INTO certificates (name, hash, reg_date) VALUES (?, ?, ?)", 
                         (reg_name, h, datetime.datetime.now()))
            conn.commit()
            st.success(f"Registered {reg_name}")

    elif mode == "System Logs":
        st.header("📋 Logs")
        conn = sqlite3.connect('vericert_enterprise.db')
        st.dataframe(pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC", conn), use_container_width=True)

if __name__ == "__main__":
    main()