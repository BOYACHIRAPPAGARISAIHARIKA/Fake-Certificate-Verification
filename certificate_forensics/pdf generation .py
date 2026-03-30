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

# Tesseract Path (Update this if your installation path is different)
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

def log_event(event, user="Admin"):
    try:
        conn = sqlite3.connect('vericert_enterprise.db')
        c = conn.cursor()
        c.execute("INSERT INTO logs (event, user, timestamp) VALUES (?, ?, ?)", 
                  (event, user, datetime.datetime.now()))
        conn.commit()
        conn.close()
    except: pass

# --- 3. FORENSIC ANALYTICS ENGINE ---
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
    pixels_clean = pixels[pixels > 5] # Filter black background
    if len(pixels_clean) == 0: return 100.0, 0, 0, 0
    
    std = np.std(pixels_clean)
    kurt = kurtosis(pixels_clean)
    mean = np.mean(pixels_clean)
    
    # Forensic Score Heuristic
    score = max(0.0, min(100.0, 100.0 - (std * 1.5) - (abs(kurt) * 2)))
    return round(score, 2), mean, std, kurt

def verify_document(file_bytes):
    h = hashlib.sha256(file_bytes).hexdigest()
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (h,))
    res = c.fetchone()
    conn.close()
    return res[0] if res else None

def extract_text(image):
    try:
        open_cv_image = np.array(image.convert('RGB'))
        gray = cv2.cvtColor(open_cv_image, cv2.COLOR_BGR2GRAY)
        processed_img = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        return pytesseract.image_to_string(processed_img)
    except: return "OCR Engine Unavailable"

# --- 4. REPORT GENERATION ENGINE ---
def generate_pdf_report(name, score, status, orig_bytes, ela_img):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    w, h = letter
    
    # Header
    p.setFillColor(colors.navy)
    p.rect(0, h-80, w, 80, fill=1)
    p.setFillColor(colors.white)
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, h-50, "FORENSIC VERIFICATION REPORT")
    
    # Summary
    p.setFillColor(colors.black)
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, h-120, f"Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    p.drawString(50, h-140, f"Status: {status}")
    p.drawString(50, h-160, f"Authenticity Score: {score}%")
    p.drawString(50, h-180, f"Registered To: {name if name else 'Unregistered'}")

    # Visual Evidence
    ela_buf = BytesIO()
    ela_img.save(ela_buf, format="PNG")
    p.drawImage(ImageReader(BytesIO(orig_bytes)), 50, h-450, width=240, height=200, preserveAspectRatio=True)
    p.drawImage(ImageReader(ela_buf), 310, h-450, width=240, height=200, preserveAspectRatio=True)
    
    p.setFont("Helvetica-Bold", 10)
    p.drawString(110, h-465, "SOURCE DOCUMENT")
    p.drawString(380, h-465, "ELA ERROR MAP")

    p.showPage()
    p.save()
    return buffer.getvalue()

# --- 5. UI VIEWS ---
def show_dashboard():
    st.markdown("## 📊 System Overview")
    conn = sqlite3.connect('vericert_enterprise.db')
    c1, c2, c3 = st.columns(3)
    
    total_certs = pd.read_sql_query("SELECT COUNT(*) FROM certificates", conn).iloc[0,0]
    total_logs = pd.read_sql_query("SELECT COUNT(*) FROM logs", conn).iloc[0,0]
    
    c1.metric("Registered Assets", total_certs)
    c2.metric("Audit Logs", total_logs)
    c3.metric("System Health", "Optimal")
    
    st.subheader("Recent Activity")
    logs = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10", conn)
    st.dataframe(logs, use_container_width=True)
    conn.close()

def show_forensic_lab(sens):
    st.markdown("## 🔬 Advanced Forensic Laboratory")
    up_file = st.file_uploader("Upload Document (High-Res)", type=["jpg", "png", "jpeg"])
    
    if up_file:
        file_bytes = up_file.getvalue()
        img = Image.open(BytesIO(file_bytes))
        
        # UI Columns
        col1, col2 = st.columns(2)
        with col1:
            st.image(img, caption="Original Document", use_container_width=True)
            owner = verify_document(file_bytes)
            if owner: st.success(f"✅ Verified Owner: {owner}")
            else: st.error("⚠️ Document is UNREGISTERED")
            
        with col2:
            ela_img = perform_ela(img, enhancement=sens)
            fig, ax = plt.subplots()
            ax.imshow(ela_img, cmap='magma')
            ax.axis('off')
            st.pyplot(fig)
            plt.close(fig)

        # Statistical Metrics
        score, m, s, k = analyze_noise(ela_img)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Authenticity Index", f"{score}%")
        m2.metric("Noise StdDev", f"{s:.2f}")
        m3.metric("Kurtosis", f"{k:.2f}")
        m4.metric("Mean Intensity", f"{m:.2f}")

        # OCR & Report Row
        st.divider()
        r1, r2 = st.columns(2)
        with r1:
            if st.button("Run OCR Verification"):
                text = extract_text(img)
                st.code(text[:500] + "...")
        with r2:
            status = "GENUINE" if score > 80 else "SUSPICIOUS"
            pdf_report = generate_pdf_report(owner, score, status, file_bytes, ela_img)
            st.download_button("📩 Download Forensic Report", pdf_report, "VeriCert_Report.pdf", "application/pdf")

def show_bulk_auditor():
    st.markdown("## 📂 Bulk Auditor")
    files = st.file_uploader("Upload multiple documents", accept_multiple_files=True)
    if files:
        results = []
        for f in files:
            f_bytes = f.getvalue()
            img = Image.open(BytesIO(f_bytes))
            score, _, _, _ = analyze_noise(perform_ela(img))
            results.append({"Filename": f.name, "Score": score, "Status": "Pass" if score > 80 else "Review"})
        st.table(pd.DataFrame(results))

def show_settings():
    st.markdown("## ⚙️ System Settings")
    st.subheader("Asset Registration")
    with st.form("reg_form"):
        name = st.text_input("Assign Identity/Owner Name")
        doc = st.file_uploader("Upload Original Master Copy")
        if st.form_submit_button("Register Secure Hash"):
            if name and doc:
                h = hashlib.sha256(doc.getvalue()).hexdigest()
                conn = sqlite3.connect('vericert_enterprise.db')
                conn.execute("INSERT INTO certificates (name, hash, reg_date) VALUES (?,?,?)", 
                             (name, h, datetime.datetime.now()))
                conn.commit()
                conn.close()
                st.success(f"Successfully registered {name}")
                log_event(f"Registered new asset: {name}")

# --- 6. MAIN CONTROLLER ---
def main():
    init_db()
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/1067/1067357.png", width=80)
        st.title("Admin Controls")
        nav = st.radio("Switch Workspace", ["Dashboard", "Forensic Lab", "Bulk Auditor", "System Settings"])
        st.divider()
        sens = st.slider("ELA Enhancement", 1.0, 20.0, 10.0)
        
    if nav == "Dashboard": show_dashboard()
    elif nav == "Forensic Lab": show_forensic_lab(sens)
    elif nav == "Bulk Auditor": show_bulk_auditor()
    elif nav == "System Settings": show_settings()

if __name__ == "__main__":
    main()
    
    
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

# --- 3. FORENSIC ANALYTICS ENGINE ---
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
    pixels_clean = pixels[pixels > 5] 
    if len(pixels_clean) == 0: return 100.0, 0, 0, 0, []
    
    std = np.std(pixels_clean)
    kurt = kurtosis(pixels_clean)
    mean = np.mean(pixels_clean)
    score = max(0.0, min(100.0, 100.0 - (std * 1.5) - (abs(kurt) * 2)))
    return round(score, 2), mean, std, kurt, pixels_clean

# --- 4. UI VIEWS ---
def show_bulk_auditor(sens):
    st.markdown("## 📂 Bulk Forensic Auditor")
    files = st.file_uploader("Upload Batch", accept_multiple_files=True, type=["jpg", "png", "jpeg"])
    
    if files:
        bulk_data = []
        for f in files:
            with st.container():
                st.divider()
                st.subheader(f"📄 File: {f.name}")
                f_bytes = f.getvalue()
                img = Image.open(BytesIO(f_bytes))
                
                # Forensic Processing
                ela_img = perform_ela(img, enhancement=sens)
                score, m, s, k, raw_noise = analyze_noise(ela_img)
                
                # Visual Evidence Row
                c1, c2, c3 = st.columns([1, 1, 1.2])
                with c1:
                    st.image(img, use_container_width=True, caption="Source")
                with c2:
                    fig, ax = plt.subplots()
                    ax.imshow(ela_img, cmap='magma')
                    ax.axis('off')
                    st.pyplot(fig)
                    plt.close(fig)
                with c3:
                    # Statistical Profile Graph
                    fig_hist, ax_hist = plt.subplots(figsize=(5,3))
                    ax_hist.hist(raw_noise, bins=50, color='skyblue', edgecolor='black', alpha=0.7)
                    ax_hist.set_title("Noise Intensity Distribution")
                    st.pyplot(fig_hist)
                    plt.close(fig_hist)
                
                # Metrics Row
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Confidence", f"{score}%")
                m2.metric("Noise StdDev", f"{s:.2f}")
                m3.metric("Kurtosis", f"{k:.2f}")
                status = "PASS" if score > 80 else "REVIEW"
                m4.write(f"**Final Status:** {'✅' if status == 'PASS' else '🚨'} {status}")
                
                bulk_data.append({"Filename": f.name, "Score": score, "StdDev": s, "Kurtosis": k, "Status": status})

        # Export Functionality
        st.divider()
        df = pd.DataFrame(bulk_data)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📊 Export Audit Results to CSV", csv, "Audit_Log.csv", "text/csv")

def show_settings():
    st.markdown("## ⚙️ System Settings")
    with st.form("reg_form"):
        name = st.text_input("Owner Name")
        doc = st.file_uploader("Master Copy")
        if st.form_submit_button("Register Hash"):
            if name and doc:
                h = hashlib.sha256(doc.getvalue()).hexdigest()
                conn = sqlite3.connect('vericert_enterprise.db')
                conn.execute("INSERT INTO certificates (name, hash, reg_date) VALUES (?,?,?)", (name, h, datetime.datetime.now()))
                conn.commit()
                conn.close()
                st.success(f"Registered {name}")

# --- 5. MAIN CONTROLLER ---
def main():
    init_db()
    with st.sidebar:
        st.title("VeriCert AI")
        nav = st.radio("Navigation", ["Dashboard", "Forensic Lab", "Bulk Auditor", "System Settings"])
        sens = st.slider("ELA Intensity", 1.0, 20.0, 10.0)
        
    if nav == "Dashboard": 
        st.write("Welcome to VeriCert Dashboard. Select a workspace to begin.")
    elif nav == "Forensic Lab": 
        # (Include your existing forensic_lab logic here)
        st.write("Forensic Lab active.") 
    elif nav == "Bulk Auditor": 
        show_bulk_auditor(sens)
    elif nav == "System Settings": 
        show_settings()

if __name__ == "__main__":
    main()