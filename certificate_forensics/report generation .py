import streamlit as st
import sqlite3
import hashlib
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import datetime
import pytesseract
import gc
from io import BytesIO
from PIL import Image, ImageChops
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# -----------------------------
# Tesseract Path
# -----------------------------
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

SYSTEM_VERSION = "2.1.0-Stable"
DATABASE_NAME = "vericert_enterprise.db"

# -----------------------------
# DATABASE
# -----------------------------
def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS certificates
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT, hash TEXT, date TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  action TEXT, user TEXT, time TIMESTAMP)""")
    conn.commit()
    conn.close()

def compute_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def verify_hash(file_bytes):
    h = compute_hash(file_bytes)
    conn = sqlite3.connect(DATABASE_NAME)
    result = conn.execute(
        "SELECT name FROM certificates WHERE hash=?", (h,)
    ).fetchone()
    conn.close()
    return result[0] if result else None

# -----------------------------
# SAFE IMAGE LOADER
# -----------------------------
def load_and_resize(file_bytes, max_dim=1000):
    image = Image.open(BytesIO(file_bytes))
    image = image.convert("RGB")

    # Controlled resize
    if image.width > max_dim or image.height > max_dim:
        ratio = min(max_dim / image.width, max_dim / image.height)
        new_size = (int(image.width * ratio), int(image.height * ratio))
        image = image.resize(new_size)

    return image

# -----------------------------
# LIGHTWEIGHT ELA
# -----------------------------
def get_ela(image, quality=85):
    buffer = BytesIO()
    image.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)
    resaved = Image.open(buffer).convert("RGB")

    ela = ImageChops.difference(image, resaved)
    ela = ela.convert("L")
    return ela

# -----------------------------
# AUTH SCORE (LIGHT)
# -----------------------------
def get_auth_score(ela_image):
    pixels = np.array(ela_image)
    std_dev = np.std(pixels)
    score = 100 - (std_dev * 1.2)
    return round(max(0, min(100, score)), 2)

# -----------------------------
# LIGHT OCR
# -----------------------------
def run_ocr(image):
    gray = image.convert("L")
    return pytesseract.image_to_string(gray)

# -----------------------------
# PDF REPORT
# -----------------------------
def create_pdf_report(filename, score):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(100, 750, "FORENSIC AUTHENTICATION REPORT")
    p.setFont("Helvetica", 12)
    p.drawString(100, 720, f"Document: {filename}")
    p.drawString(100, 700, f"Authenticity Score: {score}%")
    p.drawString(100, 680, f"Status: {'PASS' if score > 80 else 'FLAGGED'}")
    p.drawString(100, 660, f"Generated On: {datetime.datetime.now()}")
    p.save()

    pdf_data = buffer.getvalue()
    buffer.close()
    return pdf_data

# -----------------------------
# MAIN APP
# -----------------------------
def main():
    st.set_page_config(page_title="VeriCert AI Enterprise", layout="wide")
    init_db()

    st.sidebar.title("VeriCert Enterprise")
    st.sidebar.markdown(f"Version: {SYSTEM_VERSION}")
    menu = st.sidebar.selectbox(
        "Workspace",
        ["System Dashboard", "Forensic Lab", "Registry"]
    )

    if menu == "System Dashboard":
        st.title("Security Operations Center")
        col1, col2, col3 = st.columns(3)
        col1.metric("System Status", "Active")
        col2.metric("Engine", "Stable")
        col3.metric("Memory Mode", "Optimized")

    elif menu == "Forensic Lab":
        st.title("Forensic Laboratory")

        file = st.file_uploader(
            "Upload Document (Max Recommended < 8MB)",
            type=["jpg", "jpeg", "png"]
        )

        if file and st.button("Run Forensic Analysis"):
            file_bytes = file.read()

            if file.size > 8 * 1024 * 1024:
                st.error("File too large. Please upload image under 8MB.")
                return

            with st.spinner("Processing document safely..."):
                image = load_and_resize(file_bytes)
                ela_image = get_ela(image)
                score = get_auth_score(ela_image)
                ocr_text = run_ocr(image)
                owner = verify_hash(file_bytes)

            col1, col2 = st.columns([2, 1])

            with col1:
                st.subheader("Compression Heatmap")
                fig, ax = plt.subplots()
                ax.imshow(np.array(ela_image), cmap="magma")
                ax.axis("off")
                st.pyplot(fig)

                st.subheader("Noise Histogram (Sampled)")
                pixels = np.array(ela_image)
                sample = pixels[::4, ::4]  # reduce memory
                fig2, ax2 = plt.subplots()
                ax2.hist(sample.ravel(), bins=30)
                st.pyplot(fig2)

            with col2:
                st.metric("Authenticity Index", f"{score}%")

                if owner:
                    st.success(f"Registry Match: {owner}")
                else:
                    st.warning("No Registry Match")

                st.text_area("OCR Extracted Text", ocr_text, height=200)

                report = create_pdf_report(file.name, score)
                st.download_button(
                    "Download PDF Report",
                    report,
                    f"{file.name}_report.pdf",
                    mime="application/pdf"
                )

            gc.collect()

    elif menu == "Registry":
        st.title("Document Registry")

        name = st.text_input("Assignee Name")
        reg_file = st.file_uploader("Master Certificate")

        if st.button("Register Document"):
            if name and reg_file:
                file_bytes = reg_file.read()
                h = compute_hash(file_bytes)

                conn = sqlite3.connect(DATABASE_NAME)
                conn.execute(
                    "INSERT INTO certificates (name, hash, date) VALUES (?, ?, ?)",
                    (name, h, datetime.datetime.now())
                )
                conn.commit()
                conn.close()

                st.success("Registration Successful")

        conn = sqlite3.connect(DATABASE_NAME)
        df = pd.read_sql_query(
            "SELECT id, name, date FROM certificates",
            conn
        )
        st.dataframe(df)
        conn.close()

if __name__ == "__main__":
    main()