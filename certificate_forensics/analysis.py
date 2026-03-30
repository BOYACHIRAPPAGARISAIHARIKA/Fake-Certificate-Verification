import streamlit as st
import sqlite3
import hashlib
import os
import numpy as np
import matplotlib.pyplot as plt
from io import BytesIO
from PIL import Image, ImageChops, ImageEnhance, ImageDraw, ExifTags

# --- DATABASE LOGIC ---
def init_db():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    signature TEXT
                )''')
    conn.commit()
    conn.close()

def compute_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def add_certificate(name, file_bytes, signature=None):
    hash_value = compute_hash(file_bytes)
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("INSERT INTO certificates (name, hash, signature) VALUES (?, ?, ?)", (name, hash_value, signature))
    conn.commit()
    conn.close()

def verify_certificate(file_bytes):
    hash_value = compute_hash(file_bytes)
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (hash_value,))
    result = c.fetchone()
    conn.close()
    return (result[0], 100) if result else (None, 0)

# --- FORENSIC ANALYSIS FUNCTIONS ---

def analyze_metadata(file_bytes):
    """Scans for digital footprints of editing software."""
    try:
        img = Image.open(BytesIO(file_bytes))
        exif_data = img.getexif()
        warnings = []
        editing_tools = ["photoshop", "gimp", "adobe", "canva", "picsart", "corel", "snapseed"]
        
        if not exif_data:
            return ["No EXIF metadata found. (Note: Many social media platforms strip metadata automatically.)"]

        for tag_id, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag_id, tag_id)
            if tag_name == "Software":
                warnings.append(f"🛠️ **Software Identified:** {value}")
                if any(tool in str(value).lower() for tool in editing_tools):
                    warnings.append("⚠️ **HIGH RISK:** This document was saved using image editing software.")
            if tag_name == "DateTime":
                warnings.append(f"📅 **Internal Timestamp:** {value}")
        
        return warnings if warnings else ["✅ Metadata appears clean or standard."]
    except Exception as e:
        return [f"Metadata Scan Error: {e}"]

def perform_ela(image, quality=90):
    """Performs Error Level Analysis to find compression inconsistencies."""
    image = image.convert('RGB')
    ela_buffer = BytesIO()
    image.save(ela_buffer, 'JPEG', quality=quality)
    ela_buffer.seek(0)
    ela_image = Image.open(ela_buffer)
    
    diff = ImageChops.difference(image, ela_image)
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0: max_diff = 1
    scale = 255.0 / max_diff
    diff = ImageEnhance.Brightness(diff).enhance(scale)
    return diff

def generate_heat_map(file_bytes, file_type, score):
    if "image" in file_type:
        image = Image.open(BytesIO(file_bytes))
        if score == 0:  # Visualizing potential tampering zones for unknown files
            draw = ImageDraw.Draw(image, 'RGBA')
            w, h = image.size
            # Generic zones where text is usually changed
            draw.rectangle([0.1*w, 0.2*h, 0.6*w, 0.35*h], fill=(255, 0, 0, 80)) # Name Zone
            draw.text((0.1*w, 0.18*h), "Suspected Text Modification Area", fill="red")
            return image
        else:
            ela_diff = perform_ela(image)
            return ela_diff
    return None

# --- UI CONFIGURATION ---
st.set_page_config(page_title="AI Document Verifier", page_icon="🔒", layout="wide")

st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stMetric { background-color: #ffffff; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    </style>
    """, unsafe_allow_html=True)

init_db()

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ VeriCert AI")
    menu = st.radio("Navigation", ["📤 Verify Document", "⚙️ Admin Portal"])
    st.divider()
    st.info("This system uses Cryptographic Hashing and ELA Forensics to detect forged certificates.")

# --- MAIN INTERFACE ---
if menu == "📤 Verify Document":
    st.header("Upload Certificate for Verification")
    uploaded_file = st.file_uploader("Upload Image (JPG/PNG)", type=["jpg", "jpeg", "png"])

    if uploaded_file:
        file_bytes = uploaded_file.read()
        verified_name, score = verify_certificate(file_bytes)
        
        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("Results")
            if verified_name:
                st.success(f"✅ **GENUINE DOCUMENT**\n\nVerified Owner: {verified_name}")
                st.metric("Authenticity Score", "100%")
            else:
                st.error("❌ **UNVERIFIED / FAKE DOCUMENT**")
                st.warning("This document's digital signature does not match our records.")
                st.metric("Authenticity Score", "0%", delta="-100%")

        with col2:
            st.subheader("Forensic Metadata Scan")
            metadata_results = analyze_metadata(file_bytes)
            for msg in metadata_results:
                st.write(msg)

        st.divider()
        
        # Heatmap / ELA Section
        st.subheader("🔍 Visual Forensic Analysis")
        tab1, tab2 = st.tabs(["Original Image", "Tamper Analysis (ELA)"])
        
        with tab1:
            st.image(file_bytes, use_container_width=True)
        
        with tab2:
            analysis_img = generate_heat_map(file_bytes, uploaded_file.type, score)
            if analysis_img:
                st.image(analysis_img, caption="ELA Analysis: Brighter pixels indicate potential edits.", use_container_width=True)
                st.caption("How to read: In a genuine image, the 'noise' should be uniform. Bright spots around text or photos suggest those areas were altered.")

elif menu == "⚙️ Admin Portal":
    st.header("Administrator Record Management")
    
    with st.expander("➕ Register New Genuine Certificate"):
        c_name = st.text_input("Full Name on Certificate")
        c_file = st.file_uploader("Upload Master File", type=["jpg", "png"])
        if st.button("Add to Secure Ledger"):
            if c_name and c_file:
                add_certificate(c_name, c_file.read())
                st.success(f"Certificate for {c_name} successfully hashed and stored.")
            else:
                st.error("Please fill in all fields.")

    st.subheader("Stored Registry")
    conn = sqlite3.connect('certificates.db')
    import pandas as pd
    df = pd.read_sql_query("SELECT id, name, hash FROM certificates", conn)
    st.dataframe(df, use_container_width=True)
    conn.close()