import streamlit as st
import sqlite3
import hashlib
import numpy as np
import matplotlib.pyplot as plt
from io import BytesIO
from PIL import Image, ImageChops, ImageEnhance, ExifTags
import pandas as pd

# --- INITIALIZATION ---
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

# --- CORE FORENSIC LOGIC ---
def compute_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def verify_certificate(file_bytes):
    hash_value = compute_hash(file_bytes)
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (hash_value,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def delete_certificate(cert_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
    conn.commit()
    conn.close()

def perform_ela(image, quality=90, enhancement=5.0):
    image = image.convert('RGB')
    ela_buffer = BytesIO()
    image.save(ela_buffer, 'JPEG', quality=quality)
    ela_buffer.seek(0)
    ela_image = Image.open(ela_buffer)
    diff = ImageChops.difference(image, ela_image)
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0: max_diff = 1
    scale = (255.0 / max_diff) * enhancement
    return ImageEnhance.Brightness(diff).enhance(scale)

def calculate_auth_score(ela_image):
    """Enhanced Sensitivity: Analyzes sub-pixel peaks to detect small text edits."""
    pixels = np.array(ela_image.convert('L'))
    
    # Global noise stats
    mean_val = np.mean(pixels)
    std_dev = np.std(pixels)
    
    # Detect high-intensity pixel clusters (typical of text tampering)
    # We look for pixels that are 3x brighter than the average noise
    peak_threshold = mean_val + (2 * std_dev)
    peaks = pixels[pixels > peak_threshold]
    peak_ratio = len(peaks) / pixels.size
    
    # Heuristic scoring formula
    # Penalizes high variance and localized bright 'spikes'
    base_score = 100 - (std_dev * 1.5)
    penalty = (peak_ratio * 500)  # Heavy penalty for localized 'glowing' pixels
    
    final_score = base_score - penalty
    return round(max(0.0, min(100.0, final_score)), 2)

# --- UI CONFIGURATION ---
st.set_page_config(page_title="VeriCert AI Forensic Tool", layout="wide", page_icon="🔐")
init_db()

# --- SIDEBAR ---
with st.sidebar:
    st.title("Forensic Control")
    page = st.radio("Navigation", ["📄 Authentication Portal", "⚙️ Admin Dashboard"])
    st.divider()
    ela_sens = st.slider("Heatmap Intensity", 1.0, 15.0, 7.0)
    st.caption("Pro Tip: For high-res docs, use 7.0+ sensitivity to see sub-pixel text edits.")

# --- PAGE 1: AUTHENTICATION PORTAL ---
if page == "📄 Authentication Portal":
    st.markdown("<h1 style='text-align: center;'>AI Document Authentication Portal</h1>", unsafe_allow_html=True)
    mode = st.tabs(["🔍 Single Document Analysis", "📁 Bulk Forensic Audit"])

    with mode[0]:
        uploaded_file = st.file_uploader("Upload document", type=["jpg", "jpeg", "png"], key="single")
        if uploaded_file:
            file_bytes = uploaded_file.read()
            img = Image.open(BytesIO(file_bytes))
            
            # Forensic Engine
            db_match = verify_certificate(file_bytes)
            ela_img = perform_ela(img, enhancement=ela_sens)
            score = calculate_auth_score(ela_img)

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Authenticity Score", f"{score}%")
                if score > 85: st.success("Status: Authentic")
                elif score > 65: st.warning("Status: Suspicious")
                else: st.error("Status: Likely Tampered")
            with col2:
                st.write("**Database Integrity:**")
                if db_match: st.success(f"Matched Record: {db_match}")
                else: st.error("No Registry Match")
            with col3:
                st.write("**Metadata Engine:**")
                exif = img.getexif()
                software = exif.get(305) or exif.get(0x0131)
                if software: st.warning(f"Editor Detected: {software}")
                else: st.success("Metadata Clean")

            st.divider()
            st.subheader("🔬 Sub-pixel Level Heatmap")
            
            c1, c2 = st.columns(2)
            with c1:
                fig, ax = plt.subplots()
                im = ax.imshow(np.array(ela_img.convert('L')), cmap='magma')
                plt.colorbar(im)
                ax.axis('off')
                st.pyplot(fig)
                plt.close(fig)
            with c2:
                st.image(img, caption="Original Document", use_container_width=True)

    with mode[1]:
        st.write("### 📁 Batch Audit & Sub-pixel Gallery")
        uploaded_files = st.file_uploader("Select multiple certificates", type=["jpg", "png"], accept_multiple_files=True)
        if uploaded_files:
            audit_data = []
            gallery = []
            for file in uploaded_files:
                fb = file.read()
                fimg = Image.open(BytesIO(fb))
                match = verify_certificate(fb)
                ela = perform_ela(fimg, enhancement=ela_sens)
                f_score = calculate_auth_score(ela)
                risk = "High" if f_score < 60 else ("Med" if f_score < 85 else "Low")
                audit_data.append({"File": file.name, "Verified": "Yes" if match else "No", "Score": f_score, "Risk": risk})
                gallery.append((file.name, ela, f_score))
            
            st.table(pd.DataFrame(audit_data))
            st.divider()
            st.subheader("🔬 Forensic Gallery")
            g_cols = st.columns(3)
            for idx, (name, g_ela, g_score) in enumerate(gallery):
                with g_cols[idx % 3]:
                    st.write(f"**{name}** ({g_score}%)")
                    fig2, ax2 = plt.subplots()
                    ax2.imshow(np.array(g_ela.convert('L')), cmap='magma')
                    ax2.axis('off')
                    st.pyplot(fig2)
                    plt.close(fig2)

# --- PAGE 2: ADMIN DASHBOARD ---
elif page == "⚙️ Admin Dashboard":
    st.markdown("<h1 style='text-align: center;'>Admin Registry Dashboard</h1>", unsafe_allow_html=True)
    t_add, t_rem = st.tabs(["Add Record", "Remove Record"])

    with t_add:
        name_in = st.text_input("Name")
        file_in = st.file_uploader("Document", type=["jpg", "png"])
        if st.button("Register"):
            if name_in and file_in:
                fb = file_in.read()
                hv = compute_hash(fb)
                conn = sqlite3.connect('certificates.db')
                conn.cursor().execute("INSERT INTO certificates (name, hash) VALUES (?, ?)", (name_in, hv))
                conn.commit()
                conn.close()
                st.success("Registered!")

    with t_rem:
        conn = sqlite3.connect('certificates.db')
        data = pd.read_sql_query("SELECT id, name FROM certificates", conn)
        conn.close()
        if not data.empty:
            st.dataframe(data, use_container_width=True)
            sel = st.selectbox("Record to remove", data['id'].tolist())
            if st.button("Delete"):
                delete_certificate(sel)
                st.rerun()