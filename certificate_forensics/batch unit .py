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
    pixels = np.array(ela_image.convert('L'))
    std_dev = np.std(pixels)
    if std_dev < 2.5: 
        return round(98.5 - std_dev, 2)
    return round(max(5.0, 90.0 - (std_dev * 1.8)), 2)

# --- UI CONFIGURATION ---
st.set_page_config(page_title="VeriCert AI Forensic Tool", layout="wide", page_icon="🔐")
init_db()

st.markdown("""
    <style>
    .main-header { font-size: 32px; font-weight: bold; color: #1E3A8A; text-align: center; margin-bottom: 10px; }
    .stMetric { background-color: #ffffff; border-radius: 10px; padding: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/1067/1067357.png", width=80)
    st.title("Forensic Control")
    page = st.radio("Navigation", ["📄 Authentication Portal", "⚙️ Admin Dashboard"])
    st.divider()
    st.subheader("Analysis Parameters")
    ela_sens = st.slider("Heatmap Intensity", 1.0, 15.0, 5.0)

# --- PAGE 1: AUTHENTICATION PORTAL ---
if page == "📄 Authentication Portal":
    st.markdown('<div class="main-header">AI Document Authentication System</div>', unsafe_allow_html=True)
    mode = st.tabs(["🔍 Single Verification", "📁 Batch Processing Audit"])

    with mode[0]:
        uploaded_file = st.file_uploader("Upload document for analysis", type=["jpg", "jpeg", "png"], key="single")
        if uploaded_file:
            file_bytes = uploaded_file.read()
            img = Image.open(BytesIO(file_bytes))
            db_match = verify_certificate(file_bytes)
            ela_img = perform_ela(img, enhancement=ela_sens)
            score = calculate_auth_score(ela_img)

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Authenticity Score", f"{score}%")
                if score > 80: st.success("Result: Authentic")
                elif score > 55: st.warning("Result: Suspicious")
                else: st.error("Result: High Tamper Risk")
            with col2:
                st.write("**Database Check:**")
                if db_match: st.success(f"✅ Verified Genuine\n\nOwner: {db_match}")
                else: st.error("❌ Registry Match Failed")
            with col3:
                st.write("**Metadata Scan:**")
                exif = img.getexif()
                software = exif.get(305) or exif.get(0x0131)
                if software: st.warning(f"🚩 Editor Found: {software}")
                else: st.success("📩 No Editor Signatures")

            st.divider()
            st.subheader("🔬 Visual Forensic Heatmap (ELA)")
            c_left, c_right = st.columns(2)
            with c_left:
                fig, ax = plt.subplots()
                im = ax.imshow(np.array(ela_img.convert('L')), cmap='inferno')
                plt.colorbar(im)
                ax.axis('off')
                st.pyplot(fig)
                plt.close(fig)
            with c_right:
                st.image(img, caption="Original Document", use_container_width=True)

    with mode[1]:
        uploaded_files = st.file_uploader("Select multiple files", type=["jpg", "png"], accept_multiple_files=True, key="batch")
        if uploaded_files:
            audit_data = []
            for file in uploaded_files:
                f_bytes = file.read()
                f_img = Image.open(BytesIO(f_bytes))
                match = verify_certificate(f_bytes)
                score = calculate_auth_score(perform_ela(f_img))
                audit_data.append({"File Name": file.name, "In Database": "Yes" if match else "No", "Score (%)": score, "Risk": "High" if score < 60 else "Low"})
            df = pd.DataFrame(audit_data)
            st.table(df)

# --- PAGE 2: ADMIN DASHBOARD (MODIFIED WITH REMOVAL FEATURE) ---
elif page == "⚙️ Admin Dashboard":
    st.markdown('<div class="main-header">Authorized Registry Management</div>', unsafe_allow_html=True)
    
    tab_add, tab_remove = st.tabs(["➕ Add Records", "🗑️ Remove Records"])

    with tab_add:
        c1, c2 = st.columns([1, 2])
        with c1:
            st.subheader("Register New Master")
            new_name = st.text_input("Candidate Name")
            new_file = st.file_uploader("Upload Authentic Certificate", type=["jpg", "png"])
            if st.button("Secure & Register"):
                if new_name and new_file:
                    add_certificate_logic = lambda n, f: add_certificate_to_db(n, f) # Logic below
                    fb = new_file.read()
                    hv = compute_hash(fb)
                    conn = sqlite3.connect('certificates.db')
                    c = conn.cursor()
                    c.execute("INSERT INTO certificates (name, hash) VALUES (?, ?)", (new_name, hv))
                    conn.commit()
                    conn.close()
                    st.success(f"Registered {new_name}")

    with tab_remove:
        st.subheader("Manage Existing Records")
        conn = sqlite3.connect('certificates.db')
        data = pd.read_sql_query("SELECT id, name, hash FROM certificates", conn)
        conn.close()

        if not data.empty:
            st.dataframe(data, use_container_width=True)
            
            # Selection for deletion
            st.divider()
            col_del1, col_del2 = st.columns([2, 1])
            with col_del1:
                # Create a list of options: "ID: Name"
                options = {f"ID {row['id']}: {row['name']}": row['id'] for index, row in data.iterrows()}
                selection = st.selectbox("Select Record to Remove:", list(options.keys()))
            
            with col_del2:
                st.write("###") # Spacing
                if st.button("🗑️ Delete Selected Record", use_container_width=True):
                    target_id = options[selection]
                    delete_certificate(target_id)
                    st.warning(f"Record {selection} has been removed.")
                    st.rerun() # Refresh to update the table
        else:
            st.info("The registry is currently empty.")