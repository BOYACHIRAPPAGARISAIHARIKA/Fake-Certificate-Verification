import streamlit as st
import sqlite3
import hashlib
import numpy as np
import matplotlib.pyplot as plt
from io import BytesIO
from PIL import Image, ImageChops, ImageEnhance, ExifTags

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

# --- FORENSIC LOGIC ---

def analyze_metadata(file_bytes):
    """Scans for digital footprints of editing software."""
    try:
        img = Image.open(BytesIO(file_bytes))
        exif_data = img.getexif()
        warnings = []
        editing_tools = ["photoshop", "gimp", "adobe", "canva", "picsart", "corel", "snapseed"]
        
        if not exif_data:
            return ["No EXIF metadata found. (Note: Many platforms strip metadata automatically.)"]

        for tag_id, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag_id, tag_id)
            if tag_name == "Software":
                warnings.append(f"🛠️ **Software:** {value}")
                if any(tool in str(value).lower() for tool in editing_tools):
                    warnings.append("⚠️ **WARNING:** Document likely modified in an editor.")
            if tag_name == "DateTime":
                warnings.append(f"📅 **Timestamp:** {value}")
        return warnings if warnings else ["✅ Metadata appears clean."]
    except: return ["Metadata Scan Error."]

def perform_ela(image, quality, enhancement):
    """Performs ELA with adjustable sensitivity."""
    image = image.convert('RGB')
    ela_buffer = BytesIO()
    image.save(ela_buffer, 'JPEG', quality=quality)
    ela_buffer.seek(0)
    ela_image = Image.open(ela_buffer)
    
    diff = ImageChops.difference(image, ela_image)
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0: max_diff = 1
    
    # Apply user-defined enhancement factor
    scale = (255.0 / max_diff) * enhancement
    diff = ImageEnhance.Brightness(diff).enhance(scale)
    return diff

# --- UI CONFIG ---
st.set_page_config(page_title="VeriCert AI", page_icon="🔒", layout="wide")
init_db()

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    st.title("🛡️ Forensic Tools")
    menu = st.radio("Go to", ["📤 Verify Document", "⚙️ Admin Portal"])
    st.divider()
    st.subheader("ELA Settings")
    ela_quality = st.slider("JPEG Quality (for comparison)", 70, 95, 90)
    ela_boost = st.slider("Heatmap Sensitivity", 1.0, 10.0, 3.0)
    st.caption("Lower quality or higher sensitivity makes tampering more visible.")

# --- MAIN PAGE ---
if menu == "📤 Verify Document":
    st.header("Upload Document for Verification")
    uploaded_file = st.file_uploader("Upload Image (JPG/PNG)", type=["jpg", "jpeg", "png"])

    if uploaded_file:
        file_bytes = uploaded_file.read()
        verified_name, score = verify_certificate(file_bytes)
        
        # Display Metrics
        c1, c2 = st.columns(2)
        with c1:
            if verified_name:
                st.success(f"✅ **GENUINE**\n\nOwner: {verified_name}")
            else:
                st.error("❌ **UNVERIFIED / POTENTIALLY FAKE**")
        with c2:
            st.info("🔍 **Forensic Metadata:**")
            for msg in analyze_metadata(file_bytes):
                st.write(msg)

        st.divider()

        # Visual Analysis
        t1, t2 = st.tabs(["Original View", "🔬 Tamper Analysis (Heatmap)"])
        
        with t1:
            st.image(file_bytes, use_container_width=True)
        
        with t2:
            img_obj = Image.open(BytesIO(file_bytes))
            ela_result = perform_ela(img_obj, ela_quality, ela_boost)
            
            # Convert to Heatmap using Matplotlib
            fig, ax = plt.subplots()
            # 'magma' or 'inferno' are great for showing small variations
            im = ax.imshow(np.array(ela_result.convert('L')), cmap='magma')
            ax.axis('off')
            plt.colorbar(im, ax=ax, label="Error Level Intensity")
            st.pyplot(fig)
            
            st.warning("**How to read this:** In a genuine photo, the colors should be mostly uniform. If you see bright 'shining' pixels around a specific name or date while the rest of the image is dark, that area has been edited.")

elif menu == "⚙️ Admin Portal":
    st.header("Registration Ledger")
    name = st.text_input("Candidate Name")
    file = st.file_uploader("Original Certificate", type=["jpg", "png"])
    if st.button("Register Certificate"):
        if name and file:
            add_certificate(name, file.read())
            st.success(f"Hash stored for {name}")

    # View database
    conn = sqlite3.connect('certificates.db')
    import pandas as pd
    df = pd.read_sql_query("SELECT id, name, hash FROM certificates", conn)
    st.table(df)
    conn.close()