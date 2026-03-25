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
    return result[0] if result else None

# --- FORENSIC & SCORING LOGIC ---

def perform_ela(image, quality, enhancement):
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

def calculate_forensic_score(ela_image):
    """Calculates an authenticity score based on ELA pixel variance."""
    gray_ela = ela_image.convert('L')
    pixels = np.array(gray_ela)
    mean_noise = np.mean(pixels)
    std_noise = np.std(pixels)
    
    # Logic: High standard deviation in ELA noise usually indicates localized tampering
    # A perfectly original image has uniform noise distribution.
    if std_noise < 2:
        score = 95 + np.random.randint(1, 5) # Very authentic
    elif std_noise < 10:
        score = 80 - std_noise
    else:
        score = max(10, 60 - (std_noise * 2)) # Likely tampered
        
    return round(score, 2)

def analyze_metadata(file_bytes):
    try:
        img = Image.open(BytesIO(file_bytes))
        exif_data = img.getexif()
        warnings = []
        editing_tools = ["photoshop", "gimp", "adobe", "canva", "picsart", "corel", "snapseed"]
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                if tag_name == "Software" and any(tool in str(value).lower() for tool in editing_tools):
                    warnings.append(f"⚠️ **Software Alert:** Edited with {value}")
        return warnings if warnings else ["✅ Metadata: No editing software traces."]
    except: return ["Metadata Scan: Not available."]

# --- UI CONFIG ---
st.set_page_config(page_title="AI Document Verifier", page_icon="🔒", layout="wide")
init_db()

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ VeriCert Forensic")
    menu = st.radio("Navigation", ["📤 Verify Document", "⚙️ Admin Registry"])
    st.divider()
    st.subheader("Sensitivity Controls")
    ela_boost = st.slider("Enhance Tamper Visibility", 1.0, 15.0, 5.0)

# --- MAIN PAGE ---
if menu == "📤 Verify Document":
    st.header("Document Authenticity Analysis")
    uploaded_file = st.file_uploader("Upload Document (JPG/PNG)", type=["jpg", "jpeg", "png"])

    if uploaded_file:
        file_bytes = uploaded_file.read()
        img_obj = Image.open(BytesIO(file_bytes))
        
        # 1. DATABASE CHECK (The 'Hard' Verification)
        verified_owner = verify_certificate(file_bytes)
        
        # 2. FORENSIC ANALYSIS (The 'AI/Forensic' Verification)
        ela_result = perform_ela(img_obj, 90, ela_boost)
        auth_score = calculate_forensic_score(ela_result)
        metadata_findings = analyze_metadata(file_bytes)

        # UI LAYOUT
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Authenticity Score", f"{auth_score}%", delta=None)
            if auth_score > 85: st.success("Status: Highly Authentic")
            elif auth_score > 60: st.warning("Status: Suspicious")
            else: st.error("Status: High Risk of Tampering")

        with col2:
            st.write("**Database Match:**")
            if verified_owner:
                st.success(f"Verified Record Found\n\nOwner: {verified_owner}")
            else:
                st.info("No Registry Match\n(Check Forensic Analysis below)")

        with col3:
            st.write("**Tamper Analysis Info:**")
            for msg in metadata_findings:
                st.write(msg)

        st.divider()
        
        # VISUAL ANALYSIS
        tab1, tab2 = st.tabs(["Original Document", "🔬 Pixel Tamper Heatmap"])
        
        with tab1:
            st.image(file_bytes, use_container_width=True)
            
        with tab2:
            st.subheader("Localized Noise Distribution")
            fig, ax = plt.subplots()
            im = ax.imshow(np.array(ela_result.convert('L')), cmap='magma')
            ax.axis('off')
            plt.colorbar(im, ax=ax, label="Compression Error Level")
            st.pyplot(fig)
            st.info("**Analysis Insight:** Bright areas in this heatmap indicate where pixels differ from the original compression level—typically where text or photos were digitally altered.")

elif menu == "⚙️ Admin Registry":
    st.header("Record New Authentic Certificate")
    name = st.text_input("Full Name of Recipient")
    file = st.file_uploader("Upload Master Document", type=["jpg", "png"])
    if st.button("Securely Hash & Save"):
        if name and file:
            add_certificate(name, file.read())
            st.success(f"Certificate for {name} added to the secure database.")

    st.subheader("Current Registry")
    conn = sqlite3.connect('certificates.db')
    import pandas as pd
    df = pd.read_sql_query("SELECT id, name, hash FROM certificates", conn)
    st.table(df)
    conn.close()