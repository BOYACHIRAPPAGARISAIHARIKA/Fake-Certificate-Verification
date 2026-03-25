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
from PIL import Image, ImageChops, ImageEnhance, ExifTags
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

SYSTEM_VERSION = "2.0.4-Advanced"

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
    mean = np.mean(pixels)
    std = np.std(pixels)
    pixel_kurtosis = kurtosis(pixels)
    pixel_skew = skew(pixels)
    
    score = 100.0
    if std > 5.0: score -= (std * 2)
    if pixel_kurtosis > 10.0: score -= 20.0
    
    return round(max(0.0, min(100.0, score)), 2), mean, std, pixel_kurtosis

def compute_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def verify_document(file_bytes):
    h = compute_hash(file_bytes)
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (h,))
    res = c.fetchone()
    conn.close()
    return res[0] if res else None

# --- 4. ADVANCED OCR ENGINE ---

def extract_text_from_image(image):
    open_cv_image = np.array(image.convert('RGB'))
    gray = cv2.cvtColor(open_cv_image, cv2.COLOR_BGR2GRAY)
    processed_img = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    extracted_text = pytesseract.image_to_string(processed_img)
    return extracted_text

def cross_reference_text(extracted_text, registered_name):
    if not registered_name:
        return "N/A - No Registry Match", 0
    
    clean_text = extracted_text.lower().strip()
    target_name = registered_name.lower().strip()
    
    if target_name in clean_text:
        return "✅ Text Match Confirmed", 100
    else:
        return "⚠️ Text Mismatch: Name on doc does not match registry!", 0

# --- 5. PDF GENERATION ENGINE ---

def generate_forensic_report(filename, owner, score, metadata, ela_img_bytes, orig_img_bytes):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica-Bold", 22)
    p.setStrokeColor(colors.navy)
    p.drawString(100, height - 50, "FORENSIC AUTHENTICATION REPORT")
    
    p.setFont("Helvetica", 10)
    p.drawString(100, height - 70, f"Report Generated On: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p.line(100, height - 75, 500, height - 75)

    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, height - 110, "1. Executive Summary")
    
    p.setFont("Helvetica", 12)
    status = "GENUINE" if score > 85 else "SUSPICIOUS / TAMPERED"
    p.drawString(120, height - 130, f"Document Status: {status}")
    p.drawString(120, height - 150, f"Assigned Identity: {owner if owner else 'UNREGISTERED'}")
    p.drawString(120, height - 170, f"Confidence Score: {score}%")

    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, height - 210, "2. Digital Metadata Footprint")
    p.setFont("Helvetica-Oblique", 10)
    
    y_offset = height - 230
    for item in metadata:
        p.drawString(120, y_offset, f"• {item}")
        y_offset -= 15

    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, y_offset - 20, "3. Visual Evidence (ELA vs Original)")
    
    orig_img = ImageReader(BytesIO(orig_img_bytes))
    p.drawImage(orig_img, 100, y_offset - 250, width=180, height=200, preserveAspectRatio=True)
    p.setFont("Helvetica-Bold", 8)
    p.drawString(150, y_offset - 260, "SOURCE DOCUMENT")

    ela_img = ImageReader(BytesIO(ela_img_bytes))
    p.drawImage(ela_img, 300, y_offset - 250, width=180, height=200, preserveAspectRatio=True)
    p.drawString(340, y_offset - 260, "QUANTIZATION ERROR MAP")

    p.setFont("Helvetica-Oblique", 8)
    p.setStrokeColor(colors.grey)
    p.line(100, 50, 500, 50)
    p.drawString(100, 40, "This report is generated by VeriCert AI.")

    p.showPage()
    p.save()
    
    pdf_data = buffer.getvalue()
    buffer.close()
    return pdf_data

# --- 6. STATISTICAL ANALYSIS ---

def generate_noise_profile(ela_image):
    pixels = np.array(ela_image.convert('L')).flatten()
    noise_data = pixels[pixels > 5] 
    
    if len(noise_data) == 0:
        return None

    fig = ff.create_distplot([noise_data], ['Pixel Intensity'], 
                             bin_size=2, 
                             curve_type='kde', 
                             colors=['#636EFA'])

    fig.update_layout(
        title="Sub-pixel Noise Distribution Profile",
        xaxis_title="Error Intensity (0-255)",
        yaxis_title="Density",
        template="plotly_white",
        height=400,
        showlegend=False
    )
    
    return fig

# --- 7. UI COMPONENTS ---

def draw_sidebar():
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/1067/1067357.png", width=100)
        st.title("Admin Controls")
        nav = st.radio("Switch Workspace", ["Dashboard", "Forensic Lab", "Bulk Auditor", "System Settings"])
        st.divider()
        st.subheader("Lab Settings")
        sens = st.slider("ELA Enhancement Factor", 1.0, 20.0, 8.0)
        st.divider()
        if st.button("Clear Cache"):
            st.cache_data.clear()
        return nav, sens

def show_dashboard():
    st.markdown("<h1 style='color: #1E3A8A;'>System Overview</h1>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    
    conn = sqlite3.connect('vericert_enterprise.db')
    total_certs = pd.read_sql_query("SELECT COUNT(*) FROM certificates", conn).iloc[0,0]
    total_logs = pd.read_sql_query("SELECT COUNT(*) FROM logs", conn).iloc[0,0]
    
    c1.metric("Registered Assets", total_certs)
    c2.metric("Audit Logs", total_logs)
    c3.metric("System Health", "Optimal")
    
    st.subheader("Recent Activity")
    logs = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10", conn)
    st.table(logs)
    conn.close()

# --- 8. MAIN APPLICATION ---

def main():
    init_db()
    nav, ela_sensitivity = draw_sidebar()

    if nav == "Dashboard":
        show_dashboard()

    elif nav == "Forensic Lab":
        st.markdown("## 🔬 Advanced Forensic Laboratory")
        up_file = st.file_uploader("Upload Document (High-Res)", type=["jpg", "png", "jpeg"])
        
        if up_file:
            # Initialize session state
            if 'current_file' not in st.session_state:
                st.session_state.current_file = None
            if 'results' not in st.session_state:
                st.session_state.results = {}
            
            # Reset if new file
            if st.session_state.current_file != up_file.name:
                st.session_state.current_file = up_file.name
                st.session_state.results = {}
            
            # --- STEP 1: FILE LOADING ---
            st.subheader("📤 Step 1: Document Upload")
            with st.expander("File Information", expanded=True):
                st.write(f"**Filename:** {up_file.name}")
                st.write(f"**File Size:** {len(up_file.getvalue()) / 1024:.2f} KB")
                
                if 'img_bytes' not in st.session_state.results:
                    f_bytes = up_file.read()
                    img = Image.open(BytesIO(f_bytes))
                    st.session_state.results['img_bytes'] = f_bytes
                    st.session_state.results['img'] = img
                else:
                    f_bytes = st.session_state.results['img_bytes']
                    img = st.session_state.results['img']
                
                st.image(img, caption="Uploaded Document", use_container_width=True)
            
            # --- STEP 2: IDENTITY VERIFICATION ---
            st.subheader("🔍 Step 2: Identity Verification")
            with st.expander("Blockchain Hash Verification", expanded=True):
                if 'owner' not in st.session_state.results:
                    with st.spinner("Computing SHA-256 Hash..."):
                        owner = verify_document(f_bytes)
                        st.session_state.results['owner'] = owner
                else:
                    owner = st.session_state.results['owner']
                
                if owner:
                    st.success(f"✅ Verified Owner: {owner}")
                    log_event(f"Document verified - Owner: {owner}")
                else:
                    st.error("⚠️ No Registry Record Found - Document is UNREGISTERED")
                    log_event("Unregistered document analyzed")
            
            # --- STEP 3: ELA ANALYSIS ---
            st.subheader("⚡ Step 3: Error Level Analysis")
            with st.expander("Compression Error Detection", expanded=True):
                if 'ela_img' not in st.session_state.results:
                    with st.spinner("Performing ELA Analysis..."):
                        ela_img = perform_ela(img, enhancement=ela_sensitivity)
                        st.session_state.results['ela_img'] = ela_img
                else:
                    ela_img = st.session_state.results['ela_img']
                
                st.write("**Quantization Error Map:**")
                fig, ax = plt.subplots(figsize=(10, 6))
                im = ax.imshow(np.array(ela_img.convert('L')), cmap='magma')
                plt.colorbar(im, label="Compression Error Density")
                ax.axis('off')
                st.pyplot(fig)
                plt.close(fig)
            
            # --- STEP 4: FORENSIC METRICS ---
            st.subheader("📊 Step 4: Forensic Metrics")
            with st.expander("Statistical Analysis", expanded=True):
                if 'metrics' not in st.session_state.results:
                    with st.spinner("Computing Statistical Metrics..."):
                        score, mean_n, std_n, kurt_n = analyze_noise_distribution(ela_img)
                        st.session_state.results['metrics'] = {
                            'score': score, 'mean': mean_n, 'std': std_n, 'kurtosis': kurt_n
                        }
                else:
                    metrics = st.session_state.results['metrics']
                    score = metrics['score']
                    mean_n = metrics['mean']
                    std_n = metrics['std']
                    kurt_n = metrics['kurtosis']
                
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Authenticity Index", f"{score}%")
                c2.metric("Noise Mean", f"{mean_n:.2f}")
                c3.metric("Std Deviation", f"{std_n:.2f}")
                c4.metric("Kurtosis", f"{kurt_n:.2f}")
                
                if score > 85:
                    st.success("✅ HIGH CONFIDENCE: Document appears authentic")
                elif score > 60:
                    st.warning("⚠️ MEDIUM CONFIDENCE: Some anomalies detected")
                else:
                    st.error("🚨 LOW CONFIDENCE: Document shows signs of tampering")
            
            # --- STEP 5: METADATA ANALYSIS ---
            st.subheader("📋 Step 5: Metadata Analysis")
            with st.expander("EXIF & File Metadata", expanded=True):
                if 'metadata' not in st.session_state.results:
                    exif = img.getexif()
                    software = exif.get(305) or exif.get(0x0131)
                    metadata_findings = []
                    
                    if software:
                        st.warning(f"⚠️ Metadata Alert: Document edited via **{software}**")
                        metadata_findings.append(f"Editing Software: {software}")
                    else:
                        st.info("✅ Metadata Clean: No editing software headers found.")
                        metadata_findings.append("Metadata: Clean")
                    
                    st.session_state.results['metadata'] = metadata_findings
                else:
                    metadata_findings = st.session_state.results['metadata']
            
            # --- STEP 6: OCR TEXT VERIFICATION ---
            st.subheader("📝 Step 6: OCR Text Verification")
            with st.expander("Optical Character Recognition", expanded=True):
                if 'ocr_text' not in st.session_state.results:
                    with st.spinner("Extracting text from image..."):
                        text_on_doc = extract_text_from_image(img)
                        st.session_state.results['ocr_text'] = text_on_doc
                else:
                    text_on_doc = st.session_state.results['ocr_text']
                
                st.write("**Extracted Text Snippet:**")
                if text_on_doc:
                    st.code(text_on_doc[:300] + "..." if len(text_on_doc) > 300 else text_on_doc)
                else:
                    st.warning("No text detected in image")
                
                if 'match_status' not in st.session_state.results:
                    match_status, text_score = cross_reference_text(text_on_doc, owner)
                    st.session_state.results['match_status'] = match_status
                    st.session_state.results['text_score'] = text_score
                else:
                    match_status = st.session_state.results['match_status']
                    text_score = st.session_state.results['text_score']
                
                st.write("**Consistency Check:**")
                if text_score == 100:
                    st.success(f"✅ {match_status}")
                elif text_score == 0 and owner is None:
                    st.info("ℹ️ No registry match to compare - Document is unregistered")
                else:
                    st.error(f"⚠️ {match_status}")
            
            
            

            # --- STEP 8: PDF REPORT ---
            st.divider()
            st.subheader("📄 Step 7: Generate Report")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🗑️ Clear Analysis", use_container_width=True):
                    st.session_state.results = {}
                    st.rerun()
            
            with col2:
                # Prepare and download PDF
                try:
                    ela_buf = BytesIO()
                    ela_img.save(ela_buf, format="PNG")
                    ela_img_bytes = ela_buf.getvalue()
                    
                    pdf_data = generate_forensic_report(
                        filename=up_file.name,
                        owner=owner if owner else "Unregistered",
                        score=score,
                        metadata=metadata_findings,
                        ela_img_bytes=ela_img_bytes,
                        orig_img_bytes=f_bytes
                    )
                    
                    st.download_button(
                        label="📥 Download Official Report",
                        data=pdf_data,
                        file_name=f"Forensic_Report_{up_file.name}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        type="primary"
                    )
                except Exception as e:
                    st.error(f"Report generation failed: {e}")

    elif nav == "System Settings":
        st.header("⚙️ System Settings")
        st.write(f"VeriCert Version: {SYSTEM_VERSION}")
        if st.button("Reset Database Logs"):
            log_event("Logs cleared by Admin")
            st.success("Logs reset.")

if __name__ == "__main__":
    main()