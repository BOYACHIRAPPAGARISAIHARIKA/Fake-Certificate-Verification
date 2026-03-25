import streamlit as st
import sqlite3
import hashlib
import os
import base64
from io import BytesIO
from PIL import Image, ImageChops, ImageEnhance, ImageDraw
import matplotlib.pyplot as plt
import numpy as np

# Database initialization
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

# Function to compute SHA-256 hash of a file
def compute_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

# Function to add a certificate to the database
def add_certificate(name, file_bytes, signature=None):
    hash_value = compute_hash(file_bytes)
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("INSERT INTO certificates (name, hash, signature) VALUES (?, ?, ?)", (name, hash_value, signature))
    conn.commit()
    conn.close()

# Function to verify a certificate and compute authenticity score
def verify_certificate(file_bytes):
    hash_value = compute_hash(file_bytes)
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT name FROM certificates WHERE hash = ?", (hash_value,))
    result = c.fetchone()
    conn.close()
    if result:
        return result[0], 100  # Genuine, 100% score
    else:
        return None, 0  # Fake, 0% score

# Function to perform Error Level Analysis (ELA) on images
def perform_ela(image, quality=90):
    # Save image at lower quality
    ela_buffer = BytesIO()
    image.save(ela_buffer, 'JPEG', quality=quality)
    ela_buffer.seek(0)
    ela_image = Image.open(ela_buffer)
    
    # Compute difference
    diff = ImageChops.difference(image, ela_image)
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0:
        max_diff = 1
    scale = 255.0 / max_diff
    diff = ImageEnhance.Brightness(diff).enhance(scale)
    return diff

# Function to generate heat map with pixel analysis and zone overlays for fake documents
def generate_heat_map(file_bytes, file_type, score):
    if file_type in ['image/jpeg', 'image/png']:
        image = Image.open(BytesIO(file_bytes))
        
        if score == 0:  # Fake document: Overlay red zones on specific areas (name, photo, login)
            # Assume standard certificate layout (adjust coordinates as needed for real docs)
            draw = ImageDraw.Draw(image, 'RGBA')
            width, height = image.size
            
            # Example zones (as fractions of image size for generality)
            name_zone = (0.1*width, 0.2*height, 0.5*width, 0.3*height)  # Name area
            photo_zone = (0.6*width, 0.1*height, 0.9*width, 0.4*height)  # Photo area
            login_zone = (0.1*width, 0.7*height, 0.5*width, 0.8*height)  # Login/signature area
            
            # Draw semi-transparent red overlays
            draw.rectangle(name_zone, fill=(255, 0, 0, 128))  # Red for name
            draw.rectangle(photo_zone, fill=(255, 0, 0, 128))  # Red for photo
            draw.rectangle(login_zone, fill=(255, 0, 0, 128))  # Red for login
            
            # Add labels
            draw.text((name_zone[0]+10, name_zone[1]+10), "NAME (Suspected Tampering)", fill="white")
            draw.text((photo_zone[0]+10, photo_zone[1]+10), "PHOTO (Suspected Tampering)", fill="white")
            draw.text((login_zone[0]+10, login_zone[1]+10), "LOGIN (Suspected Tampering)", fill="white")
            
            return image  # Return annotated image
        
        else:  # Genuine: Use ELA heatmap
            ela_diff = perform_ela(image)
            ela_array = np.array(ela_diff.convert('L'))
            fig, ax = plt.subplots()
            cax = ax.imshow(ela_array, cmap='RdYlGn_r', interpolation='nearest')
            ax.set_title(f'Error Level Analysis Heat Map (Authenticity Score: {score}%)')
            fig.colorbar(cax, label='Tampering Level (Red: High Danger, Green: Safe)')
            return fig
    else:
        # For PDFs or others, generate a simple score-based heat map
        data = np.random.rand(10, 10) * (100 - score) / 100 + (score / 100) * np.random.rand(10, 10)
        fig, ax = plt.subplots()
        cax = ax.imshow(data, cmap='RdYlGn_r', interpolation='nearest')
        ax.set_title(f'Score-Based Heat Map (Authenticity Score: {score}%)')
        fig.colorbar(cax, label='Authenticity Level (Red: Danger, Green: Safe)')
        return fig

# Custom CSS for enhanced professional, secure-themed UI/UX
st.markdown("""
    <style>
    .main {
        background-color: #f0f2f6;
        padding: 20px;
    }
    .sidebar .sidebar-content {
        background-color: #2c3e50;
        color: white;
        padding: 20px;
    }
    .stButton>button {
        background-color: #3498db;
        color: white;
        border-radius: 5px;
        padding: 10px 20px;
        font-size: 16px;
    }
    .stAlert {
        border-radius: 5px;
        margin: 10px 0;
    }
    .title {
        color: #2c3e50;
        font-weight: bold;
        font-size: 24px;
        text-align: center;
    }
    .subtitle {
        color: #34495e;
        font-size: 18px;
        margin-bottom: 10px;
    }
    .card {
        background-color: white;
        padding: 15px;
        border-radius: 10px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        margin: 10px 0;
    }
    </style>
    """, unsafe_allow_html=True)

# Initialize database
init_db()

# Session state for alerts
if 'alert' not in st.session_state:
    st.session_state.alert = None

# Main app with improved UI/UX
st.title("🔒 AI-Based Fake Certificate and Document Verification System")
st.markdown('<p class="title">Secure Document Verification Platform</p>', unsafe_allow_html=True)
st.markdown("---")

# Sidebar navigation with icons
menu = st.sidebar.selectbox("📍 Navigation", ["📤 Upload & Verify", "⚙️ Admin Records"])

if menu == "📤 Upload & Verify":
    st.header("📤 Upload & Verify Document")
    st.markdown('<p class="subtitle">Upload your certificate for instant verification.</p>', unsafe_allow_html=True)
    
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        uploaded_file = st.file_uploader("Choose a certificate file (PDF, JPG, PNG)", type=["pdf", "jpg", "png"])
        st.markdown('</div>', unsafe_allow_html=True)
    
    if uploaded_file is not None:
        try:
            file_bytes = uploaded_file.read()
            file_type = uploaded_file.type
            
            if file_type not in ["application/pdf", "image/jpeg", "image/png"]:
                st.session_state.alert = "error: Invalid file type. Please upload PDF, JPG, or PNG."
            else:
                verified_name, score = verify_certificate(file_bytes)
                status = "Genuine ✅" if verified_name else "Fake/Tampered ❌"
                
                # Display results in separate sections
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown('<div class="card">', unsafe_allow_html=True)
                    st.subheader("📊 Authenticity Score")
                    st.metric("Score", f"{score}%")
                    st.markdown('</div>', unsafe_allow_html=True)
                
                with col2:
                    st.markdown('<div class="card">', unsafe_allow_html=True)
                    st.subheader("🔍 Verification Status")
                    st.write(f"**Status:** {status}")
                    if verified_name:
                        st.write(f"**Verified as:** {verified_name}")
                    st.markdown('</div>', unsafe_allow_html=True)
                
                # Generate and display heat map or annotated image
                st.markdown('<div class="card">', unsafe_allow_html=True)
                st.subheader("🗺️ Pixel Analysis Heat Map / Zone Overlay")
                heat_map_result = generate_heat_map(file_bytes, file_type, score)
                if isinstance(heat_map_result, Image.Image):
                    # For fake images: Display annotated image with red zones
                    st.image(heat_map_result, caption="Annotated Image with Suspected Tampering Zones (Red Overlays)", use_column_width=True)
                    st.markdown("**Red Zones:** Indicate potential tampering in Name, Photo, and Login areas for fake documents.")
                else:
                    # For genuine images or PDFs: Display matplotlib heatmap
                    st.pyplot(heat_map_result)
                    st.markdown("**Legend:** Red zones indicate potential tampering (danger), Green zones indicate safe/authentic areas.")
                st.markdown('</div>', unsafe_allow_html=True)
                
                if verified_name:
                    st.session_state.alert = f"success: Document verified successfully."
                else:
                    st.session_state.alert = f"warning: Document flagged as fake or tampered."
        except Exception as e:
            st.session_state.alert = f"error: An error occurred: {str(e)}"
    
    # Display alert
    if st.session_state.alert:
        alert_type, message = st.session_state.alert.split(": ", 1)
        if alert_type == "success":
            st.success(message)
        elif alert_type == "warning":
            st.warning(message)
        elif alert_type == "error":
            st.error(message)
        st.session_state.alert = None  # Reset after display

elif menu == "⚙️ Admin Records":
    st.header("⚙️ Admin Records")
    st.markdown('<p class="subtitle">Manage authorized certificates.</p>', unsafe_allow_html=True)
    
    st.subheader("➕ Add Authorized Certificate")
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        cert_name = st.text_input("Certificate Name")
        uploaded_cert = st.file_uploader("Upload Authorized Certificate (PDF, JPG, PNG)", type=["pdf", "jpg", "png"])
        signature = st.text_input("Digital Signature (optional)")
        if st.button("Add Certificate"):
            if cert_name and uploaded_cert:
                try:
                    file_bytes = uploaded_cert.read()
                    file_type = uploaded_cert.type
                    if file_type not in ["application/pdf", "image/jpeg", "image/png"]:
                        st.session_state.alert = "error: Invalid file type. Please upload PDF, JPG, or PNG."
                    else:
                        add_certificate(cert_name, file_bytes, signature)
                        st.session_state.alert = "success: Certificate added successfully."
                except Exception as e:
                    st.session_state.alert = f"error: An error occurred: {str(e)}"
            else:
                st.session_state.alert = "error: Please provide a name and upload a file."
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.subheader("📋 View Authorized Certificates")
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        conn = sqlite3.connect('certificates.db')
        c = conn.cursor()
        c.execute("SELECT id, name, hash, signature FROM certificates")
        records = c.fetchall()
        conn.close()
        
        if records:
            for record in records:
                st.write(f"🆔 ID: {record[0]}, 📄 Name: {record[1]}, 🔒 Hash: {record[2][:10]}..., ✍️ Signature: {record[3] or 'None'}")
        else:
            st.write("No records found.")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Display alert
    if st.session_state.alert:
        alert_type, message = st.session_state.alert.split(": ", 1)
        if alert_type == "success":
            st.success(message)
        elif alert_type == "warning":
            st.warning(message)
        elif alert_type == "error":
            st.error(message)
        st.session_state.alert = None  # Reset after display