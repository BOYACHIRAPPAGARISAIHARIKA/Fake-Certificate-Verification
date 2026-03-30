import cv2
import numpy as np
import pytesseract
from difflib import SequenceMatcher

class OCRProcessor:
    def __init__(self):
        # Configuration for high-accuracy document scanning
        self.config = '--psm 3 --oem 3'

    def preprocess_image(self, image_bytes):
        """Advanced CV Pipeline: Denoise -> Grayscale -> Threshold -> Deskew"""
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        # 1. Grayscale & Noise Reduction
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        denoised = cv2.fastNlMeansDenoising(gray, None, 10, 7, 21)
        
        # 2. Binary Thresholding (Otsu's Method)
        thresh = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        
        # 3. Deskewing (Fixing rotation)
        coords = np.column_stack(np.where(thresh > 0))
        angle = cv2.minAreaRect(coords)[-1]
        if angle < -45: angle = -(90 + angle)
        else: angle = -angle
        (h, w) = thresh.shape[:2]
        center = (w // 2, h // 2)
        M = cv2.getRotationMatrix2D(center, angle, 1.0)
        rotated = cv2.warpAffine(thresh, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
        
        return rotated

    def verify_text(self, image_bytes, expected_name):
        """Extracts text and performs Fuzzy Matching against the database."""
        processed_img = self.preprocess_image(image_bytes)
        extracted_text = pytesseract.image_to_string(processed_img, config=self.config)
        
        # Fuzzy Matching Logic
        ratio = SequenceMatcher(None, expected_name.lower(), extracted_text.lower()).ratio()
        status = "Match Confirmed" if ratio > 0.8 else "Text Mismatch Detected"
        
        return round(ratio * 100, 2), status, extracted_text