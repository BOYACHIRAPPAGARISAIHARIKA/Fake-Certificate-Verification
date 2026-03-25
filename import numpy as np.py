import numpy as np
import cv2
from PIL import Image, ImageChops, ImageEnhance
from io import BytesIO
from scipy.stats import kurtosis, skew

class ForensicEngine:
    def perform_ela(self, img, quality=90, scale=10.0):
        """Quantization Error Level Analysis."""
        original = img.convert('RGB')
        buf = BytesIO()
        original.save(buf, 'JPEG', quality=quality)
        recompressed = Image.open(buf)
        diff = ImageChops.difference(original, recompressed)
        extrema = diff.getextrema()
        max_diff = max([ex[1] for ex in extrema]) or 1
        return ImageEnhance.Brightness(diff).enhance(255.0/max_diff * (scale/10.0))

    def analyze_stats(self, ela_img):
        """Higher-order statistics for noise peaks."""
        pix = np.array(ela_img.convert('L')).flatten()
        active = pix[pix > 5]
        if len(active) == 0: return 0, 0, 0
        k, s = kurtosis(active), skew(active)
        score = 100 - (np.std(active) * 1.5) - (abs(k) * 2.0)
        return round(max(0, score), 2), round(k, 2), round(s, 2)