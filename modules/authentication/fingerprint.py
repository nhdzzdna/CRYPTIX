"""
modules/authentication/fingerprint.py
──────────────────────────────────────
Fingerprint verification via ORB feature matching (academic simulation).

⚠️  DISCLAIMER: This is an academic simulation using image matching,
    NOT a real hardware fingerprint sensor integration.
    Accuracy depends entirely on image quality and consistency.

Flow:
  Registration : Save a reference fingerprint image for the user.
  Verification : Compare a new image against the reference using ORB
                 feature matching. Accept if the number of good matches
                 >= FINGERPRINT_MATCH_THRESHOLD.
"""

import os
import sys
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config

try:
    import cv2
    import numpy as np
    _CV2_AVAILABLE = True
except ImportError:
    _CV2_AVAILABLE = False

_FP_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "storage", "face_data"   # reuse face_data dir for fingerprints
)
os.makedirs(_FP_DIR, exist_ok=True)


def _fp_path(user_id: int) -> str:
    return os.path.join(_FP_DIR, f"fp_{user_id}.png")


def register_fingerprint(user_id: int, image_path: str) -> bool:
    """
    Copy the uploaded fingerprint image as the reference for *user_id*.

    Parameters
    ----------
    user_id    : int
    image_path : str  Path to the uploaded image file.

    Returns
    -------
    bool  True on success.
    """
    if not os.path.exists(image_path):
        return False
    dest = _fp_path(user_id)
    shutil.copy2(image_path, dest)
    return True


def verify_fingerprint(user_id: int, probe_image_path: str) -> bool:
    """
    Verify *probe_image_path* against the stored reference image.

    Uses ORB + BFMatcher with Lowe's ratio test to count good matches.
    Accepts if good_matches >= FINGERPRINT_MATCH_THRESHOLD.

    Returns
    -------
    bool  True if fingerprint matches.
    """
    if not _CV2_AVAILABLE:
        raise RuntimeError("opencv-contrib-python is not installed.")

    reference_path = _fp_path(user_id)
    if not os.path.exists(reference_path):
        return False
    if not os.path.exists(probe_image_path):
        return False

    ref_img   = cv2.imread(reference_path,   cv2.IMREAD_GRAYSCALE)
    probe_img = cv2.imread(probe_image_path, cv2.IMREAD_GRAYSCALE)

    if ref_img is None or probe_img is None:
        return False

    # ORB feature detection & description
    orb = cv2.ORB_create(nfeatures=500)
    kp1, des1 = orb.detectAndCompute(ref_img,   None)
    kp2, des2 = orb.detectAndCompute(probe_img, None)

    if des1 is None or des2 is None:
        return False

    # Brute-force matching with Hamming distance
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    raw_matches = bf.knnMatch(des1, des2, k=2)

    # Lowe's ratio test
    good_matches = []
    for m_pair in raw_matches:
        if len(m_pair) == 2:
            m, n = m_pair
            if m.distance < 0.75 * n.distance:
                good_matches.append(m)

    return len(good_matches) >= config.FINGERPRINT_MATCH_THRESHOLD


def has_fingerprint(user_id: int) -> bool:
    """Return True if a reference fingerprint image exists for this user."""
    return os.path.exists(_fp_path(user_id))
