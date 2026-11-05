"""
modules/authentication/face_recognition.py
──────────────────────────────────────────
Face registration and verification using OpenCV LBPH.

Flow:
  Registration:
    1. Capture FACE_SAMPLE_COUNT frames from webcam.
    2. Detect faces with Haar Cascade.
    3. Train an LBPH recogniser on the cropped face ROIs.
    4. Save the model to storage/face_data/<user_id>.yml

  Verification:
    1. Capture a single frame from webcam.
    2. Detect face and run recogniser.predict().
    3. Accept if confidence <= FACE_CONFIDENCE_THRESHOLD (lower = more confident).
"""

import os
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config

try:
    import cv2
    _CV2_AVAILABLE = True
except ImportError:
    _CV2_AVAILABLE = False

_FACE_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "storage", "face_data"
)
os.makedirs(_FACE_DATA_DIR, exist_ok=True)


def _get_cascade() -> "cv2.CascadeClassifier":
    if config.HAAR_CASCADE_PATH and os.path.exists(config.HAAR_CASCADE_PATH):
        path = config.HAAR_CASCADE_PATH
    else:
        path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    cascade = cv2.CascadeClassifier(path)
    if cascade.empty():
        raise RuntimeError("Haar Cascade file not found or failed to load.")
    return cascade


def _model_path(user_id: int) -> str:
    return os.path.join(_FACE_DATA_DIR, f"user_{user_id}.yml")


def register_face_from_frames(user_id: int, frames: list) -> bool:
    """
    Train LBPH recogniser from a list of BGR numpy arrays (webcam frames).

    Parameters
    ----------
    user_id : int
    frames  : list of numpy.ndarray  (BGR, from cv2.VideoCapture)

    Returns
    -------
    bool  True on success.
    """
    if not _CV2_AVAILABLE:
        raise RuntimeError("opencv-contrib-python is not installed.")

    cascade = _get_cascade()
    faces: list[np.ndarray] = []

    for frame in frames:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        detected = cascade.detectMultiScale(gray, scaleFactor=1.2, minNeighbors=5)
        for (x, y, w, h) in detected:
            roi = cv2.resize(gray[y:y + h, x:x + w], (200, 200))
            faces.append(roi)

    if len(faces) < 5:
        return False  # not enough face samples

    recogniser = cv2.face.LBPHFaceRecognizer_create()
    labels = [user_id] * len(faces)
    recogniser.train(faces, np.array(labels))
    recogniser.save(_model_path(user_id))
    return True


def capture_and_register(user_id: int, sample_count: int | None = None) -> bool:
    """
    Open webcam, capture *sample_count* frames, train and save LBPH model.
    Blocking call — intended for CLI / background thread use.
    """
    if not _CV2_AVAILABLE:
        raise RuntimeError("opencv-contrib-python is not installed.")

    n = sample_count or config.FACE_SAMPLE_COUNT
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        raise RuntimeError("Cannot open webcam.")

    frames = []
    try:
        while len(frames) < n:
            ret, frame = cap.read()
            if not ret:
                break
            frames.append(frame)
    finally:
        cap.release()

    return register_face_from_frames(user_id, frames)


def verify_face_from_frame(user_id: int, frame: np.ndarray) -> bool:
    """
    Verify a single BGR frame against the stored LBPH model.

    Returns True if the predicted label matches user_id AND the
    confidence is within threshold.
    """
    if not _CV2_AVAILABLE:
        raise RuntimeError("opencv-contrib-python is not installed.")

    model_file = _model_path(user_id)
    if not os.path.exists(model_file):
        return False

    cascade = _get_cascade()
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    detected = cascade.detectMultiScale(gray, scaleFactor=1.2, minNeighbors=5)

    if len(detected) == 0:
        return False

    recogniser = cv2.face.LBPHFaceRecognizer_create()
    recogniser.read(model_file)

    for (x, y, w, h) in detected:
        roi = cv2.resize(gray[y:y + h, x:x + w], (200, 200))
        label, confidence = recogniser.predict(roi)
        # LBPH confidence: 0 = perfect match; lower is better
        if label == user_id and confidence <= config.FACE_CONFIDENCE_THRESHOLD:
            return True

    return False


def verify_face_webcam(user_id: int) -> bool:
    """
    Capture a single frame from the webcam and verify.
    Blocking call.
    """
    if not _CV2_AVAILABLE:
        raise RuntimeError("opencv-contrib-python is not installed.")

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        raise RuntimeError("Cannot open webcam.")
    try:
        ret, frame = cap.read()
        if not ret:
            return False
        return verify_face_from_frame(user_id, frame)
    finally:
        cap.release()


def has_face_model(user_id: int) -> bool:
    """Return True if a trained LBPH model exists for this user."""
    return os.path.exists(_model_path(user_id))
