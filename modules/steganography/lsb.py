"""
modules/steganography/lsb.py
──────────────────────────────
LSB (Least Significant Bit) steganography for PNG images.

Message format embedded in the image:
  • 32 bits (4 bytes, MSB first) — message length in bytes
  • N * 8 bits                  — message payload bytes

Each bit of the payload replaces the LSB of one colour channel (R, G, B)
of sequential pixels (row-major order).

Capacity = (width * height * 3 - 32) // 8  bytes.

Optional integration with Super Encryption: if a master_key or passphrase
is provided the message is encrypted before embedding and decrypted after
extraction.
"""

import os
import struct

import config
from modules.strings import MSG

from PIL import Image
import numpy as np


def _capacity_bytes(img: Image.Image) -> int:
    """Return maximum embeddable message bytes for a given image."""
    w, h = img.size
    total_bits = w * h * 3      # one bit per channel (R, G, B)
    return (total_bits - 32) // 8   # first 32 bits are the length header


def embed_message(
    input_image_path: str,
    message: str,
    output_path: str,
    master_key: bytes | None = None,
    passphrase: str | None = None,
) -> dict:
    """
    Embed *message* into the PNG image at *input_image_path*.

    Parameters
    ----------
    input_image_path : str   Path to the carrier PNG/JPG image.
    message          : str   Text message to embed.
    output_path      : str   Destination PNG path (must be .png for lossless).
    master_key       : bytes Optional — encrypt message with Super Encryption.
    passphrase       : str   Optional alternative to master_key.

    Returns
    -------
    dict with ``success`` bool, ``capacity`` int, ``used`` int, ``encrypted`` bool.
    """
    use_encryption = master_key is not None or passphrase is not None

    if use_encryption:
        from modules.cryptography.super_encryption import super_encrypt
        payload = super_encrypt(message, master_key=master_key, passphrase=passphrase)
    else:
        payload = message

    payload_bytes = payload.encode("utf-8")
    msg_len = len(payload_bytes)

    img = Image.open(input_image_path).convert("RGB")
    capacity = _capacity_bytes(img)

    if msg_len > capacity:
        return {
            "success": False,
            "error": f"Pesan terlalu besar: {msg_len} byte melebihi kapasitas {capacity} byte.",
        }

    pixels = np.array(img, dtype=np.uint8)
    flat = pixels.flatten()   # shape: (w*h*3,)

    # Encode length header (32 bits)
    header_bits = [(msg_len >> (31 - i)) & 1 for i in range(32)]
    # Encode message bits
    message_bits = []
    for byte in payload_bytes:
        for i in range(7, -1, -1):
            message_bits.append((byte >> i) & 1)

    all_bits = header_bits + message_bits

    for idx, bit in enumerate(all_bits):
        flat[idx] = (flat[idx] & 0xFE) | bit   # clear LSB, set to our bit

    stego_array = flat.reshape(pixels.shape)
    stego_img = Image.fromarray(stego_array, "RGB")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    stego_img.save(output_path, format="PNG")

    return {
        "success": True,
        "capacity": capacity,
        "used": msg_len,
        "encrypted": use_encryption,
    }


def extract_message(
    stego_image_path: str,
    master_key: bytes | None = None,
    passphrase: str | None = None,
) -> dict:
    """
    Extract a message previously embedded by embed_message().

    Parameters
    ----------
    stego_image_path : str    Path to the stego image.
    master_key       : bytes  Supply if message was encrypted during embed.
    passphrase       : str    Alternative to master_key.

    Returns
    -------
    dict with ``success`` bool and ``message`` str / ``error`` str.
    """
    img = Image.open(stego_image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat = pixels.flatten()

    # Read length header (32 bits)
    length_bits = [int(flat[i] & 1) for i in range(32)]
    msg_len = 0
    for b in length_bits:
        msg_len = (msg_len << 1) | b

    capacity = _capacity_bytes(img)
    if msg_len <= 0 or msg_len > capacity:
        return {"success": False, "error": MSG.STEGO_NO_MESSAGE}

    # Read message bits
    msg_bits = [int(flat[32 + i] & 1) for i in range(msg_len * 8)]

    # Reconstruct bytes
    payload_bytes = bytearray()
    for i in range(msg_len):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | msg_bits[i * 8 + j]
        payload_bytes.append(byte)

    try:
        payload = payload_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return {"success": False, "error": MSG.STEGO_DECODE_FAILED}

    # Decrypt if keys provided
    if master_key is not None or passphrase is not None:
        try:
            from modules.cryptography.super_encryption import super_decrypt
            payload = super_decrypt(payload, master_key=master_key, passphrase=passphrase)
        except Exception:
            return {"success": False, "error": MSG.STEGO_DECRYPT_FAILED}

    return {"success": True, "message": payload}
