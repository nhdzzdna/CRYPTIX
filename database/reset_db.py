"""
database/reset_db.py
─────────────────────
Interactive tool to wipe all user data from CRYPTIX.

Run with:  python -m database.reset_db

WARNING: This is irreversible. All encrypted files, notes, credentials,
stego images, and the database will be permanently deleted.
"""

import os
import sys

import config


def _delete_storage_files() -> int:
    """Delete all non-.gitkeep files under storage/ subdirectories."""
    storage_root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "storage")
    deleted = 0
    if not os.path.isdir(storage_root):
        return deleted
    for dirpath, _dirnames, filenames in os.walk(storage_root):
        for fname in filenames:
            if fname == ".gitkeep":
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                os.remove(fpath)
                print(f"  Deleted: {os.path.relpath(fpath)}")
                deleted += 1
            except OSError as exc:
                print(f"  WARNING: Could not delete {fpath}: {exc}")
    return deleted


def main() -> None:
    print("=" * 60)
    print("CRYPTIX — Database & Storage Reset Tool")
    print("=" * 60)
    print()
    print("PERINGATAN: Tindakan ini tidak dapat dibatalkan!")
    print("Semua data pengguna, file terenkripsi, catatan, dan")
    print("kunci akan dihapus secara permanen.")
    print()
    confirm = input("Ketik RESET untuk melanjutkan: ").strip()
    if confirm != "RESET":
        print("Reset dibatalkan.")
        sys.exit(0)

    print()
    print("Memulai reset...")

    # 1. Delete database
    db_path = config.DATABASE_PATH
    if os.path.isfile(db_path):
        os.remove(db_path)
        print(f"  Deleted: {db_path}")
    else:
        print(f"  Tidak ditemukan: {db_path}")

    # 2. Delete storage files (keep .gitkeep)
    storage_count = _delete_storage_files()
    print(f"  {storage_count} file di storage/ dihapus.")

    # 3. Delete instance key files
    instance_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance"
    )
    key_files = ["secret.key", "chain.key", "chain_head.json"]
    for kf in key_files:
        kpath = os.path.join(instance_dir, kf)
        if os.path.isfile(kpath):
            os.remove(kpath)
            print(f"  Deleted: {kpath}")

    print()
    print("Reset selesai. Jalankan aplikasi untuk menginisialisasi ulang database.")


if __name__ == "__main__":
    main()
