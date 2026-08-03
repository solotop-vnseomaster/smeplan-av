"""
Kiem tra khach quan ràng buoc "khong tu y viet lai tai lieu goc":

1. Tai lieu goc co con nguyen ven khong (so voi lan kiem tra truoc).
2. Co file .md/.txt nao khac trong thu muc lam viec noi dung trung lap
   phan lon voi tai lieu goc khong (dau hieu mot "phien ban khac" duoc
   tao ra song song).

Chay:
    python diff_guard.py <duong-dan-tai-lieu-goc> [thu-muc-lam-viec]

Thoat voi ma loi khac 0 neu phat hien tai lieu goc bi doi, hoac phat hien
file nghi la ban sao noi dung.
"""

import difflib
import hashlib
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SIMILARITY_THRESHOLD = 0.5
SNAPSHOT_SUFFIX = ".document_executor.sha256"
ALLOWED_NEW_FILES = {"features.md"}


def _hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check_original_unchanged(original_path):
    snapshot_path = original_path + SNAPSHOT_SUFFIX
    current_hash = _hash_file(original_path)

    if not os.path.exists(snapshot_path):
        with open(snapshot_path, "w", encoding="utf-8") as f:
            f.write(current_hash)
        print(f"OK: da luu snapshot ban dau cua {original_path}.")
        return True

    with open(snapshot_path, encoding="utf-8") as f:
        saved_hash = f.read().strip()

    if current_hash != saved_hash:
        print(f"VI PHAM: {original_path} da bi thay doi so voi snapshot ban dau.")
        return False

    print(f"OK: {original_path} con nguyen ven.")
    return True


def _read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, OSError):
        return None


def find_duplicate_versions(original_path, search_dir):
    original_text = _read_text(original_path)
    if original_text is None:
        return []

    original_name = os.path.basename(original_path)
    suspects = []

    for root, _dirs, files in os.walk(search_dir):
        for name in files:
            if not (name.endswith(".md") or name.endswith(".txt")):
                continue
            if name == original_name or name in ALLOWED_NEW_FILES:
                continue
            if name.endswith(SNAPSHOT_SUFFIX):
                continue

            candidate_path = os.path.join(root, name)
            if os.path.samefile(candidate_path, original_path):
                continue

            candidate_text = _read_text(candidate_path)
            if not candidate_text:
                continue

            ratio = difflib.SequenceMatcher(None, original_text, candidate_text).ratio()
            if ratio >= SIMILARITY_THRESHOLD:
                suspects.append((candidate_path, ratio))

    return suspects


def main():
    if len(sys.argv) < 2:
        print("Usage: python diff_guard.py <duong-dan-tai-lieu-goc> [thu-muc-lam-viec]")
        sys.exit(2)

    original_path = sys.argv[1]
    search_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(original_path) or "."

    ok = check_original_unchanged(original_path)

    suspects = find_duplicate_versions(original_path, search_dir)
    if suspects:
        print("VI PHAM: phat hien file nghi la 'phien ban khac' cua tai lieu goc:")
        for path, ratio in suspects:
            print(f"  - {path} (do trung lap noi dung: {ratio:.0%})")
        ok = False
    else:
        print("OK: khong phat hien file trung lap noi dung voi tai lieu goc.")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
