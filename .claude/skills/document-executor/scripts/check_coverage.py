import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def check_coverage(features_path):
    unchecked = []
    matched = 0
    with open(features_path, encoding="utf-8") as f:
        for line in f:
            # [SUA LOI] `\w` KHONG khop dau gach ngang, trong khi ID that cua
            # du an co dang "ARCH-01" / "F-01" / "EXT-FW-05". Voi regex cu,
            # `(\w+)` an "ARCH" roi doi ngay mot dau ":" nhung gap "-", nen
            # KHONG MOT DONG NAO khop — danh sach `unchecked` luon rong va
            # script luon in "Tat ca tinh nang da duoc danh dau hoan thanh"
            # roi thoat 0. Mot cong chat luong luon mau xanh bat ke noi dung.
            # ID that co dau gach ngang ("ARCH-01", "EXT-FW-05"), co the co
            # dau tieng Viet va ca khoang trang ("ĐỀ XUẤT-01"). Nhan moi thu
            # truoc dau ":" dau tien lam ID.
            m = re.match(r"- \[([ x])\] ([^:]+): (.+)", line.strip())
            if not m:
                continue
            matched += 1
            if m.group(1) == " ":
                unchecked.append(f"{m.group(2)}: {m.group(3)}")

    # [SUA LOI] Fail-closed: neu KHONG khop duoc dong nao, do la dau hieu
    # regex/dinh dang lech chu KHONG PHAI la "moi thu da xong". Bao loi thay
    # vi bao thanh cong — day chinh la cach loi tren song sot lau den vay.
    if matched == 0:
        print("LOI: khong doc duoc dong tinh nang nao tu " + features_path
              + " — dinh dang file hoac regex da lech. KHONG ket luan la da hoan thanh.")
        sys.exit(2)
    if unchecked:
        print("CHƯA HOÀN THÀNH:")
        for item in unchecked:
            print(f"  - {item}")
        sys.exit(1)
    print("Tất cả tính năng đã được đánh dấu hoàn thành.")

if __name__ == "__main__":
    check_coverage(sys.argv[1])
