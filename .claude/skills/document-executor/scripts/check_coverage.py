import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def check_coverage(features_path):
    unchecked = []
    with open(features_path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"- \[([ x])\] (\w+): (.+)", line.strip())
            if m and m.group(1) == " ":
                unchecked.append(f"{m.group(2)}: {m.group(3)}")
    if unchecked:
        print("CHƯA HOÀN THÀNH:")
        for item in unchecked:
            print(f"  - {item}")
        sys.exit(1)
    print("Tất cả tính năng đã được đánh dấu hoàn thành.")

if __name__ == "__main__":
    check_coverage(sys.argv[1])
