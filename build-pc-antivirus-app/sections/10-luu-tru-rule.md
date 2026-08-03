## Lưu trữ và quản lý rule phân quyền

Lưu rule trong một file SQLite cục bộ (đơn giản hơn triển khai một hệ quản trị CSDL riêng, và đủ nhanh cho khối lượng truy vấn của use case này) đặt trong thư mục dữ liệu được ACL bảo vệ chỉ cho SYSTEM và Administrator ghi được, nếu để một tiến trình thường có thể ghi trực tiếp vào file rule, toàn bộ cơ chế phân quyền sụp đổ vì malware chỉ cần tự thêm rule "Cho phép luôn" cho chính nó.

Schema tối thiểu cho bảng rule:

```sql
CREATE TABLE app_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256_hash TEXT NOT NULL,
    publisher_thumbprint TEXT,        -- NULL nếu file không ký số
    file_path TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
    scope TEXT NOT NULL CHECK(scope IN ('hash', 'publisher')),
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL          -- 'user' hoặc 'default_policy'
);
CREATE INDEX idx_rules_hash ON app_rules(sha256_hash);
CREATE INDEX idx_rules_publisher ON app_rules(publisher_thumbprint);
```

Cột `scope` phân biệt hai loại rule quan trọng: rule theo `hash` chỉ áp dụng cho đúng file có hash đó (an toàn tuyệt đối nhưng mất hiệu lực khi file được build lại), rule theo `publisher` áp dụng cho mọi file được ký bởi cùng certificate thumbprint (tiện cho phần mềm cập nhật thường xuyên nhưng rủi ro cao hơn nếu certificate đó từng bị lộ). Khi service nền tra cứu quyền cho một tiến trình mới, thứ tự ưu tiên là: tìm rule theo hash chính xác trước, không có mới tìm theo publisher thumbprint, không có nữa mới rơi về luồng hỏi người dùng ở phần trước.

Việc phân tách `scope` này còn được dùng lại nguyên vẹn ở phần xử lý false positive cho heuristic engine sau này, nên thiết kế đúng ngay từ bảng rule gốc giúp tránh phải viết thêm một bảng riêng cho whitelist detection sau này.
