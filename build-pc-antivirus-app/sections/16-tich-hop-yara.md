## Tích hợp YARA rules vào scan engine

YARA lấp đúng khoảng trống giữa hash (chỉ khớp bản sao chính xác) và heuristic (chỉ xét đặc điểm thống kê chung chung): nó cho phép mô tả một họ mã độc bằng các đoạn byte/chuỗi đặc trưng cùng điều kiện logic kết hợp, khớp được các biến thể đã bị chỉnh sửa nhẹ mà vẫn giữ nguyên phần lõi hành vi. Thư viện `libyara` (chính thức, mã nguồn mở) cung cấp API C để nhúng trực tiếp vào scan engine mà không cần gọi công cụ dòng lệnh riêng.

Một rule YARA đơn giản khớp một họ mã độc giả định dựa trên chuỗi đặc trưng và điều kiện file PE:

```yara
rule Suspicious_Downloader_Pattern
{
    meta:
        description = "Phát hiện mẫu downloader dùng chuỗi C2 mã hóa đơn giản"
        severity = "medium"

    strings:
        $api1 = "URLDownloadToFileW" ascii
        $api2 = "WinExec" ascii
        $mz = { 4D 5A }                       // magic bytes đầu file PE

    condition:
        $mz at 0 and $api1 and $api2 and filesize < 500KB
}
```

Rule này khớp file PE (bắt đầu bằng `MZ`) nhỏ hơn 500KB có chứa cả hai chuỗi API `URLDownloadToFileW` và `WinExec`, tổ hợp thường gặp ở downloader tối giản (tải file thực thi khác về rồi chạy ngay). Trong scan engine, gọi `yr_rules_scan_file` (hoặc `yr_rules_scan_mem` nếu đang quét buffer trong bộ nhớ thay vì file trên đĩa, dùng cho trường hợp real-time cần tránh đọc lại file vừa mở) với con trỏ tới rule đã compile sẵn bằng `yr_compiler_add_string` lúc khởi động engine, không compile rule lại mỗi lần quét, vì compile là bước tốn CPU không cần lặp lại cho mỗi file.

Callback nhận kết quả match trả về danh sách rule đã khớp kèm `meta.severity`, được engine dùng để quyết định mức độ tin cậy của kết luận, một rule khớp với severity thấp chỉ cộng điểm vào tổng heuristic score, trong khi rule khớp với severity cao có thể tự đủ để trả về `Malicious` ngay mà không cần chờ heuristic score tổng, tùy vào cách cấu hình ngưỡng của từng rule.
