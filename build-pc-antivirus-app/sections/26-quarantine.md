## Cơ chế Quarantine cách ly file nghi ngờ

Không xóa file bị coi là `Malicious` ngay lập tức, luôn di chuyển vào một khu vực cách ly trước, vì mọi engine phát hiện đều có tỷ lệ false positive khác không, và một khi file gốc bị xóa vĩnh viễn, không còn cách nào khôi phục nếu kết luận sau này hóa ra sai. Khu vực quarantine là một thư mục hệ thống được ACL bảo vệ (chỉ SYSTEM đọc/ghi được, người dùng thường không thể tự mở file bên trong bằng Explorer), và file khi chuyển vào đây cần qua hai bước biến đổi bắt buộc: đổi tên thành một định danh không mang phần mở rộng gốc (ví dụ dùng GUID) để Windows Explorer hay bất kỳ chương trình nào không vô tình thực thi nó nếu người dùng tò mò click vào, và mã hóa nội dung bằng một khóa đơn giản (ví dụ XOR với khóa cố định, không cần mã hóa mạnh vì mục đích chỉ là ngăn chính engine antivirus khác hoặc chương trình thực thi tình cờ đọc/chạy được file, không phải chống phân tích chuyên sâu).

```
QuarantineRecord {
    quarantine_id: GUID,
    original_path: string,       // đường dẫn gốc, cần cho việc khôi phục
    original_filename: string,
    sha256_hash: string,
    detection_reason: string,    // rule/signature nào đã gắn cờ
    quarantined_at: timestamp,
    file_size: uint64
}
```

Metadata này lưu song song trong bảng SQLite riêng (không chung bảng rule phân quyền), đủ để khôi phục chính xác file về đúng vị trí gốc nếu người dùng xác nhận đây là false positive, thao tác khôi phục chỉ nên khả dụng qua giao diện chính của app (yêu cầu xác nhận rõ ràng, không phải một nút bấm vô tình), không qua thao tác file thông thường trong Explorer.

Trường hợp đặc biệt cần xử lý riêng: nếu file bị gắn cờ nằm trong danh sách thư mục hệ thống được bảo vệ (trùng vị trí với các thư mục đã nêu ở phần "Nguyên tắc mặc định tin cậy ứng dụng gốc Windows"), không tự động quarantine ngay cả khi engine kết luận `Malicious`, chuyển sang chế độ cảnh báo yêu cầu xác nhận thủ công trước khi di chuyển, vì rủi ro gỡ nhầm một file hệ thống quan trọng gây mất ổn định hệ điều hành nghiêm trọng hơn nhiều so với việc chậm vài giây phản ứng với một phát hiện có thể đúng.
