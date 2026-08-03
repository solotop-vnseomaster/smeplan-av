## Kỹ thuật heuristic phát hiện hành vi bất thường

Heuristic chạy sau cùng trong pipeline vì chi phí tính toán cao nhất và tỷ lệ false positive vốn có cao hơn signature/YARA, nó không tìm bản sao chính xác mà tìm đặc điểm thống kê bất thường, nên luôn có khả năng gắn cờ nhầm một file hợp lệ có đặc điểm giống mã độc một cách tình cờ.

Ba rule heuristic cụ thể, dễ implement và có giá trị thực tế cao:

- **Entropy Shannon của section code trong file PE cao bất thường** (thường trên ngưỡng khoảng 7.0-7.2 trên thang 0-8), dấu hiệu của packer hoặc mã hóa/nén nội dung thực thi để tránh signature-based detection. Tính bằng cách đọc từng section trong PE header, tính phân bố tần suất byte, áp công thức entropy Shannon chuẩn. Rule này một mình không đủ kết luận malicious vì nhiều phần mềm hợp lệ cũng dùng packer (UPX, Themida) để bảo vệ bản quyền, chỉ nên cộng điểm nghi ngờ, không tự động chặn.
- **Import Address Table chứa tổ hợp API nhạy cảm bất thường**, ví dụ một file cùng lúc import cả `VirtualAllocEx`, `WriteProcessMemory` và `CreateRemoteThread` (tổ hợp kinh điển của process injection) nhưng không import bất kỳ API UI/dialog thông thường nào, gợi ý một tiến trình không có giao diện đang có khả năng ghi code vào tiến trình khác.
- **File PE có Entry Point nằm ngoài mọi section được khai báo trong Section Table**, dấu hiệu rất mạnh của packer tự giải nén tại runtime (entry point thật bị ẩn), vì trình biên dịch hợp lệ luôn đặt entry point nằm trong section code đã khai báo.

Mỗi rule heuristic khớp cộng vào một điểm số tổng (weighted score), không tự động kết luận `Malicious` chỉ từ một rule đơn lẻ, vượt một ngưỡng điểm số tổng mới trả về trạng thái `Suspicious` (không phải `Malicious`, theo phân loại bốn trạng thái ở phần trước), để luồng xử lý phía sau đối xử khác với trường hợp khớp signature chắc chắn. Quy trình đưa rule mới vào chế độ log-only trước khi enforce, nhằm đo tỷ lệ false positive thực tế trên tập file sạch trước khi áp dụng, được trình bày chi tiết ở phần xử lý false positive.
