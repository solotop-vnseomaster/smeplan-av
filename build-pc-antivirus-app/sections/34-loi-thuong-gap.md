## Những lỗi thường gặp khi tự xây antivirus

**Tin vào tên file hoặc đường dẫn như một tiêu chí bảo mật.** Đây là lỗi nền tảng nhất và đã được nhấn mạnh xuyên suốt bài: bất kỳ chuỗi văn bản nào cũng copy được. Team mới bắt đầu thường viết whitelist kiểu `if (filename == "explorer.exe") trust = true`, lỗi này chỉ lộ ra khi có người thử đặt một file cùng tên vào vị trí khác, lúc đó whitelist đã chạy trong tay hàng nghìn người dùng.

**Quét đồng bộ mọi loại file trong real-time protection.** Chặn IRP_MJ_CREATE và gửi mọi file, kể cả ảnh và văn bản, xuống service chờ kết quả trước khi cho mở, tạo ra độ trễ cảm nhận được ngay từ ngày đầu người dùng thử app, đây là lý do phổ biến nhất khiến người dùng gỡ cài đặt một antivirus tự viết chỉ sau vài phút dùng thử, trước khi kịp đánh giá khả năng phát hiện thực sự.

**Bỏ qua việc đo hiệu năng trên phần cứng thật trước khi ship.** Code chạy mượt trên máy dev cấu hình cao với SSD NVMe không nói lên gì về trải nghiệm trên máy người dùng phổ thông với ổ HDD cũ, phần tối ưu hiệu năng khi quét sâu tồn tại chính vì sự khác biệt này, và bỏ qua nó là cách nhanh nhất để một tính năng "deep scan" đúng về mặt logic trở thành lý do máy người dùng bị treo trong thực tế.

**Coi driver signing và MVI là bước hành chính có thể làm sau cùng.** Cả hai đều có thời gian xử lý tính bằng tuần và là điều kiện tiên quyết để driver nạp được hoặc để tránh xung đột với Defender, để tới gần ngày phát hành mới bắt đầu nộp hồ sơ Partner Center hoặc tìm hiểu MVI là nguyên nhân phổ biến khiến lịch phát hành bị trễ hàng tháng dù phần code kỹ thuật đã xong từ lâu.

**Tự động xóa thay vì quarantine khi engine chỉ ở mức `Suspicious`.** Heuristic và YARA luôn có tỷ lệ false positive khác không; xử lý kết quả `Suspicious` giống hệt `Malicious` (xóa ngay, không cho khôi phục) là cách chắc chắn nhất để một ngày nào đó tự xóa nhầm một công cụ hợp lệ của chính người dùng mà không có đường lùi.
