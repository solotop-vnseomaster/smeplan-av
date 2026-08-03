# Ghi chú cài đặt cho người dùng — trạng thái Windows Security Center

**Bản phát hành hiện tại của SmePlanAv CHƯA được Microsoft công nhận là nhà
cung cấp antivirus hợp lệ** (chưa qua chương trình Microsoft Virus
Initiative — MVI). Điều này ảnh hưởng trực tiếp đến trải nghiệm của bạn,
theo đúng cảnh báo trong `spec-output/v1/ops/08-trien-khai.md` mục 4 và
`spec-output/v1/security/09-bao-mat.md` mục 4 (bảng rủi ro, dòng
ERR-WSC-01):

## Bạn có thể gặp gì

Windows Defender **sẽ tiếp tục tự động bật real-time protection song
song** với SmePlanAv, vì Windows Security Center chưa "biết" SmePlanAv là một
antivirus đã được xác thực. Hai driver minifilter (của Defender và của
SmePlanAv) cùng hook vào filesystem có thể:

- Tranh chấp lock trên cùng một file, gây lỗi khó chẩn đoán hoặc mở file
  chậm bất thường.
- Làm giảm hiệu năng hệ thống do bị quét hai lần.

## Đây KHÔNG phải là lỗi của SmePlanAv

Đây là hạn chế đã biết của việc chưa hoàn tất một quy trình hành chính bên
ngoài (nộp hồ sơ MVI, cần chứng nhận từ phòng test độc lập được Microsoft
công nhận — AV-Test, AV-Comparatives, hoặc ICSA Labs), không phải lỗi kỹ
thuật trong phần mềm.

## Cách xử lý

- **Khuyến nghị**: chỉ dùng bản này trên máy dev/test, không dùng làm
  antivirus chính trên máy sản xuất, cho tới khi bản phát hành đã qua MVI.
- Nếu bạn là lập trình viên đang phát triển/test SmePlanAv và muốn tạm thời
  tắt xung đột: dùng `app/ops/scripts/exclude-defender-devtest.ps1` — script
  này **chỉ dành cho máy dev/test của chính lập trình viên**, tuyệt đối
  không hướng dẫn người dùng cuối tự chạy lệnh loại trừ Windows Defender,
  vì làm vậy tắt một lớp bảo vệ thật mà không có gì thay thế tương đương
  cho tới khi SmePlanAv chính thức qua MVI.
