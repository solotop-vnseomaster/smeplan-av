## Đóng gói, ký số installer và checklist phát hành

Installer (dùng WiX Toolset hoặc Inno Setup, cả hai đều hỗ trợ tốt việc cài driver kernel-mode kèm ứng dụng) phải tự ký bằng cùng EV Code Signing Certificate dùng cho driver, không dùng certificate khác, SmartScreen của Windows đánh giá độ tin cậy của installer một phần dựa trên uy tín tích lũy của certificate đó qua thời gian, dùng nhiều certificate khác nhau cho các phần khác nhau của cùng sản phẩm làm loãng uy tín này và tăng khả năng bị SmartScreen cảnh báo ở những lần cài đặt đầu tiên.

Checklist tối thiểu trước khi đưa bản build đầu tiên cho người dùng thật ngoài nhóm phát triển, theo đúng thứ tự phụ thuộc giữa các bước đã trình bày xuyên suốt bài:

- Driver ELAM và minifilter đã qua attestation signing hoặc WHQL (phần ký số driver), không còn dùng testsigning.
- Toàn bộ rule heuristic/YARA đã qua giai đoạn log-only đủ lâu trên tập file sạch đa dạng (phần xử lý false positive), không còn rule nào mới chưa đo tỷ lệ false positive.
- Cơ chế quarantine đã test khôi phục thành công cả trên file thường và trên trường hợp giả lập gắn cờ nhầm file hệ thống.
- Update service đã test được luồng incremental delta lẫn fallback full download, và verify chữ ký số CSDL tải về hoạt động đúng.
- Tiến trình service đã chạy ở PPL Antimalware nếu đã có certificate phù hợp, hoặc ghi rõ trong tài liệu nội bộ đây là hạn chế đã biết nếu chưa có certificate này.
- Đã quyết định rõ trạng thái đăng ký MVI/Windows Security Center, nếu chưa qua MVI, tài liệu hướng dẫn cài đặt cho người dùng cần nêu rõ khả năng xung đột với Windows Defender và cách xử lý, thay vì im lặng để người dùng tự phát hiện.
- Bộ test EICAR đã chạy qua cả ba luồng (full scan, Downloads, real-time) và cho kết quả đúng ở mỗi luồng.

Bản phát hành đầu tiên không cần đã hoàn thiện mọi mục trên ở mức sản phẩm thương mại, nhưng mỗi mục còn thiếu cần được ghi nhận rõ ràng thành hạn chế đã biết thay vì bị bỏ sót âm thầm, một antivirus tự nhận có real-time protection nhưng chưa test độ trễ, hay tự nhận có deep scan nhưng chưa test trên ổ HDD, gây hiểu lầm nguy hiểm hơn nhiều so với việc công khai nói rõ tính năng nào còn ở giai đoạn thử nghiệm.
