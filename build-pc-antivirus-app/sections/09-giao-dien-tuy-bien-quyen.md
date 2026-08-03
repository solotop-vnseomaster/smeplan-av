## Giao diện tùy biến quyền cho ứng dụng bên thứ 3

Khi một tiến trình không đạt cả ba tiêu chí "trusted by default" ở phần 5, luồng UI hiển thị một hộp thoại chặn (modal, không cho phép người dùng thao tác gì khác trên máy trong lúc chờ) với tối thiểu bốn thông tin: tên file và đường dẫn đầy đủ, publisher (nếu có ký số, dù không phải Microsoft) hoặc "Không xác định" nếu unsigned, hash SHA-256 rút gọn để người dùng có thể tự tra cứu trên VirusTotal nếu nghi ngờ, và ba lựa chọn rõ ràng: Cho phép luôn (lưu rule vĩnh viễn), Chỉ lần này (không lưu rule, hỏi lại lần sau), Chặn.

Điểm dễ bị bỏ qua nhất khi thiết kế hộp thoại này: chính giao diện đó có thể trở thành vector tấn công nếu không được bảo vệ đúng cách, vì malware hoàn toàn có thể lợi dụng nếu hộp thoại dễ bị tự động hóa. Ba biện pháp cụ thể cần có:

- **Hộp thoại phải chạy trong một tiến trình UI riêng ở mức toàn vẹn cao (High Integrity Level) hoặc trong secure desktop**, tương tự cách UAC hoạt động, để một tiến trình malware ở mức toàn vẹn thấp hơn không thể gửi window message giả lập click "Cho phép" vào nút bấm.
- **Nút "Cho phép luôn" mặc định không được focus sẵn** và cần một khoảng trễ tối thiểu (ví dụ nửa giây) trước khi nhận input, để loại trừ trường hợp một script tự động gửi phím Enter ngay khi hộp thoại vừa xuất hiện.
- **Không hiển thị hộp thoại từ chính tiến trình đang bị đánh giá**, hộp thoại luôn do service nền (chạy quyền SYSTEM, tách biệt hoàn toàn với tiến trình đang xin quyền) khởi tạo, để tiến trình khả nghi không có cách nào can thiệp trực tiếp vào nội dung hoặc hành vi của hộp thoại đang hỏi về chính nó.

Rule được người dùng chọn ("Cho phép luôn" hoặc "Chặn") cần được lưu lại có cấu trúc để không phải hỏi lại mỗi lần, cách lưu trữ và tra cứu rule này được trình bày ở phần tiếp theo.
