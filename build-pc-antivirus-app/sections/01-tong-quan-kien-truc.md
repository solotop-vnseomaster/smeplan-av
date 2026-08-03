## Tổng quan kiến trúc app antivirus Windows

Một app antivirus hoạt động được trên Windows luôn tách thành năm khối riêng biệt, chạy ở hai tầng quyền khác nhau, và giao tiếp với nhau qua kênh có kiểm soát chứ không gọi trực tiếp lẫn nhau.

Ở tầng user-mode có ba khối: giao diện người dùng (UI) chỉ chịu trách nhiệm hiển thị và nhận thao tác, không tự xử lý logic phát hiện; service nền chạy dưới quyền SYSTEM, sống độc lập với UI (để khi người dùng đóng cửa sổ, bảo vệ vẫn tiếp tục chạy) và giữ toàn bộ logic điều phối; scan engine là thư viện xử lý việc quét file thực tế, được service nền gọi vào, dùng chung cho cả full scan lẫn real-time scanning để không phải viết hai bộ logic phát hiện khác nhau cho hai luồng.

Ở tầng kernel-mode có hai khối bắt buộc nếu muốn có real-time protection thật sự: driver ELAM (Early Launch Antimalware) nạp sớm nhất trong quá trình boot để phân loại các driver boot-start khác, và minifilter driver chặn thao tác mở/đọc/ghi file ở cấp filesystem trước khi Windows cho phép thao tác đó hoàn tất. Hai driver này giao tiếp ngược lên service nền qua filter communication port (`FltCreateCommunicationPort`), vì logic quét phức tạp (heuristic, YARA, tra CSDL hash) không nên và không thể chạy trong kernel, code kernel-mode lỗi gây blue screen ngay lập tức, nên nguyên tắc thiết kế là giữ kernel-mode càng mỏng càng tốt: chỉ chặn và hỏi, không tự quyết định.

Khối thứ sáu, nằm ngoài vòng đời chạy nhưng vẫn là một phần kiến trúc, là CSDL signature cùng cơ chế cập nhật, được lưu cục bộ dưới dạng file (không phải chạy trong process) để cả scan engine lẫn driver có thể tra cứu nhanh mà không phụ thuộc kết nối mạng liên tục. Các phần tiếp theo của bài đi sâu vào từng khối này, bắt đầu từ việc chọn công cụ và ngôn ngữ phù hợp cho từng tầng.
