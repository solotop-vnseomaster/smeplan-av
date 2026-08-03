## Kiểm thử với file EICAR và bộ mẫu an toàn

Chuỗi test EICAR là một tiêu chuẩn ngành có thật, được thiết kế để mọi engine antivirus nhận diện là "mã độc" mà không chứa bất kỳ đoạn code thực thi nguy hiểm nào, an toàn tuyệt đối để dùng trong test, kể cả trên máy sản xuất. Nội dung đầy đủ, tạo bằng cách ghi chính xác chuỗi ASCII sau vào một file `.com` hoặc `.txt`:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Vì đây là chuỗi công khai được mọi vendor antivirus công nhận, việc quan trọng khi test là kiểm tra pipeline phát hiện chạy đúng ở đúng tầng, không chỉ kiểm tra "có báo động hay không". Kịch bản test tối thiểu gồm ba lần thử tách biệt: (1) đặt file EICAR tĩnh vào một thư mục thường rồi chạy full scan, xác nhận engine trả về `Malicious` qua đúng nhánh CSDL hash (vì EICAR nằm sẵn trong hầu hết CSDL signature công khai) chứ không rơi vào nhánh heuristic; (2) copy file EICAR vào thư mục Downloads, xác nhận luồng giám sát Downloads bắt được sự kiện rename/added và tự động quét, đo thời gian từ lúc file xuất hiện tới lúc cảnh báo hiện ra; (3) cố mở trực tiếp file EICAR bằng một chương trình bất kỳ, xác nhận minifilter chặn thao tác mở trước khi chương trình đọc được nội dung, không phải chặn sau khi đã đọc.

Ngoài EICAR (chỉ test được nhánh phát hiện "có mã độc"), cần thêm một bộ mẫu file sạch đa dạng, toàn bộ file trong `Program Files` của một máy Windows cài mới, một vài phần mềm phổ biến hợp pháp có dùng packer (ví dụ bản cài của một ứng dụng dùng UPX), và các định dạng file nén hợp lệ với tỷ lệ nén cao (ví dụ file cài đặt game nén tốt), để đo tỷ lệ false positive của engine trên tập dữ liệu sạch trước khi coi bất kỳ rule heuristic hay YARA mới nào là sẵn sàng chuyển từ chế độ log-only sang enforce, quy trình được nêu chi tiết ở phần tiếp theo.
