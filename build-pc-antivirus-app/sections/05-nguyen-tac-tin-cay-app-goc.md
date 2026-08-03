## Nguyên tắc mặc định tin cậy ứng dụng gốc Windows

Đừng dùng tên file hay đường dẫn làm căn cứ chính để coi một tiến trình là "app Windows gốc", cả hai đều là chuỗi văn bản mà bất kỳ file nào cũng copy được nguyên xi. Một binary tên `svchost.exe` đặt trong `C:\Users\Public\svchost.exe` chứng minh chính xác điều đó: cùng tên, khác hoàn toàn về độ tin cậy.

Ba tiêu chí sau, dùng kết hợp cả ba chứ không tách rời, mới đủ để coi một tiến trình là app gốc Windows đáng tin cậy mặc định:

1. **Chữ ký số Authenticode hợp lệ với chain dẫn về Microsoft Root CA.** Certificate còn hiệu lực, chưa bị thu hồi, và chain xác thực đầy đủ tới root certificate của Microsoft chứ không dừng ở một intermediate CA lạ.
2. **Publisher name trong subject của certificate khớp chính xác** với các giá trị chính thức như "Microsoft Windows" hoặc "Microsoft Corporation", không chấp nhận so khớp gần đúng hay chứa chuỗi con, vì kỹ thuật giả mạo publisher name bằng ký tự Unicode trông giống hệt là có thật.
3. **Vị trí file nằm trong thư mục được Windows Resource Protection (WRP) bảo vệ**, ví dụ `C:\Windows\System32`, với ACL cho thấy chỉ `TrustedInstaller` mới có quyền ghi, nếu một file nằm đúng tên trong đúng thư mục nhưng ACL đã bị nới lỏng bất thường (không còn giữ nguyên quyền TrustedInstaller mặc định), đó là dấu hiệu đáng ngờ cần hạ mức tin cậy xuống thay vì tự động allow.

Chỉ khi cả ba điều kiện cùng đúng, engine mới gắn nhãn "trusted by default" cho tiến trình đó và không yêu cầu người dùng xác nhận quyền, bất kỳ điều kiện nào thiếu, tiến trình rơi vào nhóm "ứng dụng bên thứ 3" và đi qua luồng tùy biến quyền được trình bày ở các phần sau. Cách tiếp cận ba lớp này cũng là nền cho toàn bộ cơ chế whitelist mặc định, được hiện thực hóa cụ thể bằng code ở phần tiếp theo.
