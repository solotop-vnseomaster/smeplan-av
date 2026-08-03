## Đăng ký với Windows Security Center và tránh xung đột Defender

Đây là điểm dễ hiểu nhầm nhất trong toàn bộ quá trình xây dựng app: không tồn tại một API công khai đơn giản để bất kỳ ứng dụng nào tự "đăng ký" mình là AV provider và được Windows Security Center tin ngay lập tức. Con đường thực tế là tham gia chương trình **Microsoft Virus Initiative (MVI)**, yêu cầu công ty đạt chứng nhận từ một phòng test độc lập được Microsoft công nhận (như AV-Test, AV-Comparatives, hoặc ICSA Labs), chứng minh sản phẩm có bộ phát hiện thật đạt tiêu chuẩn tối thiểu, cùng tuân thủ các yêu cầu kỹ thuật khác của chương trình. Chỉ sau khi được chấp nhận vào MVI, sản phẩm mới được cấp quyền đăng ký hiển thị trong Windows Security Center qua interface dành riêng cho provider đã duyệt.

Nếu bỏ qua bước này và cố tự ý thao tác các registry key hoặc gọi API liên quan đến WSC provider mà không qua MVI, Windows sẽ không công nhận app là AV hợp lệ, hệ quả cụ thể là Windows Defender vẫn coi máy "không có bảo vệ của bên thứ 3" và tiếp tục tự bật real-time protection của chính nó chạy song song, dẫn tới hai minifilter driver cùng tranh chấp lock trên cùng file, gây lỗi khó chẩn đoán hoặc giảm hiệu năng đáng kể, đây chính là kịch bản xung đột hai AV cùng chạy mà bất kỳ ai từng cài hai phần mềm diệt virus cùng lúc đều gặp phải.

Trong giai đoạn phát triển và test, khi chưa qua MVI, giải pháp hợp lệ và thực tế để hai engine không tranh chấp là chủ động loại trừ thư mục cài đặt và tiến trình của app khỏi phạm vi quét của Windows Defender bằng PowerShell chạy quyền Administrator:

```powershell
Add-MpPreference -ExclusionPath "C:\Program Files\YourAntivirus"
Add-MpPreference -ExclusionProcess "YourAntivirusService.exe"
```

Đây chỉ là giải pháp tạm thời cho môi trường dev/test trên máy của chính nhóm phát triển, không phải cấu hình dành cho bản phát hành thật, không nên và không thể yêu cầu người dùng cuối tự chạy lệnh loại trừ Defender cho một app chưa được công nhận chính thức, vì làm vậy đồng nghĩa tắt một lớp bảo vệ thật của Windows mà không có gì thay thế đáng tin cậy tương đương cho tới khi app đã qua MVI.
