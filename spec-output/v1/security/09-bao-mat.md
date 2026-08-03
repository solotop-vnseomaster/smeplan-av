---
id: "bao-mat"
kind: security
title: "Bảo mật & Phân quyền"
spec_version: "v1"
module: "bao-mat"
created_at: "2026-08-01T15:53:32.608145+00:00"
sources:
  - { source_id: "S1", loc: "chunk#30 Cập nhật cơ sở dữ liệu virus tự động", hash: "50e50f2343f3f260ae921b918770fb538289ed51bf6ecb9d4f2f5465cdd3ba87" }
  - { source_id: "S1", loc: "chunk#29 Cơ chế Quarantine cách ly file nghi ngờ", hash: "c0d0d265c33eefbe75d7d1c6ec0772dae67f0eeefa2112b992b52c7b021289ad" }
  - { source_id: "S1", loc: "chunk#10 Lưu trữ và quản lý rule phân quyền", hash: "2eef23f72066b39840103d0f6b4062d1b7da7382f05a22662890b36504d838f9" }
  - { source_id: "S1", loc: "chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật", hash: "738f35b68d00a2f40c9d8bee712457df7a70bd4107526f29106a9b8ede50cf74" }
  - { source_id: "S1", loc: "chunk#26 Ký số driver với Microsoft", hash: "86cf57e26ce6aa8219dd02178bb6368ecdabd98941ecb7feaeadd677ee519848" }
  - { source_id: "S1", loc: "chunk#35 Chống tắt ứng dụng bằng Protected Process Light", hash: "5b39fd5afef125607e87d665e0ec31d3a49dba81ea26201afa8beb89f69eb646" }
  - { source_id: "S1", loc: "chunk#21 Kiến trúc Real-time Protection bằng minifilter driver", hash: "ca39313935dca7f58cc49929dcb748a9f1b8ec088b8df5bd5ca87925c2ef14b7" }
  - { source_id: "S1", loc: "chunk#40 Những lỗi thường gặp khi tự xây antivirus", hash: "f337bd98c9a969567f2a3a2849d5f0d8c8aeb664fa08dd3143032ae6d671f345" }
  - { source_id: "S1", loc: "chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,", hash: "17f42d943690edcd37b9aa9205d8c5380cfe386671ef09c88769ba359d78cec5" }
  - { source_id: "S1", loc: "chunk#24 Giảm độ trễ khi quét theo thời gian thực", hash: "c95bc499a4f1bea0c0989dab031faddacda3d388d59691bca876214cf8810ac0" }
  - { source_id: "S1", loc: "chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường", hash: "e44c7e7f08017f68ab3e6a509472b314de4aa80c6e8173374d4bc431d09998bf" }
  - { source_id: "S1", loc: "chunk#4 Thiết lập môi trường phát triển", hash: "beaf2b68b93b9f502335ca2eca154631972f52fddf86d0463ff3633378aa4d1b" }
  - { source_id: "S1", loc: "chunk#9 Giao diện tùy biến quyền cho ứng dụng bên thứ 3", hash: "03948fea0e449152ae61d582b0d81821a5bf18aaaabb6079dcf3fcfca9c22cdf" }
  - { source_id: "S1", loc: "chunk#5 Nguyên tắc mặc định tin cậy ứng dụng gốc Windows", hash: "092c498ec704be0cb77634e0ebf538fbc1f968c8fca05166290df872ff02ba23" }
  - { source_id: "S1", loc: "chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender", hash: "5803b7b4e05da0cb47c25597863ce39af922cf6099f3fd5b04bcf74f101eff07" }
  - { source_id: "S1", loc: "chunk#7 Giới hạn của whitelist theo chữ ký số", hash: "40ff3f848503ba100ca44a546f2f028712d34596abfe0cb201f97edc9ebd80a1" }
  - { source_id: "S1", loc: "chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ", hash: "80eee532e66bbb3dcf94905b34d298864ce356a9f5347704f9d66c9d38f3f976" }
  - { source_id: "S1", loc: "chunk#1 Tổng quan kiến trúc app antivirus Windows", hash: "b142a39c6bc430bae5289b9f8ef71a468f7f5d0d7b27c4ceb33d86a64a77f17f" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#41 Kết luận", hash: "3eec6601c076d2c8892032d28b2554d458259a89bb1b7db59f4c6a37b4d41d6a" }
---

# Bảo mật & Phân quyền

## Mục lục
- [1. Luồng xác thực](#1-luồng-xác-thực)
- [2. Bảng phân quyền](#2-bảng-phân-quyền)
- [3. Lưu trữ & bảo vệ dữ liệu nhạy cảm](#3-lưu-trữ--bảo-vệ-dữ-liệu-nhạy-cảm)
- [4. Danh sách rủi ro bảo mật đã biết và biện pháp giảm thiểu](#4-danh-sách-rủi-ro-bảo-mật-đã-biết-và-biện-pháp-giảm-thiểu)

## 1. Luồng xác thực

Hệ thống không có luồng đăng nhập người dùng cuối/cấp token phiên kiểu ứng dụng web;
"xác thực" trong ngữ cảnh app antivirus này là xác thực danh tính/tính toàn vẹn của tiến
trình và dữ liệu, gồm ba luồng cụ thể có bằng chứng:

- **Xác thực chữ ký số Authenticode cho tiến trình**: gọi `WinVerifyTrust` với action GUID
  `WINTRUST_ACTION_GENERIC_VERIFY_V2` trên đường dẫn file thực thi; hàm tự kiểm tra toàn
  bộ chain certificate, thời hạn hiệu lực và trạng thái thu hồi (CRL/OCSP nếu có mạng)
  [S1]. Sau khi chain hợp lệ, kiểm tra publisher name trong subject certificate khớp
  chính xác với "Microsoft Windows"/"Microsoft Corporation" bằng so khớp chuỗi chính
  xác, không dùng hàm chứa chuỗi con [S1]. Kết quả này kết hợp với điều kiện vị trí thư
  mục (WRP) để service nền quyết định gắn nhãn "trusted by default" cho tiến trình [S1].
- **Luồng cấp quyền cho ứng dụng bên thứ 3 không đạt trusted-by-default**: hộp thoại xin
  quyền hiển thị tên file/đường dẫn, publisher (hoặc "Không xác định" nếu unsigned), hash
  SHA-256 rút gọn, và ba lựa chọn Cho phép luôn/Chỉ lần này/Chặn; hộp thoại luôn do
  service nền (SYSTEM) khởi tạo, không phải tiến trình đang bị đánh giá [S1].
- **Xác thực chữ ký số cho gói CSDL cập nhật**: mỗi gói tải về (full hoặc delta) phải
  được xác minh chữ ký số bằng `WinVerifyTrust`, ký bằng chính certificate của công ty,
  trước khi được áp dụng vào CSDL cục bộ [S1].

Cơ chế refresh/hết hạn token: TODO [UNKNOWN] — không áp dụng theo mô hình token phiên
truyền thống trong ngữ cảnh được cấp cho tài liệu này.

## 2. Bảng phân quyền

| Vai trò | Hành động được phép |
|---|---|
| SYSTEM | Duy nhất đọc/ghi được thư mục quarantine [S1]; ghi được bảng rule phân quyền (`app_rules`) cùng Administrator [S1]; là chủ thể duy nhất khởi tạo hộp thoại xin quyền [S1]; chạy service điều phối chính ở mức bảo vệ Protected Process Light nếu có certificate Antimalware [S1] |
| Administrator | Ghi được bảng rule phân quyền (cùng SYSTEM) [S1]; mở volume (`\\.\C:`) phục vụ full/deep scan [S1]; chạy lệnh PowerShell loại trừ Windows Defender trong môi trường dev/test [S1] |
| Tiến trình thường (không SYSTEM/Administrator) | Không được ghi trực tiếp vào bảng rule phân quyền hay vào registry keys/file cấu hình quan trọng (đường dẫn CSDL, bảng rule) — bị chặn bằng ACL [S1]; không tự mở được file trong quarantine bằng Explorer [S1]; không thể mở handle `PROCESS_TERMINATE` tới service đang chạy PPL Antimalware, kể cả khi chạy quyền Administrator [S1] |
| Người dùng (qua giao diện chính/hộp thoại UI) | Chọn Cho phép luôn/Chỉ lần này/Chặn khi được hỏi quyền cho ứng dụng bên thứ 3 [S1]; xác nhận khôi phục file khỏi quarantine hoặc xác nhận quarantine thủ công cho file hệ thống bị gắn cờ [S1] |

## 3. Lưu trữ & bảo vệ dữ liệu nhạy cảm

- **Bảng rule phân quyền (`app_rules`)**: lưu trong file SQLite cục bộ đặt trong thư mục
  dữ liệu được ACL bảo vệ chỉ cho SYSTEM và Administrator ghi được; nếu một tiến trình
  thường ghi được trực tiếp, toàn bộ cơ chế phân quyền sụp đổ vì malware chỉ cần tự thêm
  rule "Cho phép luôn" cho chính nó [S1].
- **File trong quarantine**: qua hai bước biến đổi bắt buộc trước khi lưu — đổi tên thành
  định danh không mang phần mở rộng gốc (ví dụ GUID) để không bị vô tình thực thi, và mã
  hóa nội dung bằng một khóa đơn giản (ví dụ XOR với khóa cố định); mục đích chỉ là ngăn
  chương trình khác đọc/chạy tình cờ, không phải chống phân tích chuyên sâu [S1]. Khu vực
  quarantine là thư mục hệ thống được ACL bảo vệ, chỉ SYSTEM đọc/ghi được [S1].
- **Registry keys và file cấu hình quan trọng** (đường dẫn CSDL, bảng rule phân quyền):
  cần ACL chặn ghi từ tiến trình không phải SYSTEM, để kẻ tấn công không đi vòng qua việc
  tắt service bằng cách sửa trực tiếp cấu hình trong lúc service đang chạy [S1].
- **Gói CSDL cập nhật (full/delta)**: phải được xác minh chữ ký số bằng `WinVerifyTrust`
  trước khi áp dụng; sau khi verify, ghi vào file tạm rồi đổi tên hoán đổi nguyên tử
  (`MoveFileEx` với `MOVEFILE_REPLACE_EXISTING`) thay thế file cũ, để không bao giờ có
  khoảng thời gian CSDL ở trạng thái ghi dở dang nếu update service crash hoặc mất điện
  giữa chừng [S1].
- **EV Code Signing Certificate** (dùng ký driver và installer): bắt buộc lưu trên USB
  token phần cứng theo yêu cầu của chuẩn EV, không cho export ra file mềm [S1].

## 4. Danh sách rủi ro bảo mật đã biết và biện pháp giảm thiểu

| Rủi ro | Biện pháp giảm thiểu |
|---|---|
| Malware giả mạo app Windows gốc bằng cách đặt file trùng tên/đường dẫn (ví dụ `svchost.exe` giả) | Whitelist ba lớp kết hợp: chữ ký số Authenticode hợp lệ + publisher khớp chính xác + vị trí thư mục được Windows Resource Protection bảo vệ, dùng cả ba chứ không tách rời [S1] |
| Rootkit ký bằng certificate bị đánh cắp hoặc certificate công ty vỏ bọc để nạp driver độc hại trước cả antivirus | Bắt buộc driver kernel-mode mới phải ký qua Microsoft trên máy bật Secure Boot, không có ngoại lệ self-signed hay CA thương mại thông thường; certificate EKU riêng cho ELAM chỉ cấp qua chương trình đối tác Microsoft [S1] |
| ELAM giả mạo có thể chặn driver bảo mật thật của người khác nạp lên trước | Windows giới hạn số lượng driver ELAM được nạp ở giai đoạn boot sớm nhất, chỉ driver mang đúng certificate EKU Early Launch Antimalware mới được công nhận [S1] |
| Giả mạo publisher name bằng ký tự Unicode trông giống hệt "Microsoft Windows"/"Microsoft Corporation" | So khớp chuỗi publisher name chính xác, không dùng hàm chứa chuỗi con (`wcsstr`) [S1] |
| Rootkit đã chiếm quyền hệ thống cao hơn TrustedInstaller thay thế binary hợp lệ nhưng giữ nguyên chữ ký cũ, hoặc code injection vào tiến trình đã whitelist | Whitelist theo chữ ký số CHỈ xử lý được phần lớn trường hợp giả mạo phổ biến, không phải giải pháp chống rootkit toàn diện; kernel integrity monitoring/giám sát vùng nhớ tiến trình nằm ngoài phạm vi app này, cần kỹ thuật khác [S1] |
| Malware tự thêm rule "Cho phép luôn" cho chính nó nếu ghi được vào bảng rule | ACL bảo vệ file rule chỉ cho SYSTEM và Administrator ghi được [S1] |
| Malware tự động hóa việc click "Cho phép" trên hộp thoại xin quyền (giả lập window message hoặc gửi phím Enter) | Hộp thoại chạy ở High Integrity Level/secure desktop; nút "Cho phép luôn" không focus sẵn và có độ trễ tối thiểu trước khi nhận input; hộp thoại luôn do service SYSTEM khởi tạo, không phải tiến trình đang bị đánh giá [S1] |
| Malware chạy quyền Administrator tắt service antivirus qua Task Manager trước khi thực thi payload | Chạy service ở Protected Process Light (PPL) với signer level "Antimalware" (yêu cầu certificate EKU Antimalware), không thể bị mở handle `PROCESS_TERMINATE` từ tiến trình thường kể cả chạy quyền Administrator [S1] |
| Kẻ tấn công vòng qua bảo vệ tiến trình bằng cách sửa trực tiếp file cấu hình/registry trong lúc service đang chạy | ACL chặn ghi từ tiến trình không phải SYSTEM lên registry keys và file cấu hình quan trọng (đường dẫn CSDL, bảng rule) — bảo vệ tiến trình mà không bảo vệ dữ liệu nó đọc/ghi chỉ giải quyết được một nửa vấn đề [S1] |
| Máy chủ CDN hoặc kênh phân phối CSDL bị xâm nhập, đẩy CSDL giả xuống máy người dùng (đã từng xảy ra thực tế với vài sản phẩm bảo mật) | Verify chữ ký số mọi gói CSDL (full/delta) bằng `WinVerifyTrust` trước khi áp dụng, ký bằng certificate của chính công ty [S1] |
| Hai AV cùng chạy tranh chấp lock file nếu app chưa qua MVI (Windows Defender vẫn tự bật real-time protection song song) | Tham gia chương trình Microsoft Virus Initiative (MVI); trong giai đoạn dev/test loại trừ tạm thời Windows Defender bằng PowerShell quyền Administrator, không áp dụng cho người dùng cuối [S1] |


## Nguồn tham chiếu
- S1 (final.md, chunk#30 Cập nhật cơ sở dữ liệu virus tự động)
- S1 (final.md, chunk#29 Cơ chế Quarantine cách ly file nghi ngờ)
- S1 (final.md, chunk#10 Lưu trữ và quản lý rule phân quyền)
- S1 (final.md, chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật)
- S1 (final.md, chunk#26 Ký số driver với Microsoft)
- S1 (final.md, chunk#35 Chống tắt ứng dụng bằng Protected Process Light)
- S1 (final.md, chunk#21 Kiến trúc Real-time Protection bằng minifilter driver)
- S1 (final.md, chunk#40 Những lỗi thường gặp khi tự xây antivirus)
- S1 (final.md, chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,)
- S1 (final.md, chunk#24 Giảm độ trễ khi quét theo thời gian thực)
- S1 (final.md, chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường)
- S1 (final.md, chunk#4 Thiết lập môi trường phát triển)
- S1 (final.md, chunk#9 Giao diện tùy biến quyền cho ứng dụng bên thứ 3)
- S1 (final.md, chunk#5 Nguyên tắc mặc định tin cậy ứng dụng gốc Windows)
- S1 (final.md, chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender)
- S1 (final.md, chunk#7 Giới hạn của whitelist theo chữ ký số)
- S1 (final.md, chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ)
- S1 (final.md, chunk#1 Tổng quan kiến trúc app antivirus Windows)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#41 Kết luận)
