---
id: "tong-quan"
kind: overview
title: "Tổng quan"
spec_version: "v1"
module: "tong-quan"
created_at: "2026-08-01T15:42:01.068630+00:00"
sources:
  - { source_id: "S1", loc: "chunk#1 Tổng quan kiến trúc app antivirus Windows", hash: "b142a39c6bc430bae5289b9f8ef71a468f7f5d0d7b27c4ceb33d86a64a77f17f" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender", hash: "5803b7b4e05da0cb47c25597863ce39af922cf6099f3fd5b04bcf74f101eff07" }
  - { source_id: "S1", loc: "chunk#24 Giảm độ trễ khi quét theo thời gian thực", hash: "c95bc499a4f1bea0c0989dab031faddacda3d388d59691bca876214cf8810ac0" }
  - { source_id: "S1", loc: "chunk#18 Tối ưu hiệu năng khi quét sâu", hash: "6651987e1a5f94a302fefea430b892f7713846471fc366e723235c419fcf9f23" }
  - { source_id: "S1", loc: "chunk#16 Tích hợp YARA rules vào scan engine", hash: "09f3633e6e1995108b8c8a01daa26dd7a383faf54cee9139abed99d3278ad6b4" }
  - { source_id: "S1", loc: "chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", hash: "4f3ee047f0e2b9eff547e6871b1da177a8c0f97319d67e1f99089eb8b83d305c" }
  - { source_id: "S1", loc: "chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa", hash: "bcf95a76fd630c410fa5205a4cb67cf644f19f86b3c5e705b59ccecbe07ef035" }
  - { source_id: "S1", loc: "chunk#29 Cơ chế Quarantine cách ly file nghi ngờ", hash: "c0d0d265c33eefbe75d7d1c6ec0772dae67f0eeefa2112b992b52c7b021289ad" }
  - { source_id: "S1", loc: "chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường", hash: "e44c7e7f08017f68ab3e6a509472b314de4aa80c6e8173374d4bc431d09998bf" }
  - { source_id: "S1", loc: "chunk#10 Lưu trữ và quản lý rule phân quyền", hash: "2eef23f72066b39840103d0f6b4062d1b7da7382f05a22662890b36504d838f9" }
  - { source_id: "S1", loc: "chunk#41 Kết luận", hash: "3eec6601c076d2c8892032d28b2554d458259a89bb1b7db59f4c6a37b4d41d6a" }
  - { source_id: "S1", loc: "chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,", hash: "17f42d943690edcd37b9aa9205d8c5380cfe386671ef09c88769ba359d78cec5" }
  - { source_id: "S1", loc: "chunk#27 Giám sát riêng thư mục Downloads", hash: "2c250a52583f3208242ad843aef00370be7ca79dbfbffe35b3fd4d92763dc4f0" }
  - { source_id: "S1", loc: "chunk#23 NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL", hash: "06f81b36fd2a8fc5200f665027562b08c60e062f94aaec6507423e2c846d58e1" }
  - { source_id: "S1", loc: "chunk#19 Quét trong file nén và chống zip bomb", hash: "72554f74c77e4383627c539208132779f6fd51651765a6d7e926ca3e4cb9b83a" }
  - { source_id: "S1", loc: "chunk#35 Chống tắt ứng dụng bằng Protected Process Light", hash: "5b39fd5afef125607e87d665e0ec31d3a49dba81ea26201afa8beb89f69eb646" }
  - { source_id: "S1", loc: "chunk#20 Quét trong file nén và chống zip bomb", hash: "aa9d8cd228951c99653ecd1a0a1b66809ce11fa26129f5c42ac1a03a04812df6" }
  - { source_id: "S1", loc: "chunk#25 Viết Early Launch Antimalware driver cơ bản", hash: "f41b68505282e58b734c1adc5e3581a2968329011499fedca868e830669419c2" }
  - { source_id: "S1", loc: "chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ", hash: "80eee532e66bbb3dcf94905b34d298864ce356a9f5347704f9d66c9d38f3f976" }
---

# Tổng quan

## Mục lục
- [Mục tiêu](#mục-tiêu)
- [Phạm vi](#phạm-vi)
- [Vai trò và quyền hạn của các bên liên quan](#vai-trò-và-quyền-hạn-của-các-bên-liên-quan)

## Mục tiêu

Xây dựng một ứng dụng antivirus hoạt động thật trên Windows, tách thành sáu khối kiến
trúc riêng biệt chạy ở hai tầng quyền khác nhau: giao diện người dùng (UI), service nền
chạy quyền SYSTEM, scan engine, driver ELAM, minifilter driver, và CSDL signature cùng
cơ chế cập nhật [S1]. Mục tiêu cụ thể của hệ thống gồm:

- Mặc định tin cậy các ứng dụng gốc Windows dựa trên whitelist theo chữ ký số, đồng thời
  kiểm soát/tùy biến quyền đối với ứng dụng bên thứ 3 [S1].
- Quét sâu (full/deep scan) toàn bộ ổ đĩa thông qua enumerate USN Journal thay vì duyệt
  cây thư mục thông thường [S1].
- Phát hiện sớm theo thời gian thực (real-time protection) bằng minifilter driver chặn
  thao tác mở/đọc/ghi file ở cấp filesystem [S1].
- Giám sát riêng thư mục Downloads để quét file tải về ngay khi tải xong [S1].
- Cách ly (quarantine) file nghi ngờ thay vì xóa ngay, và cập nhật CSDL signature định
  kỳ [S1].
- Đăng ký với Windows Security Center thông qua chương trình Microsoft Virus Initiative
  (MVI) để tránh xung đột với Windows Defender [S1].
- Tự bảo vệ chính tiến trình service khỏi bị tắt bằng cơ chế Protected Process Light
  (PPL) [S1].

Theo phần kết luận của tài liệu nguồn, hệ thống hướng tới "kiến trúc và cơ chế cụ thể để
bắt đầu triển khai một antivirus Windows thật, từ whitelist app gốc theo chữ ký số, kiểm
soát quyền cho app bên thứ 3, quét sâu toàn ổ đĩa, real-time protection bằng minifilter,
đến quarantine và cập nhật CSDL" [S1].

## Phạm vi

### Bao gồm
- Kiến trúc 6 khối: UI, service nền (SYSTEM), scan engine, driver ELAM, minifilter
  driver, CSDL signature [S1].
- Pipeline phát hiện trong scan engine theo thứ tự chi phí tăng dần: tra hash SHA-256 →
  YARA rules → heuristic (entropy, IAT bất thường, entry point ngoài section) [S1].
- Bốn trạng thái kết quả quét: `Clean`, `Malicious`, `Suspicious`, `ScanError` [S1].
- Full/Deep scan toàn ổ đĩa qua `FSCTL_ENUM_USN_DATA`, tối ưu hiệu năng theo loại ổ đĩa
  (HDD/SSD) và trạng thái idle của người dùng [S1].
- Quét file nén với giới hạn chống zip bomb: tỷ lệ nén tối đa, độ sâu lồng nhau tối đa,
  trần dung lượng giải nén tuyệt đối [S1].
- Real-time protection qua minifilter (`PreCreateCallback`/`IRP_MJ_CREATE`) với cache kết
  quả quét và phân loại rủi ro theo phần mở rộng/magic bytes của file [S1].
- ELAM driver phân loại driver boot-start khác ở giai đoạn boot sớm nhất, trả về một
  trong bốn phân loại `Good`/`Bad`/`BadCritical`/`Unknown` [S1].
- Giám sát thư mục Downloads, xử lý đúng cơ chế đổi tên file tạm (`.crdownload`/`.part`)
  của trình duyệt trước khi quét [S1].
- Cơ chế Quarantine: đổi tên + mã hóa file, lưu metadata trong SQLite, hỗ trợ khôi phục
  qua giao diện chính [S1].
- Đăng ký Windows Security Center qua chương trình MVI; loại trừ tạm thời Windows
  Defender chỉ dùng cho môi trường dev/test, không dùng cho bản phát hành [S1].
- Tự bảo vệ tiến trình service bằng Protected Process Light (PPL, signer level
  Antimalware) và bảo vệ ACL cho file cấu hình/registry liên quan [S1].
- Kiểm thử bằng file EICAR ở ba tầng (full scan, giám sát Downloads, chặn minifilter),
  cùng bộ mẫu file sạch để đo tỷ lệ false positive [S1].

### Không bao gồm
TODO [UNKNOWN] — ngữ cảnh được cấp cho mục này không liệt kê rõ ràng các hạng mục bị loại
trừ khỏi phạm vi dự án (ví dụ nền tảng ngoài Windows, các lớp bảo vệ nâng cao khác ngoài
những gì đã liệt kê ở trên); cần bổ sung khi có thêm tài liệu nghiệp vụ.

## Vai trò và quyền hạn của các bên liên quan

| Vai trò/Thành phần | Tầng chạy | Quyền hạn / Trách nhiệm chính |
|---|---|---|
| Người dùng (User) | - | Xác nhận/từ chối quyền cho ứng dụng bên thứ 3, xác nhận khôi phục file khỏi quarantine qua giao diện chính, không thao tác trực tiếp file quarantine qua Explorer [S1] |
| Giao diện người dùng (UI) | User-mode | Chỉ hiển thị và nhận thao tác, không tự xử lý logic phát hiện [S1] |
| Service nền | User-mode, quyền SYSTEM | Giữ toàn bộ logic điều phối, sống độc lập với UI để bảo vệ tiếp tục chạy khi người dùng đóng cửa sổ, được bảo vệ bằng Protected Process Light (PPL, signer level Antimalware) [S1] |
| Scan engine | User-mode (thư viện) | Xử lý quét file thực tế (hash/YARA/heuristic), dùng chung cho full scan và real-time scanning, không biết và không cần biết ai đang gọi nó [S1] |
| Driver ELAM | Kernel-mode | Nạp sớm nhất trong quá trình boot, phân loại driver boot-start khác, yêu cầu certificate có Enhanced Key Usage riêng cho Early Launch Antimalware [S1] |
| Minifilter driver | Kernel-mode | Chặn thao tác mở/đọc/ghi file ở cấp filesystem trước khi Windows cho phép thao tác hoàn tất, giao tiếp ngược lên service nền qua filter communication port (`FltCreateCommunicationPort`) [S1] |
| Administrator | - | Cần quyền Administrator để mở volume phục vụ full scan (`\\.\C:`) và để chạy lệnh loại trừ Windows Defender trong môi trường dev/test [S1] |
| SYSTEM (qua ACL) | - | Duy nhất có quyền đọc/ghi thư mục quarantine và file rule phân quyền; nếu một tiến trình thường ghi được vào file rule, toàn bộ cơ chế phân quyền sụp đổ [S1] |
| Microsoft (MVI / driver signing) | Bên ngoài hệ thống | Cấp certificate ký driver/ELAM/Antimalware EKU; xét duyệt tham gia chương trình Microsoft Virus Initiative để được Windows Security Center công nhận là AV provider hợp lệ [S1] |


## Nguồn tham chiếu
- S1 (final.md, chunk#1 Tổng quan kiến trúc app antivirus Windows)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender)
- S1 (final.md, chunk#24 Giảm độ trễ khi quét theo thời gian thực)
- S1 (final.md, chunk#18 Tối ưu hiệu năng khi quét sâu)
- S1 (final.md, chunk#16 Tích hợp YARA rules vào scan engine)
- S1 (final.md, chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*)
- S1 (final.md, chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa)
- S1 (final.md, chunk#29 Cơ chế Quarantine cách ly file nghi ngờ)
- S1 (final.md, chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường)
- S1 (final.md, chunk#10 Lưu trữ và quản lý rule phân quyền)
- S1 (final.md, chunk#41 Kết luận)
- S1 (final.md, chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,)
- S1 (final.md, chunk#27 Giám sát riêng thư mục Downloads)
- S1 (final.md, chunk#23 NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
- S1 (final.md, chunk#19 Quét trong file nén và chống zip bomb)
- S1 (final.md, chunk#35 Chống tắt ứng dụng bằng Protected Process Light)
- S1 (final.md, chunk#20 Quét trong file nén và chống zip bomb)
- S1 (final.md, chunk#25 Viết Early Launch Antimalware driver cơ bản)
- S1 (final.md, chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ)
