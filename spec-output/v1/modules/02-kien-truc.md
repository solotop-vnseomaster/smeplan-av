---
id: "kien-truc"
kind: architecture
title: "Kiến trúc"
spec_version: "v1"
module: "kien-truc"
created_at: "2026-08-01T15:43:29.640842+00:00"
sources:
  - { source_id: "S1", loc: "chunk#1 Tổng quan kiến trúc app antivirus Windows", hash: "b142a39c6bc430bae5289b9f8ef71a468f7f5d0d7b27c4ceb33d86a64a77f17f" }
  - { source_id: "S1", loc: "chunk#0 Tự Xây Antivirus Windows: Kiểm Quyền, Quét Sâu, Real-time", hash: "d3b7349fba4476f51a55fa969fa36745722e2e44e4209f386f840b9727e037ea" }
  - { source_id: "S1", loc: "chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật", hash: "738f35b68d00a2f40c9d8bee712457df7a70bd4107526f29106a9b8ede50cf74" }
  - { source_id: "S1", loc: "chunk#41 Kết luận", hash: "3eec6601c076d2c8892032d28b2554d458259a89bb1b7db59f4c6a37b4d41d6a" }
  - { source_id: "S1", loc: "chunk#21 Kiến trúc Real-time Protection bằng minifilter driver", hash: "ca39313935dca7f58cc49929dcb748a9f1b8ec088b8df5bd5ca87925c2ef14b7" }
  - { source_id: "S1", loc: "chunk#11 Engine giám sát tiến trình theo thời gian thực", hash: "3362274f397f853363dbd50458567edaa7502b4cb582fb56b36a7a697dbaffb2" }
  - { source_id: "S1", loc: "chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", hash: "4f3ee047f0e2b9eff547e6871b1da177a8c0f97319d67e1f99089eb8b83d305c" }
  - { source_id: "S1", loc: "chunk#14 Xây dựng cơ sở dữ liệu signature dựa trên hash", hash: "8de40e7324bdcaa66f177c8e534b2f37953c2d4ca49074643ede798407cddead" }
  - { source_id: "S1", loc: "chunk#9 Giao diện tùy biến quyền cho ứng dụng bên thứ 3", hash: "03948fea0e449152ae61d582b0d81821a5bf18aaaabb6079dcf3fcfca9c22cdf" }
  - { source_id: "S1", loc: "chunk#39 Đóng gói, ký số installer và checklist phát hành", hash: "4237edd642b7c565dd067daad5463c98cbdac0dd3656d4aea610d1f9c301badf" }
  - { source_id: "S1", loc: "chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,", hash: "17f42d943690edcd37b9aa9205d8c5380cfe386671ef09c88769ba359d78cec5" }
  - { source_id: "S1", loc: "chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ", hash: "80eee532e66bbb3dcf94905b34d298864ce356a9f5347704f9d66c9d38f3f976" }
  - { source_id: "S1", loc: "chunk#37 Logging và báo cáo cho người dùng", hash: "538bc9459381222d16e8d5bf3c9692b1b3e9d087e2496b7d0f7dc738f0f90aad" }
  - { source_id: "S1", loc: "chunk#38 Đóng gói, ký số installer và checklist phát hành", hash: "60cfca34d7df11c73c83d6274602016ded4c89187fa0bb95f67bce7df25f722b" }
  - { source_id: "S1", loc: "chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa", hash: "bcf95a76fd630c410fa5205a4cb67cf644f19f86b3c5e705b59ccecbe07ef035" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#27 Giám sát riêng thư mục Downloads", hash: "2c250a52583f3208242ad843aef00370be7ca79dbfbffe35b3fd4d92763dc4f0" }
  - { source_id: "S1", loc: "chunk#10 Lưu trữ và quản lý rule phân quyền", hash: "2eef23f72066b39840103d0f6b4062d1b7da7382f05a22662890b36504d838f9" }
  - { source_id: "S1", loc: "chunk#16 Tích hợp YARA rules vào scan engine", hash: "09f3633e6e1995108b8c8a01daa26dd7a383faf54cee9139abed99d3278ad6b4" }
  - { source_id: "S1", loc: "chunk#25 Viết Early Launch Antimalware driver cơ bản", hash: "f41b68505282e58b734c1adc5e3581a2968329011499fedca868e830669419c2" }
---

# Kiến trúc

## Mục lục
- [1. Danh sách thành phần và vai trò](#1-danh-sách-thành-phần-và-vai-trò)
- [2. Lựa chọn công nghệ và lý do chọn](#2-lựa-chọn-công-nghệ-và-lý-do-chọn)
- [3. Luồng dữ liệu/luồng xử lý chính](#3-luồng-dữ-liệutuồng-xử-lý-chính)
- [4. Phụ thuộc giữa các thành phần](#4-phụ-thuộc-giữa-các-thành-phần)

## 1. Danh sách thành phần và vai trò

Hệ thống tách thành sáu khối riêng biệt, chạy ở hai tầng quyền khác nhau, giao tiếp qua
kênh có kiểm soát chứ không gọi trực tiếp lẫn nhau [S1]:

- **Giao diện người dùng (UI)** — tầng user-mode, chỉ chịu trách nhiệm hiển thị và nhận
  thao tác, không tự xử lý logic phát hiện [S1]. Bao gồm hộp thoại tùy biến quyền cho
  ứng dụng bên thứ 3, chạy trong tiến trình UI riêng ở mức toàn vẹn cao (High Integrity
  Level) hoặc secure desktop, do service nền khởi tạo chứ không phải tiến trình đang bị
  đánh giá [S1].
- **Service nền** — tầng user-mode, chạy dưới quyền SYSTEM, sống độc lập với UI để bảo vệ
  vẫn tiếp tục chạy khi người dùng đóng cửa sổ, giữ toàn bộ logic điều phối (tra rule,
  quyết định allow/block, gọi scan engine, ghi log, cập nhật CSDL) [S1]. Được bảo vệ khỏi
  bị tắt bằng Protected Process Light (PPL, signer level Antimalware) [S1].
- **Scan engine** — thư viện (DLL/static lib) xử lý việc quét file thực tế, nhận vào file
  handle hoặc buffer, trả về kết quả phân loại, không biết và không cần biết ai đang gọi
  nó; dùng chung cho cả full scan lẫn real-time scanning để không phải viết hai bộ logic
  phát hiện khác nhau cho hai luồng [S1].
- **Driver ELAM (Early Launch Antimalware)** — tầng kernel-mode, nạp sớm nhất trong quá
  trình boot, quyết định driver boot-start nào khác được phép nạp, là tuyến phòng thủ
  chống rootkit cố nạp driver độc hại trước cả antivirus [S1]. Có CSDL riêng, nhỏ gọn,
  đóng gói sẵn dưới dạng resource nhúng vì tại thời điểm ELAM chạy, service nền và CSDL
  chính chưa kịp khởi động [S1].
- **Minifilter driver** — tầng kernel-mode, đăng ký qua Filter Manager (`fltmgr.sys`),
  chặn thao tác mở/đọc/ghi file ở cấp filesystem trước khi Windows cho phép thao tác đó
  hoàn tất [S1]. Cũng đăng ký callback `PsSetCreateProcessNotifyRoutineEx` để chặn tiến
  trình mới đồng bộ ngay tại thời điểm tạo, trước khi tiến trình thực thi dòng lệnh đầu
  tiên [S1].
- **CSDL signature và cơ chế cập nhật** — nằm ngoài vòng đời chạy nhưng vẫn là một phần
  kiến trúc, lưu cục bộ dưới dạng file (không chạy trong process) để cả scan engine lẫn
  driver tra cứu nhanh mà không phụ thuộc kết nối mạng liên tục [S1].

## 2. Lựa chọn công nghệ và lý do chọn

- **Filter Manager (`fltmgr.sys`) cho minifilter**, thay vì tự viết legacy file system
  filter driver (cách cũ, phức tạp và dễ xung đột hơn nhiều); cần xin "altitude" (dải
  320000-329999 dành cho antivirus) từ Microsoft để tránh xung đột giữa các sản phẩm bảo
  mật cùng hook filesystem [S1].
- **Kết hợp ETW (`Microsoft-Windows-Kernel-Process`, event ID 1) và
  `PsSetCreateProcessNotifyRoutineEx` trong driver**, không chọn một trong hai: ETW cho
  logging/audit trail (không cần độ trễ bằng 0, dữ liệu phong phú hơn để hiển thị), còn
  callback kernel cho việc chặn thật (cần chạy đồng bộ, trước khi tiến trình thực thi)
  [S1].
- **`libyara` (mã nguồn mở) nhúng trực tiếp vào scan engine** để chạy rule YARA, thay vì
  gọi công cụ dòng lệnh riêng, vì cung cấp API C nhúng được và cho phép compile rule một
  lần lúc khởi động thay vì mỗi lần quét [S1].
- **`FSCTL_ENUM_USN_DATA` (USN Journal) trên NTFS cho full/deep scan**, nhanh hơn đáng kể
  so với duyệt cây thư mục (`FindFirstFile`/`FindNextFile`) vì trả về danh sách file theo
  thứ tự Master File Table trong một lần gọi thay vì hàng nghìn round-trip mở thư mục;
  cần fallback về duyệt cây thư mục thông thường cho volume không phải NTFS (FAT32,
  exFAT không hỗ trợ USN Journal) [S1].
- **Bloom filter (RAM) + file CSDL sorted array memory-map trên đĩa** cho tra cứu hash
  signature: Bloom filter trả lời cực nhanh "chắc chắn không có" với false positive rất
  thấp (có thể cấu hình, ví dụ 0.1%), lọc phần lớn truy vấn trước khi chạm đĩa; file CSDL
  đầy đủ dùng mảng bản ghi độ dài cố định sắp xếp theo `sha256` để binary search O(log n)
  trực tiếp trên file đã `MapViewOfFile` mà không cần load toàn bộ vào RAM [S1].
- **SQLite cục bộ cho bảng rule phân quyền**, đơn giản hơn triển khai hệ quản trị CSDL
  riêng và đủ nhanh cho khối lượng truy vấn của use case này, đặt trong thư mục dữ liệu
  được ACL bảo vệ chỉ cho SYSTEM và Administrator ghi được [S1].
- **WiX Toolset hoặc Inno Setup cho installer**, cả hai hỗ trợ tốt việc cài driver
  kernel-mode kèm ứng dụng; installer phải ký bằng cùng EV Code Signing Certificate dùng
  cho driver, không dùng certificate khác, vì SmartScreen đánh giá độ tin cậy một phần
  dựa trên uy tín tích lũy của certificate đó [S1].

## 3. Luồng dữ liệu/luồng xử lý chính

**Luồng chặn tiến trình mới (real-time process control):** driver bắt sự kiện tạo tiến
trình mới qua `PsSetCreateProcessNotifyRoutineEx`, gửi thông tin (đường dẫn, PID, hash
nếu đã tính sẵn) qua filter communication port xuống service nền để tra bảng rule đã lưu;
service trả quyết định allow/block ngược lại cho driver để hoàn tất hoặc từ chối việc tạo
tiến trình (`CreationStatus = STATUS_ACCESS_DENIED`) [S1].

**Luồng xin quyền cho ứng dụng bên thứ 3:** khi một tiến trình không đạt tiêu chí trusted
by default, UI hiển thị hộp thoại chặn (modal) với tên file/đường dẫn, publisher, hash
SHA-256 rút gọn, và ba lựa chọn Cho phép luôn/Chỉ lần này/Chặn; lựa chọn "Cho phép luôn"
được lưu thành rule trong bảng SQLite để không phải hỏi lại [S1].

**Luồng quét file (scan engine, dùng chung cho full scan và real-time):** (1) tra hash
SHA-256 trong CSDL signature cục bộ trước — nhanh nhất, kết luận ngay nếu khớp; (2) nếu
không khớp, chạy tập rule YARA qua `yr_rules_scan_file`/`yr_rules_scan_mem`; (3) nếu vẫn
chưa kết luận, chạy heuristic (entropy, cấu trúc PE bất thường); pipeline dừng ngay khi
có kết luận đủ chắc chắn, không luôn chạy hết mọi bước, và trả về một trong bốn trạng
thái `Clean`/`Malicious`/`Suspicious`/`ScanError` [S1].

**Luồng Full/Deep Scan:** mở volume bằng quyền Administrator, enumerate toàn bộ file qua
`FSCTL_ENUM_USN_DATA`, đưa kết quả vào work queue chia cho thread pool (số core vật lý
trừ 1), mỗi thread gọi vào scan engine cho từng file [S1].

**Luồng giám sát Downloads:** service nền đăng ký `ReadDirectoryChangesW` trên thư mục
Downloads (lấy đường dẫn thật qua `SHGetKnownFolderPath`); bắt sự kiện
`FILE_ACTION_RENAMED_NEW_NAME` (trình duyệt đổi tên từ `.crdownload`/`.part`) hoặc
`FILE_ACTION_ADDED` (công cụ dòng lệnh); xác nhận file đã ghi xong (polling `CreateFile`
exclusive hoặc hook `IRP_MJ_CLEANUP`) rồi mới đưa qua pipeline scan engine đồng bộ và đầy
đủ; kết quả `Malicious` tự động quarantine, `Suspicious` hiển thị cảnh báo cho người dùng
tự quyết [S1].

**Luồng ghi log:** mọi quyết định allow/block và kết quả scan ghi vào audit trail kỹ
thuật (structured JSON lines, không hiển thị trực tiếp cho người dùng); một bản tóm tắt
được lọc và diễn giải lại từ audit trail để hiển thị trên UI [S1].

## 4. Phụ thuộc giữa các thành phần

- Minifilter driver và ELAM driver **giao tiếp ngược lên service nền** qua filter
  communication port (`FltCreateCommunicationPort`), vì logic quét phức tạp (heuristic,
  YARA, tra CSDL hash) không nên và không thể chạy trong kernel — code kernel-mode lỗi
  gây blue screen ngay lập tức, nên kernel-mode được giữ càng mỏng càng tốt: chỉ chặn và
  hỏi, không tự quyết định [S1].
- Service nền **phụ thuộc vào scan engine** (gọi vào như một thư viện) cho cả luồng full
  scan lẫn real-time, và **phụ thuộc vào bảng rule SQLite** để tra quyền cho tiến trình
  mới trước khi trả quyết định về driver [S1].
- Scan engine **phụ thuộc vào CSDL signature** (Bloom filter + file sorted array) và vào
  `libyara` đã compile sẵn rule lúc khởi động; engine lúc chạy chỉ đọc CSDL, không bao
  giờ tự ghi vào CSDL [S1].
- Driver ELAM **phụ thuộc vào CSDL riêng đóng gói sẵn dạng resource nhúng** (tách biệt
  với CSDL đầy đủ của scan engine) vì tại thời điểm ELAM chạy, service nền chưa kịp khởi
  động [S1].
- Luồng giám sát Downloads **có thể tái sử dụng hạ tầng minifilter** (hook `IRP_MJ_CLEANUP`)
  nếu driver real-time protection đã tồn tại, thay vì polling từ user-mode [S1].
- Toàn bộ driver kernel-mode (ELAM, minifilter) và installer **phụ thuộc vào chứng chỉ
  ký số do Microsoft cấp** (EKU ELAM/Antimalware, EV Code Signing Certificate qua
  Microsoft Partner Center) — không có ngoại lệ cho self-signed certificate trên máy bật
  Secure Boot mặc định [S1].
- Việc app được Windows Security Center công nhận là AV provider **phụ thuộc vào việc
  tham gia chương trình Microsoft Virus Initiative (MVI)**, không có API công khai để tự
  đăng ký [S1].


## Nguồn tham chiếu
- S1 (final.md, chunk#1 Tổng quan kiến trúc app antivirus Windows)
- S1 (final.md, chunk#0 Tự Xây Antivirus Windows: Kiểm Quyền, Quét Sâu, Real-time)
- S1 (final.md, chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật)
- S1 (final.md, chunk#41 Kết luận)
- S1 (final.md, chunk#21 Kiến trúc Real-time Protection bằng minifilter driver)
- S1 (final.md, chunk#11 Engine giám sát tiến trình theo thời gian thực)
- S1 (final.md, chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*)
- S1 (final.md, chunk#14 Xây dựng cơ sở dữ liệu signature dựa trên hash)
- S1 (final.md, chunk#9 Giao diện tùy biến quyền cho ứng dụng bên thứ 3)
- S1 (final.md, chunk#39 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,)
- S1 (final.md, chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ)
- S1 (final.md, chunk#37 Logging và báo cáo cho người dùng)
- S1 (final.md, chunk#38 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#27 Giám sát riêng thư mục Downloads)
- S1 (final.md, chunk#10 Lưu trữ và quản lý rule phân quyền)
- S1 (final.md, chunk#16 Tích hợp YARA rules vào scan engine)
- S1 (final.md, chunk#25 Viết Early Launch Antimalware driver cơ bản)
