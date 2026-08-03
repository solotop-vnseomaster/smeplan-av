---
id: "luong-xu-ly"
kind: sequence-flow
title: "Luồng xử lý"
spec_version: "v1"
module: "luong-xu-ly"
created_at: "2026-08-01T15:57:14.084770+00:00"
sources:
  - { source_id: "S1", loc: "chunk#10 Lưu trữ và quản lý rule phân quyền", hash: "2eef23f72066b39840103d0f6b4062d1b7da7382f05a22662890b36504d838f9" }
  - { source_id: "S1", loc: "chunk#38 Đóng gói, ký số installer và checklist phát hành", hash: "60cfca34d7df11c73c83d6274602016ded4c89187fa0bb95f67bce7df25f722b" }
  - { source_id: "S1", loc: "chunk#12 Luồng xử lý khi một ứng dụng thực thi", hash: "21565980c6961104b59cc82412e55d2b9a3571deb663d93a41f6b4bc5f69a825" }
  - { source_id: "S1", loc: "chunk#27 Giám sát riêng thư mục Downloads", hash: "2c250a52583f3208242ad843aef00370be7ca79dbfbffe35b3fd4d92763dc4f0" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#39 Đóng gói, ký số installer và checklist phát hành", hash: "4237edd642b7c565dd067daad5463c98cbdac0dd3656d4aea610d1f9c301badf" }
  - { source_id: "S1", loc: "chunk#29 Cơ chế Quarantine cách ly file nghi ngờ", hash: "c0d0d265c33eefbe75d7d1c6ec0772dae67f0eeefa2112b992b52c7b021289ad" }
  - { source_id: "S1", loc: "chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ", hash: "80eee532e66bbb3dcf94905b34d298864ce356a9f5347704f9d66c9d38f3f976" }
  - { source_id: "S1", loc: "chunk#7 Giới hạn của whitelist theo chữ ký số", hash: "40ff3f848503ba100ca44a546f2f028712d34596abfe0cb201f97edc9ebd80a1" }
  - { source_id: "S1", loc: "chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa", hash: "bcf95a76fd630c410fa5205a4cb67cf644f19f86b3c5e705b59ccecbe07ef035" }
  - { source_id: "S1", loc: "chunk#18 Tối ưu hiệu năng khi quét sâu", hash: "6651987e1a5f94a302fefea430b892f7713846471fc366e723235c419fcf9f23" }
  - { source_id: "S1", loc: "chunk#1 Tổng quan kiến trúc app antivirus Windows", hash: "b142a39c6bc430bae5289b9f8ef71a468f7f5d0d7b27c4ceb33d86a64a77f17f" }
  - { source_id: "S1", loc: "chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường", hash: "e44c7e7f08017f68ab3e6a509472b314de4aa80c6e8173374d4bc431d09998bf" }
  - { source_id: "S1", loc: "chunk#37 Logging và báo cáo cho người dùng", hash: "538bc9459381222d16e8d5bf3c9692b1b3e9d087e2496b7d0f7dc738f0f90aad" }
  - { source_id: "S1", loc: "chunk#40 Những lỗi thường gặp khi tự xây antivirus", hash: "f337bd98c9a969567f2a3a2849d5f0d8c8aeb664fa08dd3143032ae6d671f345" }
  - { source_id: "S1", loc: "chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật", hash: "59cc3cbd79938b6365158b712f193e4f01658bfe18f760c6cf660ec23ef6811d" }
  - { source_id: "S1", loc: "chunk#41 Kết luận", hash: "3eec6601c076d2c8892032d28b2554d458259a89bb1b7db59f4c6a37b4d41d6a" }
  - { source_id: "S1", loc: "chunk#26 Ký số driver với Microsoft", hash: "86cf57e26ce6aa8219dd02178bb6368ecdabd98941ecb7feaeadd677ee519848" }
  - { source_id: "S1", loc: "chunk#33 Xử lý false positive với whitelist nhiều lớp", hash: "66ff8147f168732ddf02f1b46144a34efab0bd1641498b8c729cf35ca1995f9d" }
  - { source_id: "S1", loc: "chunk#25 Viết Early Launch Antimalware driver cơ bản", hash: "f41b68505282e58b734c1adc5e3581a2968329011499fedca868e830669419c2" }
---

# Luồng xử lý

## Mục lục
- [Luồng thực thi ứng dụng mới (kiểm soát tiến trình)](#luồng-thực-thi-ứng-dụng-mới-kiểm-soát-tiến-trình)
- [Luồng phát hiện & xử lý file tải về trong Downloads](#luồng-phát-hiện--xử-lý-file-tải-về-trong-downloads)
- [Luồng quét file trong scan engine](#luồng-quét-file-trong-scan-engine)
- [Luồng Full/Deep Scan toàn ổ đĩa](#luồng-fulldeep-scan-toàn-ổ-đĩa)
- [Luồng xử lý false positive với whitelist nhiều lớp](#luồng-xử-lý-false-positive-với-whitelist-nhiều-lớp)

### Luồng thực thi ứng dụng mới (kiểm soát tiến trình)

- Điều kiện tiên quyết: driver đã đăng ký callback `PsSetCreateProcessNotifyRoutineEx`;
  service nền đang chạy và có quyền truy cập bảng rule phân quyền [S1].
- Các bước:
  - Bước 1: {Hệ điều hành} -> {Driver}: một tiến trình mới được tạo; kernel gọi
    `PsSetCreateProcessNotifyRoutineEx` đồng bộ ngay tại thời điểm tạo, trước khi tiến
    trình thực thi dòng lệnh đầu tiên [S1].
  - Bước 2: {Driver} -> {Service nền}: gửi đường dẫn file và PID qua filter
    communication port [S1].
  - Bước 3: {Service nền} (nội bộ): tính SHA-256 của file, hoặc lấy từ cache nếu đã tính
    trước đó và file chưa đổi timestamp sửa đổi [S1].
  - Bước 4: {Service nền} -> {Bảng rule}: tra rule theo thứ tự hash rồi publisher.
    - Rẽ nhánh 4a: tìm thấy rule theo hash hoặc publisher → dùng `action` của rule đó,
      chuyển thẳng Bước 6 [S1].
    - Rẽ nhánh 4b: không tìm thấy rule nào và tiến trình không đạt tiêu chí
      trusted-by-default → sang Bước 5 [S1].
  - Bước 5: {Service nền} -> {Người dùng}: kích hoạt hộp thoại hỏi quyền, chờ phản hồi
    với timeout tối đa 30 giây.
    - Rẽ nhánh: người dùng chọn Cho phép luôn/Chỉ lần này/Chặn → dùng làm quyết định
      [S1].
    - Rẽ nhánh: hết timeout không có phản hồi → mặc định deny-and-log [S1].
  - Bước 6: {Service nền} -> {Driver}: trả quyết định cuối cùng (allow/block) [S1].
- Điều kiện kết thúc (happy path): driver nhận được quyết định trong giới hạn thời gian
  (dưới 50 mili giây cho trường hợp chỉ tra rule có sẵn), cho phép hoặc từ chối tiến
  trình chạy tiếp tương ứng [S1].
- Các nhánh lỗi/ngoại lệ: nếu service không phản hồi kịp timeout (rule tra cứu thông
  thường hoặc chờ người dùng), hành vi mặc định là deny-and-log, trừ khi tiến trình đã
  đạt điều kiện trusted-by-default ngay ở tầng driver mà không cần chờ service [S1].

### Luồng phát hiện & xử lý file tải về trong Downloads

- Điều kiện tiên quyết: service nền đã đăng ký `ReadDirectoryChangesW` trên thư mục
  Downloads thực tế của người dùng (lấy qua `SHGetKnownFolderPath`) [S1].
- Các bước:
  - Bước 1: {Trình duyệt/công cụ dòng lệnh} -> {Hệ thống file}: tạo file tạm
    (`.crdownload`/`.part`) trong lúc tải, sau đó rename bỏ đuôi tạm khi tải xong (trình
    duyệt); hoặc ghi thẳng tên file cuối cùng ngay từ đầu (công cụ dòng lệnh) [S1].
  - Bước 2: {Service nền} bắt sự kiện `FILE_ACTION_RENAMED_NEW_NAME` (trường hợp trình
    duyệt) hoặc `FILE_ACTION_ADDED` (trường hợp công cụ dòng lệnh); cả hai đều đưa file
    vào hàng đợi chờ thay vì quét ngay [S1].
  - Bước 3: {Service nền} -> {Hệ thống file}: xác nhận file đã ghi xong bằng polling
    `CreateFile` mở exclusive (chu kỳ ~200ms, timeout tổng 30 giây với file lớn), hoặc
    hook `IRP_MJ_CLEANUP` nếu đã có sẵn minifilter cho real-time protection.
    - Rẽ nhánh: mở thành công → file sẵn sàng, sang Bước 4 [S1].
    - Rẽ nhánh: `ERROR_SHARING_VIOLATION` → tiếp tục chờ, lặp lại Bước 3 [S1].
  - Bước 4: {Service nền} -> {Scan engine}: đưa file qua pipeline hash → YARA →
    heuristic, quét đồng bộ và đầy đủ, không bỏ qua theo phần mở rộng "ít rủi ro" như
    real-time protection thông thường [S1].
  - Bước 5: {Scan engine} -> {Service nền}: trả verdict.
    - Rẽ nhánh `Clean`: không làm gì thêm, để nguyên file cho người dùng dùng bình
      thường [S1].
    - Rẽ nhánh `Malicious`: tự động chuyển file vào quarantine ngay lập tức, hiển thị
      toast notification nêu rõ tên file và lý do [S1].
    - Rẽ nhánh `Suspicious`: không tự động di chuyển file, hiển thị cảnh báo kèm ba lựa
      chọn Xóa/Cách ly/Bỏ qua để người dùng tự quyết [S1].
- Điều kiện kết thúc (happy path): file được phân loại đúng verdict và người dùng nhận
  được thông báo/tùy chọn tương ứng [S1].
- Các nhánh lỗi/ngoại lệ: nếu file tiếp tục báo `ERROR_SHARING_VIOLATION` cho tới hết
  timeout tổng, hành vi tiếp theo TODO [UNKNOWN] — ngữ cảnh không nêu rõ.

### Luồng quét file trong scan engine

- Điều kiện tiên quyết: CSDL signature (Bloom filter + file sorted array) và rule YARA đã
  compile sẵn, sẵn sàng trong engine trước khi nhận yêu cầu quét [S1].
- Các bước:
  - Bước 1: {Service nền hoặc full-scan worker} -> {Scan engine}: gọi engine với một
    file handle hoặc buffer [S1].
  - Bước 2: {Scan engine} -> {CSDL signature}: tra hash SHA-256 trong CSDL cục bộ.
    - Rẽ nhánh: khớp mã độc đã biết → trả `Malicious` ngay, kết thúc pipeline [S1].
  - Bước 3 (nếu không khớp CSDL hash): {Scan engine} -> {Rule YARA}: chạy
    `yr_rules_scan_file`/`yr_rules_scan_mem`.
    - Rẽ nhánh: khớp rule với `severity` cao → trả `Malicious` ngay [S1].
    - Rẽ nhánh: khớp rule với `severity` thấp → cộng điểm vào heuristic score, sang
      Bước 4 [S1].
  - Bước 4 (nếu vẫn chưa kết luận): {Scan engine} chạy heuristic (entropy Shannon, tổ
    hợp API nhạy cảm trong IAT, entry point ngoài section), cộng vào một điểm số tổng
    (weighted score).
    - Rẽ nhánh: vượt ngưỡng điểm số tổng → trả `Suspicious` [S1].
    - Rẽ nhánh: không đọc được file (khóa hoặc hỏng) → trả `ScanError` [S1].
    - Rẽ nhánh: không phát hiện gì → trả `Clean` [S1].
- Điều kiện kết thúc (happy path): engine trả về đúng một trong bốn verdict
  `Clean`/`Malicious`/`Suspicious`/`ScanError` [S1].
- Các nhánh lỗi/ngoại lệ: file bị khóa hoặc hỏng dẫn tới `ScanError`, không được mặc
  định coi là `Clean` trong trường hợp này [S1].

### Luồng Full/Deep Scan toàn ổ đĩa

- Điều kiện tiên quyết: có quyền Administrator để mở volume (`\\.\C:`) [S1].
- Các bước:
  - Bước 1: {Người dùng/lịch quét} -> {Service nền}: yêu cầu chạy full scan.
  - Bước 2: {Service nền} -> {Hệ thống file}: kiểm tra file system type qua
    `GetVolumeInformation`.
    - Rẽ nhánh NTFS: mở `hVolume`, enumerate toàn bộ file qua `FSCTL_ENUM_USN_DATA`
      theo thứ tự Master File Table [S1].
    - Rẽ nhánh FAT32/exFAT (không hỗ trợ USN Journal): fallback duyệt cây thư mục thông
      thường bằng `FindFirstFile`/`FindNextFile` đệ quy [S1].
  - Bước 3: {Service nền} -> {Work queue}: đưa danh sách file vào hàng đợi công việc,
    chia cho một thread pool có kích thước giới hạn (số core vật lý trừ 1) [S1].
  - Bước 4: {Mỗi thread} -> {Scan engine}: gọi pipeline quét cho từng file (xem luồng
    "Luồng quét file trong scan engine") [S1].
  - Bước 5: {Service nền} áp dụng tối ưu hiệu năng song song: hạ mức ưu tiên I/O
    (`SetPriorityClass`/`FileIoPriorityHintInformation`), theo dõi thời gian rảnh người
    dùng qua `GetLastInputInfo` để giảm/tạm dừng số luồng song song, và trên HDD (kiểm
    tra qua `IOCTL_STORAGE_QUERY_PROPERTY`) sắp xếp lại thứ tự đọc theo LBA tăng dần và
    giảm số luồng song song xuống 1 [S1].
  - Bước 6 (tùy chọn): {Người dùng} -> {Service nền}: yêu cầu tạm dừng scan; service lưu
    `FileReferenceNumber` cuối cùng đã xử lý vào một file trạng thái nhỏ để tiếp tục sau
    mà không mất tiến độ [S1].
- Điều kiện kết thúc (happy path): toàn bộ file trên volume được đưa qua scan engine và
  xử lý theo verdict tương ứng [S1].
- Các nhánh lỗi/ngoại lệ: bỏ qua tối ưu hiệu năng theo loại ổ đĩa (đặc biệt trên HDD) có
  thể khiến máy người dùng bị treo hoặc giật lag nghiêm trọng trong thực tế [S1]; nếu
  không lưu tiến độ khi tạm dừng, lần chạy tiếp theo phải quét lại từ đầu [S1].

### Luồng xử lý false positive với whitelist nhiều lớp

- Điều kiện tiên quyết: rule heuristic/YARA mới đã được viết; hệ thống có sẵn tập file
  sạch đa dạng dùng để đo false positive [S1].
- Các bước:
  - Bước 1: {Đội phát triển} -> {Hệ thống}: triển khai rule mới ở chế độ log-only —
    rule chạy trên mọi file được quét, kết quả khớp được ghi log kèm hash và đường dẫn,
    không kích hoạt hành động chặn/quarantine, chạy tối thiểu vài ngày trên tập file
    sạch [S1].
  - Bước 2: {Hệ thống} đo tỷ lệ match trên tập sạch.
    - Rẽ nhánh: tỷ lệ bằng không hoặc thấp tới mức chấp nhận được → chuyển rule sang chế
      độ enforce thật cho người dùng [S1].
    - Rẽ nhánh: tỷ lệ chưa chấp nhận được → giữ ở log-only; bước tinh chỉnh tiếp theo
      TODO [UNKNOWN].
  - Bước 3 (sau khi enforce): {Rule đã enforce} gắn cờ nhầm một file hợp lệ (false
    positive vẫn có thể xảy ra dù đã qua log-only) [S1].
  - Bước 4: {Người dùng} -> {Cơ chế quarantine}: khôi phục file từ quarantine về đúng vị
    trí gốc bằng metadata đã lưu [S1].
  - Bước 5: {Người dùng/Đội phát triển} -> {Bảng rule}: thêm ngoại lệ whitelist theo
    đúng `scope` — theo `hash` cho file tĩnh ít thay đổi, theo `publisher` thumbprint
    (kể cả self-signed nội bộ) cho phần mềm được build liên tục vì mỗi lần build ra hash
    khác nhau [S1].
  - Bước 6: {Hệ thống} ghi lại ngoại lệ cùng với rule/signature nào đã gây false
    positive vào một danh sách nội bộ để review định kỳ [S1].
- Điều kiện kết thúc (happy path): file được khôi phục đúng vị trí gốc, không bị gắn cờ
  lại ở lần quét sau nhờ ngoại lệ whitelist đúng scope [S1].
- Các nhánh lỗi/ngoại lệ: whitelist theo `hash` vô tác dụng ngay từ lần build tiếp theo
  đối với phần mềm được build liên tục (hash đổi dù mã nguồn không đổi bản chất), buộc
  phải dùng lớp whitelist theo `publisher` thumbprint thay thế [S1].


## Nguồn tham chiếu
- S1 (final.md, chunk#10 Lưu trữ và quản lý rule phân quyền)
- S1 (final.md, chunk#38 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#12 Luồng xử lý khi một ứng dụng thực thi)
- S1 (final.md, chunk#27 Giám sát riêng thư mục Downloads)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#39 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#29 Cơ chế Quarantine cách ly file nghi ngờ)
- S1 (final.md, chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ)
- S1 (final.md, chunk#7 Giới hạn của whitelist theo chữ ký số)
- S1 (final.md, chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa)
- S1 (final.md, chunk#18 Tối ưu hiệu năng khi quét sâu)
- S1 (final.md, chunk#1 Tổng quan kiến trúc app antivirus Windows)
- S1 (final.md, chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường)
- S1 (final.md, chunk#37 Logging và báo cáo cho người dùng)
- S1 (final.md, chunk#40 Những lỗi thường gặp khi tự xây antivirus)
- S1 (final.md, chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật)
- S1 (final.md, chunk#41 Kết luận)
- S1 (final.md, chunk#26 Ký số driver với Microsoft)
- S1 (final.md, chunk#33 Xử lý false positive với whitelist nhiều lớp)
- S1 (final.md, chunk#25 Viết Early Launch Antimalware driver cơ bản)
