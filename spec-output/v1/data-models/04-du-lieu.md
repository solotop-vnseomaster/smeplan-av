---
id: "du-lieu"
kind: data-model
title: "Dữ liệu"
spec_version: "v1"
module: "du-lieu"
created_at: "2026-08-01T15:45:40.786018+00:00"
sources:
  - { source_id: "S1", loc: "chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,", hash: "17f42d943690edcd37b9aa9205d8c5380cfe386671ef09c88769ba359d78cec5" }
  - { source_id: "S1", loc: "chunk#10 Lưu trữ và quản lý rule phân quyền", hash: "2eef23f72066b39840103d0f6b4062d1b7da7382f05a22662890b36504d838f9" }
  - { source_id: "S1", loc: "chunk#24 Giảm độ trễ khi quét theo thời gian thực", hash: "c95bc499a4f1bea0c0989dab031faddacda3d388d59691bca876214cf8810ac0" }
  - { source_id: "S1", loc: "chunk#14 Xây dựng cơ sở dữ liệu signature dựa trên hash", hash: "8de40e7324bdcaa66f177c8e534b2f37953c2d4ca49074643ede798407cddead" }
  - { source_id: "S1", loc: "chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa", hash: "bcf95a76fd630c410fa5205a4cb67cf644f19f86b3c5e705b59ccecbe07ef035" }
  - { source_id: "S1", loc: "chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", hash: "4f3ee047f0e2b9eff547e6871b1da177a8c0f97319d67e1f99089eb8b83d305c" }
  - { source_id: "S1", loc: "chunk#11 Engine giám sát tiến trình theo thời gian thực", hash: "3362274f397f853363dbd50458567edaa7502b4cb582fb56b36a7a697dbaffb2" }
  - { source_id: "S1", loc: "chunk#39 Đóng gói, ký số installer và checklist phát hành", hash: "4237edd642b7c565dd067daad5463c98cbdac0dd3656d4aea610d1f9c301badf" }
  - { source_id: "S1", loc: "chunk#38 Đóng gói, ký số installer và checklist phát hành", hash: "60cfca34d7df11c73c83d6274602016ded4c89187fa0bb95f67bce7df25f722b" }
  - { source_id: "S1", loc: "chunk#30 Cập nhật cơ sở dữ liệu virus tự động", hash: "50e50f2343f3f260ae921b918770fb538289ed51bf6ecb9d4f2f5465cdd3ba87" }
  - { source_id: "S1", loc: "chunk#29 Cơ chế Quarantine cách ly file nghi ngờ", hash: "c0d0d265c33eefbe75d7d1c6ec0772dae67f0eeefa2112b992b52c7b021289ad" }
  - { source_id: "S1", loc: "chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ", hash: "80eee532e66bbb3dcf94905b34d298864ce356a9f5347704f9d66c9d38f3f976" }
  - { source_id: "S1", loc: "chunk#37 Logging và báo cáo cho người dùng", hash: "538bc9459381222d16e8d5bf3c9692b1b3e9d087e2496b7d0f7dc738f0f90aad" }
  - { source_id: "S1", loc: "chunk#25 Viết Early Launch Antimalware driver cơ bản", hash: "f41b68505282e58b734c1adc5e3581a2968329011499fedca868e830669419c2" }
  - { source_id: "S1", loc: "chunk#12 Luồng xử lý khi một ứng dụng thực thi", hash: "21565980c6961104b59cc82412e55d2b9a3571deb663d93a41f6b4bc5f69a825" }
  - { source_id: "S1", loc: "chunk#16 Tích hợp YARA rules vào scan engine", hash: "09f3633e6e1995108b8c8a01daa26dd7a383faf54cee9139abed99d3278ad6b4" }
  - { source_id: "S1", loc: "chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật", hash: "59cc3cbd79938b6365158b712f193e4f01658bfe18f760c6cf660ec23ef6811d" }
  - { source_id: "S1", loc: "chunk#33 Xử lý false positive với whitelist nhiều lớp", hash: "66ff8147f168732ddf02f1b46144a34efab0bd1641498b8c729cf35ca1995f9d" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#26 Ký số driver với Microsoft", hash: "86cf57e26ce6aa8219dd02178bb6368ecdabd98941ecb7feaeadd677ee519848" }
---

# Dữ liệu

## Mục lục
- [app_rules](#app_rules)
- [QuarantineRecord](#quarantinerecord)
- [SignatureRecord](#signaturerecord)

### app_rules

Bảng rule phân quyền, lưu trong file SQLite cục bộ đặt trong thư mục dữ liệu được ACL
bảo vệ chỉ cho SYSTEM và Administrator ghi được [S1].

- Danh sách trường:
  - `id`: INTEGER, khóa chính, AUTOINCREMENT [S1]
  - `sha256_hash`: TEXT, NOT NULL [S1]
  - `publisher_thumbprint`: TEXT, NULL cho phép — NULL nếu file không ký số [S1]
  - `file_path`: TEXT, NOT NULL [S1]
  - `action`: TEXT, NOT NULL, ràng buộc CHECK giá trị trong (`allow`, `block`) [S1]
  - `scope`: TEXT, NOT NULL, ràng buộc CHECK giá trị trong (`hash`, `publisher`) — phân
    biệt rule áp dụng theo đúng hash file cụ thể hay theo mọi file cùng publisher
    certificate thumbprint [S1]
  - `created_at`: INTEGER, NOT NULL [S1]
  - `created_by`: TEXT, NOT NULL — giá trị `user` hoặc `default_policy` [S1]
- Khóa chính: `id` (INTEGER PRIMARY KEY AUTOINCREMENT) [S1]
- Khóa ngoại: TODO [UNKNOWN] — ngữ cảnh không nêu bảng này tham chiếu bảng nào khác
- Index: `idx_rules_hash` trên `sha256_hash`, `idx_rules_publisher` trên
  `publisher_thumbprint` — phục vụ thứ tự tra cứu ưu tiên hash trước, publisher sau khi
  service nền tra quyền cho tiến trình mới [S1]
- Unique constraint: TODO [UNKNOWN] — schema được nêu không khai báo ràng buộc UNIQUE
  tường minh trên `sha256_hash` hay `publisher_thumbprint`
- Soft delete/versioning: TODO [UNKNOWN]
- Ghi chú migration (nếu có thay đổi so với bản trước): TODO [UNKNOWN] — cột `scope`
  được thiết kế để dùng lại nguyên vẹn cho whitelist xử lý false positive của heuristic
  engine sau này, tránh phải tạo thêm bảng riêng [S1]

### QuarantineRecord

Metadata cho file đã bị cách ly (quarantine), lưu song song trong một bảng SQLite riêng,
không chung bảng với `app_rules` [S1].

- Danh sách trường:
  - `quarantine_id`: GUID [S1]
  - `original_path`: string — đường dẫn gốc, cần cho việc khôi phục [S1]
  - `original_filename`: string [S1]
  - `sha256_hash`: string [S1]
  - `detection_reason`: string — rule/signature nào đã gắn cờ [S1]
  - `quarantined_at`: timestamp [S1]
  - `file_size`: uint64 [S1]
  - Bắt buộc/NULL và giá trị mặc định cho từng trường: TODO [UNKNOWN]
- Khóa chính: `quarantine_id` (GUID dùng làm định danh bản ghi) [S1]
- Khóa ngoại: TODO [UNKNOWN]
- Index: TODO [UNKNOWN]
- Unique constraint: TODO [UNKNOWN]
- Soft delete/versioning: không có cơ chế xóa cứng được nêu; bản ghi tồn tại để hỗ trợ
  khôi phục chính xác file về đúng vị trí gốc khi người dùng xác nhận false positive, qua
  giao diện chính của app, không qua thao tác file thông thường trong Explorer [S1]. Cơ
  chế xóa bản ghi sau khi khôi phục (hoặc giữ lại làm lịch sử): TODO [UNKNOWN]
- Ghi chú migration (nếu có thay đổi so với bản trước): TODO [UNKNOWN]

### SignatureRecord

Bản ghi signature mã độc trong CSDL trên đĩa, dạng mảng bản ghi độ dài cố định để hỗ trợ
binary search trực tiếp trên file đã memory-map, không cần load toàn bộ vào bộ nhớ [S1].
Engine lúc chạy chỉ đọc CSDL này, không bao giờ tự ghi vào [S1].

- Danh sách trường:
  - `sha256`: uint8_t[32] — hash của mẫu mã độc [S1]
  - `threat_id`: uint32_t — ID tham chiếu tên/họ mã độc [S1]
  - `severity`: uint8_t, giá trị 0-255 — mức độ nguy hiểm [S1]
  - `reserved`: uint32_t [S1]
  - Bắt buộc/NULL và giá trị mặc định cho từng trường: TODO [UNKNOWN] (đây là struct
    nhị phân có độ dài cố định, không phải bảng quan hệ có ràng buộc NULL/NOT NULL)
- Khóa chính: `sha256` theo nghĩa mảng được sắp xếp tăng dần theo trường này để binary
  search O(log n) [S1]
- Khóa ngoại: TODO [UNKNOWN]
- Index: một Bloom filter nạp toàn bộ vào RAM lọc trước câu hỏi "hash này chắc chắn
  không có trong CSDL" (false positive rất thấp, có thể cấu hình, ví dụ 0.1%) trước khi
  tra vào mảng `SignatureRecord` trên đĩa [S1]; bản thân mảng trên đĩa được sắp xếp theo
  `sha256` tăng dần để hỗ trợ binary search trực tiếp trên vùng nhớ đã
  `CreateFileMapping`/`MapViewOfFile` [S1]
- Unique constraint: TODO [UNKNOWN]
- Soft delete/versioning: TODO [UNKNOWN] — việc build lại Bloom filter và mảng sorted
  này là công việc của service cập nhật CSDL chạy định kỳ (xem tài liệu Triển khai/API
  về cập nhật CSDL) [S1]
- Ghi chú migration (nếu có thay đổi so với bản trước): TODO [UNKNOWN]


## Nguồn tham chiếu
- S1 (final.md, chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,)
- S1 (final.md, chunk#10 Lưu trữ và quản lý rule phân quyền)
- S1 (final.md, chunk#24 Giảm độ trễ khi quét theo thời gian thực)
- S1 (final.md, chunk#14 Xây dựng cơ sở dữ liệu signature dựa trên hash)
- S1 (final.md, chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa)
- S1 (final.md, chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*)
- S1 (final.md, chunk#11 Engine giám sát tiến trình theo thời gian thực)
- S1 (final.md, chunk#39 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#38 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#30 Cập nhật cơ sở dữ liệu virus tự động)
- S1 (final.md, chunk#29 Cơ chế Quarantine cách ly file nghi ngờ)
- S1 (final.md, chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ)
- S1 (final.md, chunk#37 Logging và báo cáo cho người dùng)
- S1 (final.md, chunk#25 Viết Early Launch Antimalware driver cơ bản)
- S1 (final.md, chunk#12 Luồng xử lý khi một ứng dụng thực thi)
- S1 (final.md, chunk#16 Tích hợp YARA rules vào scan engine)
- S1 (final.md, chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật)
- S1 (final.md, chunk#33 Xử lý false positive với whitelist nhiều lớp)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#26 Ký số driver với Microsoft)
