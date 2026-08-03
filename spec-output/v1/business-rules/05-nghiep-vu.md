---
id: "nghiep-vu"
kind: business-rules
title: "Business Rules"
spec_version: "v1"
module: "nghiep-vu"
created_at: "2026-08-01T15:47:36.427733+00:00"
sources:
  - { source_id: "S1", loc: "chunk#37 Logging và báo cáo cho người dùng", hash: "538bc9459381222d16e8d5bf3c9692b1b3e9d087e2496b7d0f7dc738f0f90aad" }
  - { source_id: "S1", loc: "chunk#35 Chống tắt ứng dụng bằng Protected Process Light", hash: "5b39fd5afef125607e87d665e0ec31d3a49dba81ea26201afa8beb89f69eb646" }
  - { source_id: "S1", loc: "chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường", hash: "e44c7e7f08017f68ab3e6a509472b314de4aa80c6e8173374d4bc431d09998bf" }
  - { source_id: "S1", loc: "chunk#10 Lưu trữ và quản lý rule phân quyền", hash: "2eef23f72066b39840103d0f6b4062d1b7da7382f05a22662890b36504d838f9" }
  - { source_id: "S1", loc: "chunk#1 Tổng quan kiến trúc app antivirus Windows", hash: "b142a39c6bc430bae5289b9f8ef71a468f7f5d0d7b27c4ceb33d86a64a77f17f" }
  - { source_id: "S1", loc: "chunk#12 Luồng xử lý khi một ứng dụng thực thi", hash: "21565980c6961104b59cc82412e55d2b9a3571deb663d93a41f6b4bc5f69a825" }
  - { source_id: "S1", loc: "chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,", hash: "17f42d943690edcd37b9aa9205d8c5380cfe386671ef09c88769ba359d78cec5" }
  - { source_id: "S1", loc: "chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa", hash: "bcf95a76fd630c410fa5205a4cb67cf644f19f86b3c5e705b59ccecbe07ef035" }
  - { source_id: "S1", loc: "chunk#39 Đóng gói, ký số installer và checklist phát hành", hash: "4237edd642b7c565dd067daad5463c98cbdac0dd3656d4aea610d1f9c301badf" }
  - { source_id: "S1", loc: "chunk#4 Thiết lập môi trường phát triển", hash: "beaf2b68b93b9f502335ca2eca154631972f52fddf86d0463ff3633378aa4d1b" }
  - { source_id: "S1", loc: "chunk#16 Tích hợp YARA rules vào scan engine", hash: "09f3633e6e1995108b8c8a01daa26dd7a383faf54cee9139abed99d3278ad6b4" }
  - { source_id: "S1", loc: "chunk#8 Thiết kế chính sách kiểm soát ứng dụng bằng AppLocker/WDAC", hash: "d5236d1041a2aeab5679f1aa092a0a979342c01c9e86f60b1f7302bc8dbde2fa" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#20 Quét trong file nén và chống zip bomb", hash: "aa9d8cd228951c99653ecd1a0a1b66809ce11fa26129f5c42ac1a03a04812df6" }
  - { source_id: "S1", loc: "chunk#6 Kiểm tra chữ ký số Authenticode để whitelist mặc định", hash: "cce87f8a3c8cd1398b9083926e9a18d87ec17594835fcb6ba821adcc3f787d01" }
  - { source_id: "S1", loc: "chunk#19 Quét trong file nén và chống zip bomb", hash: "72554f74c77e4383627c539208132779f6fd51651765a6d7e926ca3e4cb9b83a" }
  - { source_id: "S1", loc: "chunk#38 Đóng gói, ký số installer và checklist phát hành", hash: "60cfca34d7df11c73c83d6274602016ded4c89187fa0bb95f67bce7df25f722b" }
  - { source_id: "S1", loc: "chunk#7 Giới hạn của whitelist theo chữ ký số", hash: "40ff3f848503ba100ca44a546f2f028712d34596abfe0cb201f97edc9ebd80a1" }
  - { source_id: "S1", loc: "chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật", hash: "738f35b68d00a2f40c9d8bee712457df7a70bd4107526f29106a9b8ede50cf74" }
  - { source_id: "S1", loc: "chunk#33 Xử lý false positive với whitelist nhiều lớp", hash: "66ff8147f168732ddf02f1b46144a34efab0bd1641498b8c729cf35ca1995f9d" }
---

# Business Rules

## Mục lục
- [Quyết định cấp quyền cho tiến trình mới (Process Trust Decision)](#quyết-định-cấp-quyền-cho-tiến-trình-mới-process-trust-decision)
- [Kết quả quét file (Scan Verdict)](#kết-quả-quét-file-scan-verdict)
- [File trong Quarantine](#file-trong-quarantine)
- [Rule heuristic/YARA (Log-only → Enforce)](#rule-heuristicyara-log-only--enforce)

### Quyết định cấp quyền cho tiến trình mới (Process Trust Decision)

- Sơ đồ trạng thái (state machine): `Unknown`, `TrustedByDefault`, `RuleAllow`,
  `RuleBlock`, `PendingUserDecision`, `AllowedAlways`, `AllowedOnce`, `Blocked`,
  `DeniedByTimeout` [S1]
- Chuyển trạng thái hợp lệ:
  - `Unknown -> TrustedByDefault` (tiến trình đạt đủ ba tiêu chí trusted-by-default:
    chữ ký số Authenticode hợp lệ + publisher khớp Microsoft + vị trí thư mục được WRP
    bảo vệ) [S1]
  - `Unknown -> RuleAllow` (service tra được rule theo hash hoặc theo publisher với
    `action = allow`, ưu tiên tra theo hash trước, publisher sau) [S1]
  - `Unknown -> RuleBlock` (tra được rule với `action = block`) [S1]
  - `Unknown -> PendingUserDecision` (không đạt trusted-by-default và không tìm thấy
    rule nào theo hash lẫn publisher) [S1]
  - `PendingUserDecision -> AllowedAlways` (người dùng chọn "Cho phép luôn", lưu rule
    vĩnh viễn vào bảng rule) [S1]
  - `PendingUserDecision -> AllowedOnce` (người dùng chọn "Chỉ lần này", không lưu rule,
    hỏi lại lần sau) [S1]
  - `PendingUserDecision -> Blocked` (người dùng chọn "Chặn") [S1]
  - `PendingUserDecision -> DeniedByTimeout` (hết thời gian chờ tối đa, ví dụ 30 giây,
    không có phản hồi từ người dùng) [S1]
  - KHÔNG được phép: `TrustedByDefault -> loại trừ hoàn toàn khỏi giám sát` — tiến trình
    đã whitelist vẫn phải nằm trong phạm vi giám sát hành vi bất thường ở mức độ nhẹ hơn,
    không được loại trừ hoàn toàn khỏi mọi kiểm tra [S1]
  - KHÔNG được phép: tra rule thông thường mà hết timeout không phản hồi rồi mặc định
    `Allowed` — hành vi mặc định khi timeout phải là deny-and-log (an toàn hơn allow mù),
    trừ khi tiến trình đã đạt điều kiện `TrustedByDefault` ngay ở tầng driver mà không
    cần chờ service [S1]
- Bảng phân quyền (vai trò × hành động):
  | Vai trò | Hành động được phép |
  |---|---|
  | Driver (kernel-mode) | Gửi thông tin tiến trình mới xuống service; tự cho qua ngay không cần chờ service nếu tiến trình đã đạt `TrustedByDefault` ở tầng driver; nếu không, giữ IRP chờ quyết định từ service [S1] |
  | Service nền (SYSTEM) | Tính hash, tra bảng rule theo thứ tự hash rồi publisher, tự quyết định `RuleAllow`/`RuleBlock`/`TrustedByDefault` mà không cần hỏi người dùng; kích hoạt hộp thoại hỏi người dùng khi không có rule nào [S1] |
  | Người dùng | Chỉ được quyết định khi ở trạng thái `PendingUserDecision`, chọn một trong ba: Cho phép luôn/Chỉ lần này/Chặn [S1] |
- Quy tắc validate nghiệp vụ: toàn bộ chuỗi tra cứu và quyết định phải hoàn tất trong
  thời gian có giới hạn trên rõ ràng vì driver đang giữ tiến trình ở trạng thái chờ — ví
  dụ dưới 50 mili giây cho trường hợp chỉ tra rule có sẵn, tối đa 30 giây cho trường hợp
  cần hỏi người dùng [S1]. Whitelist theo chữ ký số chỉ được dùng để quyết định có cần
  hỏi quyền hay không, không được dùng làm căn cứ duy nhất để loại trừ tiến trình khỏi
  việc quét real-time [S1].
- Domain invariant: tên file hoặc đường dẫn không bao giờ được dùng làm căn cứ chính để
  coi một tiến trình là "app Windows gốc" [S1]. Hộp thoại xin quyền luôn do service nền
  (SYSTEM), tách biệt hoàn toàn với tiến trình đang xin quyền, khởi tạo — không bao giờ
  do chính tiến trình đang bị đánh giá hiển thị [S1].

### Kết quả quét file (Scan Verdict)

- Sơ đồ trạng thái (state machine): `Clean`, `Malicious`, `Suspicious`, `ScanError` [S1]
- Chuyển trạng thái hợp lệ:
  - `(đang quét) -> Clean` — đã quét, không phát hiện gì qua cả ba bước hash/YARA/
    heuristic [S1]
  - `(đang quét) -> Malicious` — khớp CSDL hash, hoặc khớp rule YARA có `severity` đủ
    cao để tự kết luận ngay [S1]
  - `(đang quét) -> Suspicious` — rule YARA severity thấp hoặc heuristic vượt một
    ngưỡng điểm số tổng (weighted score), hoặc vượt giới hạn chống zip bomb (tỷ lệ nén,
    độ sâu lồng nhau, trần dung lượng giải nén) [S1]
  - `(đang quét) -> ScanError` — không đọc được file, ví dụ file bị khóa hoặc hỏng [S1]
  - `Malicious -> Quarantined` (tự động, xem nghiệp vụ Quarantine) [S1]
  - `Suspicious -> (người dùng chọn Xóa/Cách ly/Bỏ qua)` — riêng với file tải về từ
    Downloads [S1]
  - KHÔNG được phép: `ScanError -> Clean` — không được mặc định coi `ScanError` là
    `Clean` khi gặp lỗi đọc file [S1]
  - KHÔNG được phép: `Suspicious -> Xóa vĩnh viễn ngay lập tức` — xử lý `Suspicious`
    giống hệt `Malicious` (xóa ngay, không cho khôi phục) là lỗi vì heuristic/YARA luôn
    có tỷ lệ false positive khác không [S1]
- Bảng phân quyền (vai trò × hành động):
  | Vai trò | Hành động được phép |
  |---|---|
  | Scan engine | Tự động quyết định verdict qua pipeline hash → YARA → heuristic, dừng ngay khi có kết luận đủ chắc chắn [S1] |
  | Service nền | Thực hiện hành động tương ứng verdict: tự động quarantine khi `Malicious`, hiển thị cảnh báo khi `Suspicious` [S1] |
  | Người dùng | Với file tải về ở trạng thái `Suspicious`, tự chọn Xóa/Cách ly/Bỏ qua vì mức độ chắc chắn của heuristic không đủ để hệ thống tự hành động [S1] |
- Quy tắc validate nghiệp vụ: pipeline chạy theo thứ tự tăng dần chi phí tính toán (hash
  → YARA → heuristic), dừng lại ngay khi có kết luận đủ chắc chắn, không luôn chạy hết
  mọi bước [S1]. Mỗi rule heuristic khớp chỉ cộng vào điểm số tổng, không tự động kết
  luận `Malicious` chỉ từ một rule đơn lẻ [S1]. Mọi rule heuristic/YARA mới phải qua giai
  đoạn log-only trước khi được phép enforce (xem nghiệp vụ Rule heuristic/YARA) [S1].
- Domain invariant: `Suspicious` phải luôn tách biệt khỏi `Malicious` ngay từ interface
  của scan engine, không gộp chung rồi phân loại lại ở tầng gọi, vì điều này quyết định
  trực tiếp cách luồng quarantine và luồng xử lý false positive vận hành [S1].

### File trong Quarantine

- Sơ đồ trạng thái (state machine): `Active` (chưa đánh giá/nằm trên đĩa), `Malicious`,
  `PendingManualConfirmation`, `Quarantined`, `Restored` [S1]
- Chuyển trạng thái hợp lệ:
  - `Malicious -> Quarantined` (tự động, khi file không nằm trong thư mục hệ thống được
    bảo vệ) — đổi tên thành định danh không mang phần mở rộng gốc (ví dụ GUID) và mã hóa
    nội dung trước khi di chuyển [S1]
  - `Malicious -> PendingManualConfirmation` (khi file nằm trong thư mục hệ thống được
    Windows Resource Protection bảo vệ) — không tự động quarantine ngay cả khi engine
    kết luận `Malicious` [S1]
  - `PendingManualConfirmation -> Quarantined` (chỉ sau khi người dùng xác nhận thủ
    công) [S1]
  - `Quarantined -> Restored` (người dùng xác nhận đây là false positive qua giao diện
    chính của app, khôi phục chính xác về vị trí gốc bằng metadata đã lưu) [S1]
  - KHÔNG được phép: `Malicious -> Xóa vĩnh viễn` — không xóa file `Malicious` ngay lập
    tức, luôn di chuyển vào khu vực cách ly trước vì mọi engine phát hiện đều có tỷ lệ
    false positive khác không [S1]
  - KHÔNG được phép: `Quarantined -> Restored` qua thao tác file thông thường trong
    Explorer — thao tác khôi phục chỉ được khả dụng qua giao diện chính của app, yêu cầu
    xác nhận rõ ràng [S1]
- Bảng phân quyền (vai trò × hành động):
  | Vai trò | Hành động được phép |
  |---|---|
  | SYSTEM (qua ACL thư mục quarantine) | Duy nhất có quyền đọc/ghi khu vực quarantine [S1] |
  | Người dùng thường | Không thể tự mở file trong quarantine bằng Explorer [S1] |
  | Người dùng (qua giao diện chính) | Xác nhận khôi phục file khỏi quarantine khi tin đây là false positive; xác nhận quarantine thủ công cho file hệ thống bị gắn cờ [S1] |
- Quy tắc validate nghiệp vụ: file khi chuyển vào quarantine phải qua hai bước biến đổi
  bắt buộc — đổi tên thành định danh không mang phần mở rộng gốc, và mã hóa nội dung
  bằng một khóa đơn giản để ngăn thực thi/đọc tình cờ [S1]. Metadata quarantine
  (`QuarantineRecord`) phải đủ để khôi phục chính xác file về đúng vị trí gốc [S1].
- Domain invariant: rủi ro gỡ nhầm một file hệ thống quan trọng luôn được coi là nghiêm
  trọng hơn việc chậm vài giây phản ứng với một phát hiện có thể đúng — vì vậy file nằm
  trong thư mục hệ thống bảo vệ không bao giờ được tự động quarantine [S1].

### Rule heuristic/YARA (Log-only → Enforce)

- Sơ đồ trạng thái (state machine): `LogOnly`, `Enforce` [S1]
- Chuyển trạng thái hợp lệ:
  - `LogOnly -> Enforce` (chỉ khi tỷ lệ match của rule trên tập file sạch bằng không
    hoặc thấp tới mức chấp nhận được, sau khi đã chạy tối thiểu vài ngày ở chế độ
    log-only) [S1]
  - KHÔNG được phép: `(rule mới) -> Enforce` trực tiếp mà bỏ qua giai đoạn `LogOnly` —
    checklist phát hành yêu cầu "không còn rule nào mới chưa đo tỷ lệ false positive"
    trước khi ship [S1]
- Bảng phân quyền (vai trò × hành động): TODO [UNKNOWN] — ngữ cảnh không nêu rõ vai trò
  cụ thể (ví dụ đội phát triển hay một cấu hình tự động) là bên quyết định chuyển rule từ
  `LogOnly` sang `Enforce`
- Quy tắc validate nghiệp vụ: ở trạng thái `LogOnly`, rule vẫn chạy trên mọi file được
  quét, kết quả khớp được ghi log kèm hash và đường dẫn nhưng không kích hoạt hành động
  chặn/quarantine nào [S1]. Sau khi enforce, nếu false positive vẫn xảy ra, quy trình
  khôi phục gồm hai bước tách biệt: khôi phục file từ quarantine, và thêm ngoại lệ theo
  đúng `scope` phù hợp — `hash` cho file tĩnh ít thay đổi, `publisher` (theo certificate
  thumbprint, kể cả self-signed nội bộ) cho phần mềm được build liên tục vì mỗi lần build
  ra hash khác nhau [S1]. Mỗi lần người dùng thêm ngoại lệ thủ công, cần ghi lại cùng
  rule/signature nào đã gây false positive để review định kỳ [S1].
- Domain invariant: một rule heuristic/YARA mới không bao giờ được coi là sẵn sàng
  enforce chỉ vì đã viết xong về mặt logic; điều kiện duy nhất để chuyển sang enforce là
  đã đo được tỷ lệ false positive thực tế trên tập dữ liệu sạch [S1].


## Nguồn tham chiếu
- S1 (final.md, chunk#37 Logging và báo cáo cho người dùng)
- S1 (final.md, chunk#35 Chống tắt ứng dụng bằng Protected Process Light)
- S1 (final.md, chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường)
- S1 (final.md, chunk#10 Lưu trữ và quản lý rule phân quyền)
- S1 (final.md, chunk#1 Tổng quan kiến trúc app antivirus Windows)
- S1 (final.md, chunk#12 Luồng xử lý khi một ứng dụng thực thi)
- S1 (final.md, chunk#36 PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,)
- S1 (final.md, chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa)
- S1 (final.md, chunk#39 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#4 Thiết lập môi trường phát triển)
- S1 (final.md, chunk#16 Tích hợp YARA rules vào scan engine)
- S1 (final.md, chunk#8 Thiết kế chính sách kiểm soát ứng dụng bằng AppLocker/WDAC)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#20 Quét trong file nén và chống zip bomb)
- S1 (final.md, chunk#6 Kiểm tra chữ ký số Authenticode để whitelist mặc định)
- S1 (final.md, chunk#19 Quét trong file nén và chống zip bomb)
- S1 (final.md, chunk#38 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#7 Giới hạn của whitelist theo chữ ký số)
- S1 (final.md, chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật)
- S1 (final.md, chunk#33 Xử lý false positive với whitelist nhiều lớp)
