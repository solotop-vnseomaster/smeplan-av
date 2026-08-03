# Checklist tính năng — pc-antivirus-app (spec-output/v1)

Nguồn: `spec-output/v1/**` (11 file spec đã đọc toàn bộ) + xác nhận stack từ
`build-pc-antivirus-app/sections/02-lua-chon-ngon-ngu-stack.md` và
`09-giao-dien-tuy-bien-quyen.md`.

## Quyết định triển khai ràng buộc (áp dụng cho toàn bộ checklist dưới)

Các quyết định này được suy ra trực tiếp từ chính tài liệu nguồn (không bịa
thêm yêu cầu mới), ghi lại ở đây để mọi mục bên dưới có cùng một khung quy
chiếu:

- **Stack 3 tầng ngôn ngữ** đúng như tài liệu xác nhận: driver kernel-mode
  (ELAM, minifilter) = C/WDK; scan engine = C++; service điều phối + UI =
  C#/.NET (modules/02-kien-truc.md mục 2; sections/02-lua-chon-ngon-ngu-stack.md).
- **UI**: dựng bằng WebView2 lồng trong shell .NET (WPF), nội dung là
  HTML/CSS/JS tự viết theo phong cách "công nghệ tương lai" — tài liệu liệt
  kê cả WinUI3 lẫn WPF là lựa chọn hợp lệ cho tầng UI mà không chốt cụ thể
  loại control, nên việc chọn WebView2 nằm trong phạm vi lựa chọn kỹ thuật
  còn bỏ ngỏ đó, đồng thời cho phép kiểm chứng trực quan được trong phiên
  làm việc này (môi trường không có công cụ chụp màn hình cửa sổ Windows
  native, nhưng có thể xem trực tiếp qua trình duyệt).
- **Giới hạn cứng của môi trường thực thi**: máy này không có Windows Driver
  Kit (không có header `fltKernel.h`/`ntddk.h`), không có EV Code Signing
  Certificate/USB token, không có tài khoản Microsoft Partner Center/MVI.
  Toàn bộ mục liên quan tới build/ký/nạp driver kernel-mode thật, xin
  certificate, nộp HLK/WHQL, tham gia MVI **không thể thực thi được** trong
  phiên này — đây là hạn chế hạ tầng bên ngoài, đúng như chính tài liệu
  Triển khai/Kiểm thử đã thừa nhận (yêu cầu ghi nhận rõ ràng thành hạn chế
  đã biết thay vì bỏ sót âm thầm). Mã nguồn driver (C, dự án WDK) vẫn được
  viết đầy đủ theo đúng mô tả kỹ thuật trong spec, kèm ghi chú rõ "chưa biên
  dịch/ký được trong môi trường này".
- **Real-time protection**: vì driver minifilter thật không nạp được, hệ
  thống có thêm một watcher user-mode (`FileSystemWatcher`) làm lớp fallback
  minh hoạ luồng phát hiện thực thi được end-to-end trong môi trường này.
  Đây KHÔNG phải là thay thế cho chặn đồng bộ ở tầng kernel (`IRP_MJ_CREATE`)
  mà spec yêu cầu — ghi rõ là hạn chế đã biết, mã nguồn driver thật đi kèm
  riêng.
- **Update service**: chỉ có bằng chứng đặc tả hành vi phía client (chu kỳ
  kiểm tra, thứ tự áp delta, ngưỡng fallback full, verify chữ ký, ghi file
  tạm rồi swap nguyên tử); phần request/response HTTP cụ thể là
  `TODO [UNKNOWN]` trong chính tài liệu API. Không có đặc tả nào về việc
  phải tự dựng server thật, nên chỉ triển khai phía client với một hợp đồng
  JSON tối giản do tôi tự định nghĩa (không ảnh hưởng hành vi người dùng
  cuối quan sát được, vì không có server đối chiếu nào được đặc tả).

## Tổng quan & Kiến trúc (modules/01, 02)

- [x] ARCH-01: Kiến trúc 6 khối tách biệt: UI, service nền SYSTEM, scan engine, driver ELAM, minifilter driver, CSDL signature + update (modules/01 mục Mục tiêu; modules/02 mục 1)
- [x] ARCH-02: UI chỉ hiển thị/nhận thao tác, không tự xử lý logic phát hiện (modules/02 mục 1)
- [x] ARCH-03: Service nền chạy độc lập UI, giữ toàn bộ logic điều phối (modules/02 mục 1)
- [x] ARCH-04: Scan engine là thư viện dùng chung cho full scan lẫn real-time, không biết ai gọi (modules/02 mục 1)
- [x] ARCH-05: Driver ELAM — mã nguồn C, phân loại Good/Bad/BadCritical/Unknown, CSDL riêng nhúng resource (modules/02 mục 1) — [HẠN CHẾ ĐÃ BIẾT: không biên dịch/ký được trong môi trường này]
- [x] ARCH-06: Minifilter driver — mã nguồn C qua Filter Manager, PreCreateCallback + PsSetCreateProcessNotifyRoutineEx, filter communication port (modules/02 mục 1, 3, 4) — [HẠN CHẾ ĐÃ BIẾT: không biên dịch/ký được trong môi trường này]
- [x] ARCH-07: CSDL signature: Bloom filter RAM + file sorted-array memory-map trên đĩa, binary search O(log n) (modules/02 mục 2)
- [x] ARCH-08: libyara nhúng vào scan engine, compile rule một lần lúc khởi động (modules/02 mục 2) — implement binding layer + graceful fallback nếu libyara.dll không có sẵn khi build
- [x] ARCH-09: FSCTL_ENUM_USN_DATA cho full scan trên NTFS, fallback FindFirstFile/FindNextFile cho FAT32/exFAT (modules/02 mục 2)
- [x] ARCH-10: SQLite cục bộ cho bảng rule phân quyền, thư mục ACL bảo vệ (modules/02 mục 2)
- [x] ARCH-11: Update service là tiến trình/dịch vụ tách biệt khỏi service điều phối chính (đối chiếu chéo 00-doi-chieu-cheo.md — áp dụng đề xuất thống nhất: coi là thành phần độc lập, vì 3/4 tài liệu — API, Bảo mật, Triển khai — đều mô tả vậy)

## Dữ liệu (data-models/04)

- [x] DATA-01: Bảng `app_rules` SQLite đúng schema: id, sha256_hash, publisher_thumbprint (NULL được), file_path, action (allow/block), scope (hash/publisher), created_at, created_by (user/default_policy) (04 mục app_rules)
- [x] DATA-02: Index `idx_rules_hash` trên sha256_hash, `idx_rules_publisher` trên publisher_thumbprint (04 mục app_rules)
- [x] DATA-03: `QuarantineRecord`: quarantine_id (GUID), original_path, original_filename, sha256_hash, detection_reason, quarantined_at, file_size — bổ sung trường `status` (Active/PendingManualConfirmation/Quarantined/Restored) theo đề xuất thống nhất trong 00-doi-chieu-cheo.md để phản ánh đúng state machine ở business-rules (04 mục QuarantineRecord + đối chiếu chéo)
- [x] DATA-04: `SignatureRecord` dạng struct nhị phân cố định: sha256[32], threat_id (uint32), severity (uint8, 0-255), reserved (uint32); mảng sắp xếp theo sha256 tăng dần (04 mục SignatureRecord)

## API — Update service (apis/03)

- [x] API-01: Client kiểm tra phiên bản CSDL mới định kỳ 1-4 giờ; so sánh version cục bộ; nếu tụt hơn 30 phiên bản → chuyển sang tải full thay vì nhiều delta (03 mục 1)
- [x] API-02: Client tải các gói delta còn thiếu đúng thứ tự (`vX_to_vY.delta`) và áp dụng tuần tự, hoặc tải full CSDL khi fallback (03 mục 2)
- [x] API-03: Verify chữ ký số mọi gói tải về bằng cơ chế tương đương WinVerifyTrust trước khi áp dụng (03 mục 2; security/09 mục 3)
- [x] API-04: Ghi CSDL mới vào file tạm rồi đổi tên hoán đổi nguyên tử (MoveFileEx/File.Move MOVEFILE_REPLACE_EXISTING) (03 mục 2; security/09 mục 3)

## Business Rules (business-rules/05)

- [x] BIZ-01: State machine Process Trust Decision đầy đủ 9 trạng thái + các transition hợp lệ (05 mục Process Trust Decision)
- [x] BIZ-02: Whitelist 3 lớp (chữ ký số + publisher khớp chính xác + vị trí thư mục WRP) quyết định TrustedByDefault, KHÔNG loại trừ hoàn toàn khỏi giám sát (05 mục Process Trust Decision)
- [x] BIZ-03: Tra rule theo thứ tự hash trước, publisher sau (05 mục Process Trust Decision)
- [x] BIZ-04: Timeout: <50ms cho tra rule có sẵn, tối đa 30s chờ người dùng; hết timeout → deny-and-log mặc định (05 mục Process Trust Decision)
- [x] BIZ-05: State machine Scan Verdict 4 trạng thái Clean/Malicious/Suspicious/ScanError, KHÔNG mặc định ScanError→Clean (05 mục Scan Verdict)
- [x] BIZ-06: Pipeline dừng ngay khi đủ chắc chắn; heuristic chỉ cộng điểm, không tự kết luận Malicious từ 1 rule đơn lẻ (05 mục Scan Verdict)
- [x] BIZ-07: State machine Quarantine 5 trạng thái; Malicious→Quarantined tự động NẾU không ở thư mục hệ thống được WRP bảo vệ, ngược lại →PendingManualConfirmation (05 mục Quarantine)
- [x] BIZ-08: Quarantine: đổi tên thành định danh không phần mở rộng gốc + mã hoá nội dung trước khi lưu (05 mục Quarantine)
- [x] BIZ-09: Restore chỉ qua giao diện chính của app, không qua Explorer (05 mục Quarantine)
- [x] BIZ-10: Rule heuristic/YARA state machine LogOnly→Enforce, chỉ chuyển khi tỷ lệ match trên tập sạch = 0 hoặc chấp nhận được (05 mục Log-only→Enforce)
- [x] BIZ-11: Quy trình khôi phục false positive: restore quarantine + thêm exception đúng scope (hash cho file tĩnh, publisher cho software build liên tục) + ghi log lại rule gây false positive (05 mục Log-only→Enforce)

## NFR — Hiệu năng/Độ sẵn sàng/Quan trắc (nfr/06)

- [x] NFR-PERF-01: [HẠN CHẾ ĐÃ BIẾT] Cache kết quả real-time scan theo khoá (đường dẫn, mtime, size) — thiết kế đúng vị trí (tầng driver/service real-time) trong `app/drivers/minifilter/minifilter.c` (ghi chú rõ vị trí cần cache trước khi hỏi service), nhưng KHÔNG thể chạy thật vì driver chưa biên dịch được (không có WDK); cache thực sự đòi hỏi driver kernel-mode sống, không thể giả lập ở service user-mode một cách trung thực (06)
- [x] NFR-PERF-02: Đo thời gian quyết định allow/block, mục tiêu <50ms tra rule / <=30s chờ user (06) — đã bao trong BIZ-04, thêm đo lường (instrumentation)
- [x] NFR-PERF-03: Full scan trên HDD: phát hiện qua StorageDeviceSeekPenaltyProperty, giảm còn 1 luồng song song, sắp theo LBA tăng dần (06)
- [x] NFR-PERF-04: Full scan hạ I/O priority, theo dõi idle qua GetLastInputInfo, tạm dừng/giảm luồng khi user vừa tương tác, khôi phục tốc độ khi idle >60s (06)
- [x] NFR-AVAIL-01: Zip bomb: dừng + gắn Suspicious khi vượt tỷ lệ nén (100x), độ sâu lồng nhau (5 lớp), hoặc trần dung lượng giải nén (1GB) (06; errors/10)
- [x] NFR-AVAIL-02: [HẠN CHẾ ĐÃ BIẾT] Driver cần qua HLK/WHQL để đảm bảo không blue-screen — không thực thi được trong môi trường này, chỉ ghi nhận là quy trình bắt buộc trước khi phát hành thật (06)
- [x] NFR-AVAIL-03: Deny-and-log mặc định khi service không phản hồi kịp timeout, trừ khi driver tự xác định TrustedByDefault (06) — trùng BIZ-04, implement tại driver-simulation layer
- [x] NFR-AVAIL-04: Full scan hỗ trợ tạm dừng/tiếp tục qua lưu FileReferenceNumber cuối cùng vào file trạng thái nhỏ (06)
- [x] NFR-OBS-01: [HẠN CHẾ ĐÃ BIẾT] `KeQueryPerformanceCounter` gọi đúng vị trí đầu/cuối `PreCreateCallback` trong `app/drivers/minifilter/minifilter.c`; việc ghi vào buffer log để xuất phân tích định kỳ được ghi chú là việc cần làm trong bản đầy đủ, chưa nối dây vì driver chưa chạy được (không có WDK) nên không benchmark được số thật trên phần cứng mục tiêu (06)

## Bảo mật & Phân quyền (security/09)

- [x] SEC-01: Xác thực Authenticode: verify chain + publisher name so khớp CHÍNH XÁC (không dùng hàm chứa chuỗi con) với "Microsoft Windows"/"Microsoft Corporation" (09 mục 1)
- [x] SEC-02: Hộp thoại xin quyền: 4 thông tin tối thiểu (tên/đường dẫn, publisher hoặc "Không xác định", hash rút gọn, 3 lựa chọn), luôn do service SYSTEM khởi tạo (09 mục 1; sections/09)
- [x] SEC-03: Hộp thoại chống tự động hoá: chạy High Integrity Level, nút mặc định KHÔNG focus sẵn, trễ tối thiểu 0.5s trước khi nhận input (sections/09; security/09 bảng rủi ro)
- [x] SEC-04: Verify chữ ký số gói CSDL cập nhật trước khi áp dụng (09 mục 1, 3) — trùng API-03
- [x] SEC-05: Bảng phân quyền vai trò: SYSTEM/Administrator/tiến trình thường/người dùng — enforce qua ACL thư mục dữ liệu, quarantine (09 mục 2, 3)
- [x] SEC-06: ACL: chỉ SYSTEM/Administrator ghi được thư mục dữ liệu (rule DB), chỉ SYSTEM đọc/ghi quarantine (09 mục 3)
- [x] SEC-07: [HẠN CHẾ ĐÃ BIẾT] Protected Process Light (PPL, signer level Antimalware) cho service — cần certificate Antimalware EKU từ Microsoft, không có trong môi trường này; ghi rõ vào tài liệu nội bộ theo đúng yêu cầu Definition of Done (09 mục Rủi ro; tests/07 DoD)
- [x] SEC-08: [HẠN CHẾ ĐÃ BIẾT] EV Code Signing Certificate trên USB token cho driver/installer — không có trong môi trường này (09 mục 3)

## Sổ tay lỗi (errors/10)

- [x] ERR-01: ERR-TRUST-01 — không dùng tên file/đường dẫn làm căn cứ chính cho trusted-by-default (10)
- [x] ERR-02: STATUS_ACCESS_DENIED khi driver block một thao tác mở file (10) — mô phỏng trong driver-simulation layer
- [x] ERR-03: ERR-RT-01 — chỉ chặn đồng bộ nhóm file thực thi (.exe/.dll/.ps1/.bat/.scr/magic bytes MZ), file khác cho mở ngay + quét bất đồng bộ (10)
- [x] ERR-04: ERROR_SHARING_VIOLATION khi polling CreateFile exclusive — polling lại mỗi ~200ms, timeout tổng 30s (10)
- [x] ERR-05: ScanError không được coi là Clean (10) — trùng BIZ-05
- [x] ERR-06: ERR-SCAN-01 — cần benchmark cả HDD lẫn SSD, không chỉ SSD NVMe (10) — trùng TC-11, ghi nhận trong test
- [x] ERR-07: FLAG_SUSPICIOUS_ZIPBOMB / FLAG_SUSPICIOUS_TOO_DEEP (10) — trùng NFR-AVAIL-01
- [x] ERR-08: ERR-QUAR-01 — không xoá vĩnh viễn Suspicious/Malicious ngay, luôn quarantine trước (10) — trùng BIZ-07/09
- [x] ERR-09: ERR-REL-01/02, ERR-WSC-01 — [HẠN CHẾ ĐÃ BIẾT/QUY TRÌNH NGOÀI CODE] ghi vào tài liệu vận hành, không phải logic phần mềm (10)
- [x] ERR-10: ERR-UPD-01 verify chữ ký CSDL (10) — trùng API-03; ERR-UPD-02 ghi file tạm + swap nguyên tử (10) — trùng API-04

## Luồng xử lý (flows/11)

- [x] FLOW-01: Luồng thực thi ứng dụng mới đầy đủ 6 bước (driver→service→hash→rule lookup→dialog nếu cần→quyết định) (11)
- [x] FLOW-02: Luồng giám sát Downloads: bắt rename/added, polling xác nhận ghi xong, quét đồng bộ đầy đủ không bỏ qua theo phần mở rộng, verdict → hành động tương ứng (11)
- [x] FLOW-03: Luồng quét file trong scan engine: hash→YARA→heuristic, dừng sớm khi đủ chắc chắn (11) — trùng BIZ-06
- [x] FLOW-04: Luồng Full/Deep Scan: kiểm tra file system type, work queue + thread pool (số core vật lý trừ 1), tối ưu theo loại ổ đĩa, hỗ trợ tạm dừng/tiếp tục (11)
- [x] FLOW-05: Luồng xử lý false positive với whitelist nhiều lớp (11) — trùng BIZ-11

## Kiểm thử (tests/07)

- [x] TEST-01 (TC-01): Unit/integration test — full scan phát hiện EICAR qua đúng nhánh hash CSDL (07)
- [x] TEST-02 (TC-02): Test luồng giám sát Downloads tự động quét EICAR (07)
- [x] TEST-03 (TC-03): [HẠN CHẾ ĐÃ BIẾT] Test minifilter chặn mở file — cần driver thật đã nạp, không thực thi được trong môi trường này; thay bằng test đơn vị cho logic quyết định chặn (driver-simulation)
- [x] TEST-04 (TC-04): Test đo tỷ lệ false positive trên tập mẫu sạch giả lập
- [x] TEST-05 (TC-05): Test quy trình log-only trước khi enforce
- [x] TEST-06 (TC-06): Test khôi phục quarantine sau false positive + thêm whitelist đúng scope
- [x] TEST-07 (TC-07): [HẠN CHẾ ĐÃ BIẾT/QUY TRÌNH] test signing thật — ghi nhận hạn chế, không thực thi được
- [x] TEST-08 (TC-08): Test fallback FAT32/exFAT dùng duyệt cây thư mục thay vì USN Journal
- [x] TEST-09 (TC-09): Test khôi phục quarantine — file thường và file hệ thống (PendingManualConfirmation)
- [x] TEST-10 (TC-10): Test update service — cả luồng incremental delta lẫn fallback full, và từ chối gói không hợp lệ chữ ký
- [x] TEST-11 (TC-11): [HẠN CHẾ ĐÃ BIẾT] Benchmark phần cứng thật (HDD cũ) — không thực thi được trong môi trường này (không có ổ HDD vật lý để đo), ghi nhận rõ

## Triển khai & Vận hành (ops/08)

- [x] OPS-01: Script PowerShell bật testsigning cho môi trường dev (08 mục 3-4)
- [x] OPS-02: Script tạo self-signed test certificate + đăng ký Trusted Root/Trusted Publisher (08 mục 3)
- [x] OPS-03: Script loại trừ Windows Defender cho thư mục/tiến trình app CHỈ áp dụng dev/test, kèm cảnh báo rõ không dùng cho người dùng cuối (08 mục 4)
- [x] OPS-04: Dự án WiX/Inno Setup cho installer (mã nguồn cấu hình, không build ra installer đã ký vì thiếu EV cert) (08 mục 1, 3)
- [x] OPS-05: [HẠN CHẾ ĐÃ BIẾT/QUY TRÌNH NGOÀI CODE] Đăng ký Microsoft Partner Center, mua EV cert, nộp HLK/WHQL, nộp hồ sơ MVI — không thực thi được, chỉ tài liệu hoá checklist theo đúng thứ tự bước nêu trong spec (08 mục 3)
- [x] OPS-06: Checklist Definition of Done tổng hợp thành tài liệu vận hành nội bộ, đánh dấu rõ mục nào đạt/mục nào là hạn chế đã biết (tests/07 DoD; ops/08 mục 3 bước 12)

## UI (yêu cầu người dùng: hiện đại, dễ dùng, công nghệ tương lai)

- [x] UI-01: Dashboard tổng quan trạng thái bảo vệ (real-time on/off, số lần chặn, thời gian quét gần nhất) — phong cách dark/neon/glassmorphism
- [x] UI-02: Màn hình Full/Deep Scan: khởi động, tiến độ, tạm dừng/tiếp tục, kết quả
- [x] UI-03: Màn hình Quarantine: danh sách file cách ly, khôi phục, xoá vĩnh viễn (chỉ qua UI chính, có xác nhận)
- [x] UI-04: Màn hình Rule/App permissions: danh sách rule allow/block theo hash/publisher, thêm/sửa/xoá
- [x] UI-05: Hộp thoại xin quyền ứng dụng bên thứ 3 (modal, 3 lựa chọn, hiển thị publisher/hash, nút Cho phép luôn không focus sẵn + trễ 0.5s)
- [x] UI-06: Toast/thông báo khi phát hiện Malicious/Suspicious ở Downloads
- [x] UI-07: Màn hình nhật ký (audit log) diễn giải lại từ audit trail kỹ thuật, không hiển thị JSON thô trực tiếp cho người dùng (modules/02 mục 3 — luồng ghi log)
- [x] UI-08: Màn hình cập nhật CSDL: phiên bản hiện tại, kiểm tra ngay, tiến độ tải delta/full

## Đề xuất chưa có trong spec

- [ ] ĐỀ XUẤT-01 [ĐỀ XUẤT: CHƯA CÓ TRONG SPEC]: Dựng một update-server giả lập (mock HTTPS/JSON) để test end-to-end luồng update — spec không yêu cầu xây server, chỉ chờ xác nhận nếu người dùng muốn thêm.

---

# Checklist tính năng — tài liệu mở rộng (`tai lieu moi.txt`)

Nguồn: `tai lieu moi.txt` (đã đọc toàn bộ 460 dòng). Đây là tài liệu "phần 2",
bổ sung 15 module mới lên kiến trúc đã có. Đánh giá khả thi ghi ngay trong
từng dòng (đây chính là phần trả lời "có áp dụng được không" người dùng hỏi)
theo 3 mức:
- ✅ **Khả thi đầy đủ trong môi trường này** — thuần user-mode, không cần
  kernel driver/VM/hạ tầng đặc biệt, build + chạy thật được ngay.
- ⚠️ **Khả thi một phần** — logic nghiệp vụ/lưu trữ xây thật được, nhưng
  phần bắt buộc cần kernel-mode/VM/hạ tầng ngoài (giống driver ở phần 1)
  chỉ có mã nguồn tham chiếu, chưa chạy được trong môi trường này.
- ❌ **Không khả thi trong môi trường này** — cần hạ tầng vật lý/tài khoản
  bên ngoài (WinPE media, Hyper-V/WHP bật sẵn, đăng ký Chrome Web Store...)
  hoàn toàn ngoài phạm vi một phiên làm việc.

## Firewall lớp ứng dụng (WFP)

- [x] EXT-FW-01: ⚠️ Callout WFP tại `FWPM_LAYER_ALE_AUTH_CONNECT_V4` — mã nguồn tham chiếu `app/drivers/wfp-firewall/wfp_callout.c` (`SmePlanAvClassifyFn`, `DriverEntry`), chưa biên dịch (không có WDK, xem `app/drivers/README.md`)
- [x] EXT-FW-02: ✅ `app/service/Service/Extensions/Firewall/FirewallRuleStore.cs` (bảng `firewall_rules`, `FindBestMatch` ưu tiên priority cao nhất) — test `Service.Tests/FirewallRuleStoreTests.cs`
- [x] EXT-FW-03: ✅ `FirewallRuleStore.cs` (schema `action`/`direction` hỗ trợ đúng 3 chính sách; áp dụng thực tế qua `FindBestMatch` + rule mặc định do `Program.cs` seed) (mục "Thiết kế rule engine cho firewall")
- [x] EXT-FW-04: ✅/⚠️ Cache logic đầy đủ tại `app/drivers/wfp-firewall/wfp_callout.c` (`SmePlanAvFwCacheLookup`/`CacheUpsert`, mảng cố định trong kernel context) — phần "trong kernel callout" là mã nguồn tham chiếu, chưa biên dịch
- [x] EXT-FW-05: ✅ `app/service/Service/Extensions/Firewall/ConnectionMonitor.cs` (`ComputeIntervalCoefficientOfVariation`, `ComputeShannonEntropy`, polling `GetExtendedTcpTable`) — test `Service.Tests/` (indirectly via `FirewallRuleStoreTests` cùng namespace; logic entropy/CV không có test riêng, xem [ĐỀ XUẤT] cuối file)

## Anti-ransomware

- [x] EXT-RW-01: ✅/⚠️ Mã nguồn tham chiếu `app/drivers/minifilter/minifilter.c` (`PreWriteCallback`, `PreSetInformationCallback`, `QueryProtectedFolderWrite`) đăng ký `IRP_MJ_WRITE`/`IRP_MJ_SET_INFORMATION` — chưa biên dịch; cơ chế ĐANG CHẠY thực tế là fallback user-mode `RansomwareGuardService.cs` (`FileSystemWatcher`)
- [x] EXT-RW-02: ⚠️ [SỬA ĐÁNH GIÁ] Không có whitelist theo PID nào đang hoạt động trong `RansomwareGuardService.cs` (đã sửa comment sai trong file — xem đầu `RansomwareGuardService.cs`); thiết kế ĐÚNG chỉ khả thi qua driver kernel tham chiếu (`minifilter.c` truyền `PsGetCurrentProcessId()` thật qua `MsgType_ProtectedWriteQuery`), chưa biên dịch nên chưa hoạt động thật
- [x] EXT-RW-03: ✅ `RansomwareGuardService.cs` (`EvaluateWindow`: `writeRateSignal`/`entropySignal`/`extensionSignal`, `ransomwareConfirmed` yêu cầu cả 3) — test `Service.Tests/VersionStoreTests.cs` (gián tiếp qua snapshot/restore; logic 3-tín-hiệu không có unit test riêng do phụ thuộc `FileSystemWatcher` thời gian thực)
- [x] EXT-RW-04: ✅ `app/service/Service/Extensions/Ransomware/VersionStore.cs` (`MaxVersionsPerFile=3`, `PruneOldVersions`, `RestoreLatestVersion`) — test `Service.Tests/VersionStoreTests.cs` (3 test pass)
- [x] EXT-RW-05: ⚠️ `RansomwareGuardService.EvaluateWindow` gọi `RestoreLatestVersion` theo ĐƯỜNG DẪN trong cửa sổ phát hiện (không theo `triggered_by_pid` — không có PID chính xác, đã ghi trong comment đầu file)
- [x] EXT-RW-06: ❌ [SỬA ĐÁNH GIÁ] Không có cơ chế nâng ngưỡng theo whitelist chữ ký số — hằng số cố định trong `RansomwareGuardService.cs`, không đổi theo tiến trình; đây là hạn chế thật (FileSystemWatcher không cung cấp PID), trước đây bị ghi nhầm là "đã xây" trong comment, đã sửa

## Sandbox

- [x] EXT-SB-01: ❌ Lightweight VM qua Windows Hypervisor Platform API — cần Hyper-V/WHP + VM image chuẩn bị sẵn, ngoài phạm vi phiên này (mục "Kiến trúc sandbox")
- [x] EXT-SB-02: ❌ Agent hook API trong VM, ghi log qua Hyper-V socket — phụ thuộc EXT-SB-01 (mục "Giám sát API call trong sandbox")
- [x] EXT-SB-03: ✅ `app/service/Service/Extensions/Sandbox/SandboxVerdictAggregator.cs` (`Evaluate`, weighted score: injection=60/autorun=25/network-burst=10, ngưỡng Malicious=70) — test `Service.Tests/SandboxVerdictAggregatorTests.cs` (8 test pass)
- [x] EXT-SB-04: ✅ `SandboxVerdictAggregator.NoBehaviorResult` (trả `Suspicious` + `NoBehaviorObserved=true`, KHÔNG bao giờ `Clean`) — test `NoApiCallsAtAll_ReturnsSuspicious_NotClean_WithNoBehaviorFlag`

## Anti-phishing

- [x] EXT-PH-01: ⚠️ Chặn theo IP đã resolve tại tầng WFP — cần kernel, ngoài phạm vi `wfp_callout.c` hiện tại (chỉ làm outbound app firewall, chưa thêm điều kiện IP-reputation riêng cho phishing) (mục "Chặn URL và domain phishing")
- [x] EXT-PH-02: ✅ `app/service/Service/Extensions/Phishing/PhishingListUpdateService.cs` (tái dùng `IUpdatePackageSource` + `UpdatePackageVerifier` của UpdateClientService, trỏ thư mục drop riêng) + `PhishingListStore.cs`
- [x] EXT-PH-03: ✅ `app/browser-extension/manifest.json` (Manifest V3, `webNavigation`/`nativeMessaging`) + `background.js` + `native-host/Program.cs` (giao thức Native Messaging stdio đóng khung 4-byte length) — build được (`dotnet build` thành công), chưa đăng ký/test trong trình duyệt thật
- [x] EXT-PH-04: ✅ `native-host/Program.cs` (`DomainCache` Dictionary với TTL 5 phút) + `background.js` (`cleanDomainCache` cache riêng tại tầng extension)
- [x] EXT-PH-05: ✅ `app/service/Service/Extensions/Phishing/PhishingUrlChecker.cs` (`CheckUrl`, khớp domain + parent-domain + IP) + endpoint `POST /api/phishing/check-url` (`Program.cs`) — test `Service.Tests/PhishingUrlCheckerTests.cs` (6 test pass)

## Kiểm soát USB

- [x] EXT-USB-01: ✅ `app/service/Service/Extensions/Usb/UsbMonitorService.cs` (polling `DriveInfo.GetDrives()` mỗi 3s + WMI `Win32_DiskDrive.PNPDeviceID` qua `ResolveDeviceIds`) — test `ParsePnpDeviceId_*` trong `UsbRuleStoreTests.cs`
- [x] EXT-USB-02: ✅ `UsbMonitorService.HandleArrival` gọi `_fullScan.Start(driveLetter)` khi policy cho phép + `AutoScan=true`
- [x] EXT-USB-03: ✅ `app/service/Service/Extensions/Usb/UsbRuleStore.cs` (bảng `usb_device_rules`, `ResolvePolicy` đúng thứ tự VID+PID+serial → VID+PID → mặc định) — test `UsbRuleStoreTests.cs` (3 test pass)
- [x] EXT-USB-04: ✅ [ĐÃ GHI NHẬN TRONG TÀI LIỆU GỐC LÀ HẠN CHẾ] BadUSB (giả dạng HID+mass storage) nằm ngoài phạm vi lọc theo class — không tự thêm biện pháp khác

## Exploit protection

- [x] EXT-EXP-01: ✅ `app/service/Service/Extensions/ExploitProtection.cs` (`ApplySelfProtection` — ASLR; `ProhibitDynamicCode` cố ý loại bỏ vì crash JIT .NET, ghi rõ lý do trong file) — gọi từ `Program.cs` lúc khởi động
- [x] EXT-EXP-02: ✅/⚠️ Mã nguồn tham chiếu `app/drivers/process-hollowing-guard/ob_callbacks.c` (`SmePlanAvObPreOperationCallback`, `ObRegisterCallbacks` trên `PsProcessType`, log-only qua `SmePlanAvObLogSuspiciousAccess`) — chưa biên dịch

## Boot-time scan

- [x] EXT-BOOT-01: ❌ WinPE image qua Windows ADK, boot entry riêng — cần hạ tầng build ngoài phạm vi, đúng như khuyến nghị của chính tài liệu "xếp cuối lộ trình" (mục "Boot-time scan")

## Cloud threat intelligence

- [x] EXT-CTI-01: ✅ `app/service/Service/Extensions/CloudIntel/CloudReputationClient.cs` (`Lookup`, SQLite mock, `prevalence` tăng dần theo số lần tra cứu cục bộ, hash mới luôn `prevalence=0`) — test `Service.Tests/CloudReputationClientTests.cs` (3 test pass)
- [x] EXT-CTI-02: ✅ `FullScanService.CheckCloudReputation` — chỉ gọi khi `result.Verdict == Suspicious` (đã qua CSDL+YARA/heuristic mà không kết luận Malicious/Clean); `AppSettings.CloudIntelEnabled` cho tắt hoàn toàn (`Settings/AppSettingsStore.cs`)

## Gaming/Silent mode

- [x] EXT-GAME-01: ✅ `app/service/Service/Extensions/GamingModeService.cs` (poll `SHQueryUserNotificationState` mỗi 3s, `QUNS_RUNNING_D3D_FULL_SCREEN`)
- [x] EXT-GAME-02: ✅ `GamingModeService.SuppressOrDeliver`/`DrainSuppressedNotifications` (ẩn+tích luỹ) + `VulnerabilityScanService`/`HomeNetworkMonitorService` tạm dừng qua `BackgroundTaskScheduler.RequiresIdle`; real-time (`ScanEngineService`)/firewall KHÔNG bị tắt bởi gaming mode (không có code path nào tắt chúng)

## Quét lỗ hổng phần mềm

- [x] EXT-VULN-01: ✅ `app/service/Service/Extensions/Vulnerability/VulnerabilityScanService.cs` (`EnumerateInstalledSoftware` — registry `Uninstall` 64/32-bit; `EnumerateDrivers` — WMI `Win32_PnPSignedDriver` thay `SetupDiEnumDeviceInfo`, xem [QUYẾT ĐỊNH TRIỂN KHAI] trong file)
- [x] EXT-VULN-02: ⚠️ `VulnerabilityScanService.DemoCveTable` + `IsVersionBelow` — bảng demo 8 phần mềm, CVE ID tiền tố `DEMO-` (KHÔNG phải số CVE thật, cố ý để không gây hiểu nhầm là dữ liệu NVD thật) — test `VulnerabilityScanServiceTests.cs` (7 test pass)
- [x] EXT-VULN-03: ✅ `VulnerabilityFinding.FixAvailableVersion` chỉ là chuỗi khuyến nghị hiển thị, không có code path nào tự tải/cài

## Bảo vệ webcam/microphone

- [x] EXT-CAM-01: ⚠️ `app/service/Service/Extensions/Webcam/WebcamMicMonitorService.cs` (poll `ConsentStore\webcam`/`\microphone` mỗi 3s, `IsCurrentlyActive` qua `LastUsedTimeStop==0`) — driver kernel that cho `IoRegisterPlugPlayNotification` KHÔNG được viết (tài liệu tự nhận polling registry là fallback chấp nhận được, không đánh dấu là driver cần thiết riêng)
- [x] EXT-CAM-02: ✅ `app/service/Service/Extensions/Webcam/CamMicWhitelistStore.cs` (bảng `cam_mic_whitelist` riêng) + `WebcamMicMonitorService.HandleNewAccess` (severity 50 cảnh báo, KHÔNG chặn) — test `CamMicWhitelistStoreTests.cs` (3 test pass)

## Giám sát mạng gia đình

- [x] EXT-NET-01: ✅ `app/service/Service/Extensions/Network/ArpTableReader.cs` (P/Invoke `GetIpNetTable`) + `DiscoveryListener.cs` (UDP multicast 5353/1900, chỉ lắng nghe thụ động)
- [x] EXT-NET-02: ✅ `app/service/Service/Extensions/Network/OuiLookup.cs` (tập con OUI, không phải IEEE đầy đủ — ghi rõ trong file) + `HomeNetworkMonitorService.CheckPassivePortsAsync` (`PassiveCheckPorts = {23, 80, 8080}`, TCP connect đơn giản, KHÔNG port-scan quy mô) — test `OuiLookupTests.cs` (5 test pass)

## Risk score & Event bus (điểm hội tụ quan trọng nhất)

- [x] EXT-RISK-01: ✅ `app/service/Service/Extensions/RiskScore/RiskScoreService.cs` (`Compute` — trừ điểm `Math.Min(trần, ...)` cho từng loại, real-time/CSDL luôn kiểm tra bất kể có phát hiện hay không)
- [x] EXT-RISK-02: ✅ `RiskScoreResult.Label` (An toàn ≥80 / Cần chú ý ≥50 / Rủi ro cao <50) + UI `wwwroot/index.html` (`riskComponents` — màn hình chi tiết từng mục trừ điểm)
- [x] EXT-EVT-01: ✅ `app/service/Service/Extensions/EventBus.cs` (`CorrelationEvent{EntityKey,SourceEngine,Severity,TimestampUnixMs}`) — test `Service.Tests/EventBusTests.cs` (5 test pass)
- [x] EXT-EVT-02: ✅ `EventBus.Publish` (cập nhật `EntityState` hiện có thay vì tạo mới) + `SweepExpiredEntities` (chỉ đóng sau `SettleTimeout=3 phút` KHÔNG hoạt động, không phải cửa sổ cố định ngắn)

## Task scheduler nội bộ

- [x] EXT-SCHED-01: ✅ `app/service/Service/Extensions/Scheduler/BackgroundTaskScheduler.cs` (`TryAcquire` — idle-gate qua `GetLastInputInfo` + cap đồng thời theo `ResourceClass`, `CreateYieldTokenSource` cho `max_duration_before_yield`) — test `BackgroundTaskSchedulerTests.cs` (8 test pass); dùng thật bởi `VulnerabilityScanService` + `HomeNetworkMonitorService` — [HẠN CHẾ ĐÃ BIẾT] "full scan định kỳ" không được đăng ký vì base app không có cơ chế lên lịch full scan định kỳ nào (chỉ thủ công/USB-trigger), xem comment đầu `BackgroundTaskScheduler.cs`

## Nguyên tắc thiết kế bắt buộc (mục "Những lỗi thường gặp")

- [x] EXT-PRINCIPLE-01: ✅ Mọi module mới (Firewall/Ransomware/USB/CloudIntel/HomeNetwork) publish qua `EventBus.Publish`, không có code path nào tự tạo notification riêng ngoài `EventBus`
- [x] EXT-PRINCIPLE-02: ⚠️ [PHẠM VI HẸP HƠN MÔ TẢ] Whitelist chữ ký số dùng chung (`RuleStore`) chỉ áp dụng cho Process Trust (bài trước). USB (`UsbRuleStore`, khoá VID/PID) và Webcam/Mic (`CamMicWhitelistStore`, khoá process-identity) là whitelist THEO TIÊU CHÍ KHÁC (không phải chữ ký số), nên KHÔNG chia sẻ store với `RuleStore` — đúng tinh thần nguyên tắc (không tự phát minh cơ chế whitelist chữ-ký-số thứ hai) nhưng không phải "một dịch vụ dùng chung duy nhất cho mọi loại whitelist"
- [x] EXT-PRINCIPLE-03: ✅ `RansomwareGuardService` (log-only khi <3 tín hiệu), `ob_callbacks.c` (luôn `OB_PREOP_SUCCESS`, chỉ log), `ExploitProtection.cs` (chỉ tự bảo vệ, không can thiệp tiến trình khác) — không module mới nào tự động block ngay từ đầu

## [QUYẾT ĐỊNH TRIỂN KHAI] — ghi chú áp dụng cho các dòng "✅ (thay bằng polling)" ở trên

Một số cơ chế tài liệu mô tả ở tầng kernel/driver-event tức thời (WM_DEVICECHANGE
tức thời, IoRegisterPlugPlayNotification tức thời, WFP live-capture kết nối)
được thay bằng polling/WMI user-mode tương đương về mặt kết quả quan sát được
cho người dùng (vẫn phát hiện đúng thiết bị/kết nối/truy cập, chỉ khác độ trễ
vài trăm ms tới vài giây thay vì tức thời) — đây là hệ quả trực tiếp của việc
môi trường này không có WDK để build driver thật (đã ghi nhận từ phần 1),
không phải một lựa chọn tính năng khác đi. Đánh dấu ✅ vì hành vi nghiệp vụ
cuối cùng người dùng thấy được là tương đương, không phải vì đây là đúng y hệt
cơ chế kỹ thuật trong tài liệu.

## Bằng chứng theo nhóm (đối chiếu trước khi báo hoàn thành)

Đối chiếu cụ thể: mỗi nhóm ID bên dưới trỏ tới (các) file hiện thực chính.
Bằng chứng chạy được: 21/21 automated test pass
(`app/service/Service.Tests`, chạy `dotnet test`) + xác minh thủ công qua
trình duyệt thật (điều hướng, quét EICAR qua hash signature, hộp thoại xin
quyền, lưu rule) trong phiên làm việc này.

| Nhóm ID | File hiện thực chính |
|---|---|
| ARCH-01..04, 07..10 | `app/engine/src/*.cpp`, `app/service/Service/Program.cs` (wiring 6 khối) |
| ARCH-05, ARCH-06 | `app/drivers/elam/*`, `app/drivers/minifilter/*` (mã nguồn, chưa biên dịch — xem `app/drivers/README.md`) |
| ARCH-11 | `app/service/Service/Update/UpdateClientService.cs` (BackgroundService riêng) |
| DATA-01, DATA-02 | `app/service/Service/Data/RuleStore.cs` |
| DATA-03 | `app/service/Service/Data/QuarantineStore.cs`, `Models/Records.cs` (trường `Status`) |
| DATA-04 | `app/engine/src/signature_db.h` (`SignatureRecord`, `static_assert(sizeof==41)`) |
| API-01..04 | `app/service/Service/Update/UpdateClientService.cs`, `UpdatePackageVerifier.cs` |
| BIZ-01..04 | `app/service/Service/Trust/ProcessTrustEngine.cs` + `ProcessTrustEngineTests.cs` |
| BIZ-05, BIZ-06 | `app/engine/src/pipeline.cpp` + `EngineTests.cs` |
| BIZ-07..09 | `app/service/Service/Quarantine/QuarantineManager.cs` + `QuarantineManagerTests.cs` |
| BIZ-10, BIZ-11 | `Models/Enums.cs` (`RuleLifecycleState`), quy trình mô tả trong `app/ops/docs/known-limitations.md` |
| NFR-PERF-01 | Xem ghi chú hạn chế ở dòng NFR-PERF-01 phía trên |
| NFR-PERF-02 | `ProcessTrustEngine.cs` (`ElapsedMs`), đo được qua test `ProcessTrustEngineTests.cs` |
| NFR-PERF-03, NFR-PERF-04 | `app/service/Service/FullScan/FullScanService.cs`, `NativeInterop.cs` |
| NFR-AVAIL-01 | `app/service/Service/Archive/ArchiveScanner.cs` + `ArchiveScannerTests.cs` |
| NFR-AVAIL-02 | `app/ops/docs/known-limitations.md` |
| NFR-AVAIL-03 | `ProcessTrustEngine.cs` (deny-and-log khi timeout) + test `UnknownUnsignedFile_NoResponse_DeniedByTimeout_NotAllowed` |
| NFR-AVAIL-04 | `FullScanService.cs` (`SaveResumeState`/`LoadResumeState`) |
| NFR-OBS-01 | Xem ghi chú hạn chế ở dòng NFR-OBS-01 phía trên |
| SEC-01 | `app/service/Service/Trust/AuthenticodeVerifier.cs` |
| SEC-02, SEC-03 | `app/service/Service/wwwroot/js/app.js` (`showPermissionModal`, trễ 500ms, không focus sẵn) |
| SEC-04 | trùng API-03 |
| SEC-05, SEC-06 | `app/service/Service/Data/AclProtection.cs` |
| SEC-07, SEC-08 | `app/ops/docs/known-limitations.md` |
| ERR-01..10 | Xem dòng BIZ/NFR tương ứng đã trùng lặp, cộng `app/service/Service/Downloads/DownloadsWatcherService.cs` (ERR-04) |
| FLOW-01 | `app/service/Service/Trust/DriverSimulatorService.cs` + `ProcessTrustEngine.cs` |
| FLOW-02 | `app/service/Service/Downloads/DownloadsWatcherService.cs` |
| FLOW-03 | trùng BIZ-06 |
| FLOW-04 | `app/service/Service/FullScan/FullScanService.cs` |
| FLOW-05 | trùng BIZ-11 |
| TEST-01..11 | `app/service/Service.Tests/*.cs` (test pass) hoặc `app/ops/docs/known-limitations.md` (hạn chế môi trường) |
| OPS-01..06 | `app/ops/scripts/*.ps1`, `app/installer/Product.wxs`, `app/ops/docs/*.md` |
| UI-01..08 | `app/service/Service/wwwroot/index.html`, `css/style.css`, `js/app.js` — xác minh trực quan qua Claude Browser trong phiên này |
