# Definition of Done — trạng thái theo tests/07-kiem-thu.md

Theo đúng yêu cầu của spec (`tests/07-kiem-thu.md` mục Definition of Done):
*"nếu một mục chưa đạt, phải được ghi nhận rõ ràng thành hạn chế đã biết
thay vì bị bỏ sót âm thầm"*. Bảng dưới đối chiếu từng tiêu chí.

| Tiêu chí DoD | Trạng thái | Ghi chú |
|---|---|---|
| Driver ELAM/minifilter đã qua attestation/WHQL | ❌ Chưa đạt — hạn chế đã biết | Không có WDK, EV Code Signing Certificate, hay tài khoản Microsoft Partner Center trong môi trường này. Mã nguồn driver đã viết đầy đủ ở `app/drivers/`, chưa biên dịch/ký. |
| Rule heuristic/YARA đã qua log-only đủ lâu | ⚠️ Cơ chế đã cài đặt, chưa có dữ liệu vận hành thật | State machine `LogOnly → Enforce` được mô hình trong `RuleLifecycleState` (`Models/Enums.cs`); chưa có rule mới nào cần enforce vì đây là bản đầu tiên — không có gì để "log-only đủ lâu" trên. |
| Quarantine đã test khôi phục (file thường + file hệ thống) | ✅ Đạt | `QuarantineManagerTests.cs`: cả hai kịch bản (`NormalFile_QuarantinedThenRestored...`, `SystemProtectedPath_ClassifiedAsPendingManualConfirmation`) pass. |
| Update service đã test incremental delta + fallback full + verify chữ ký | ✅ Đạt | `UpdateClientServiceTests.cs`: 3 test pass (delta tuần tự, fallback full khi >30 phiên bản, từ chối gói ký sai). |
| Service chạy PPL Antimalware (hoặc hạn chế ghi nhận) | ❌ Chưa đạt — hạn chế đã biết | Cần certificate EKU "Antimalware" từ Microsoft (chỉ cấp qua chương trình đối tác). Service hiện chạy như Windows Service thường (`LocalSystem`), CHƯA có PPL. Đây là rủi ro thật: một tiến trình Administrator có thể tắt service theo cách mà bản PPL đầy đủ sẽ ngăn được. |
| Trạng thái đăng ký MVI/Windows Security Center đã quyết định rõ | ❌ Chưa đăng ký — hạn chế đã biết | Chưa nộp hồ sơ MVI (cần chứng nhận từ phòng test độc lập AV-Test/AV-Comparatives/ICSA Labs trước). Nếu phát hành ở trạng thái này, Windows Defender sẽ vẫn tự bật song song → khả năng tranh chấp lock file (ERR-WSC-01). Tài liệu cài đặt cho người dùng PHẢI nêu rõ điều này (xem `app/ops/docs/user-install-notes.md`). |
| Bộ test EICAR chạy qua cả 3 luồng (full scan, Downloads, real-time) | ⚠️ Đạt 2/3 | Full scan: đạt (`EngineTests.cs` + `/api/scan/file` demo qua UI thật, xem transcript phiên làm việc). Downloads: đạt về mặt logic (`DownloadsWatcherService` dùng chung pipeline đã test), chưa test end-to-end tự động hoá (cần copy file thật vào thư mục Downloads và quan sát). Real-time (minifilter): ❌ không thể test — cần driver kernel-mode đã nạp thật (xem TC-03 trong `app/drivers/README.md`). |

## Tóm tắt hạn chế theo nguyên nhân gốc

1. **Không có WDK** → không biên dịch được driver kernel-mode thật (ELAM,
   minifilter). Real-time protection hiện chỉ có lớp fallback user-mode
   (`DriverSimulatorService`, dùng `Win32_ProcessStartTrace`) — quan sát
   SAU khi tiến trình đã tạo, yếu hơn hẳn so với chặn đồng bộ TRƯỚC khi
   tạo mà driver thật cung cấp.
2. **Không có EV Code Signing Certificate** → không ký được driver/installer
   cho bản phát hành thật; không thể tự bảo vệ service bằng Protected
   Process Light (PPL) mức Antimalware.
3. **Không có tư cách thành viên MVI** → chưa đăng ký được với Windows
   Security Center; xung đột tiềm ẩn với Windows Defender nếu triển khai
   thật mà chưa qua bước này.
4. **Không có phần cứng HDD vật lý / volume FAT32 thật** trong môi trường
   test → NFR-PERF-03 (tối ưu HDD) và nhánh fallback FAT32 của TC-08 chỉ
   được test logic quyết định, chưa benchmark trên phần cứng thật (TC-11).

Không mục nào trong danh sách trên bị bỏ sót khỏi `features.md` — mỗi mục
đều có ID tương ứng đã đánh dấu `[HẠN CHẾ ĐÃ BIẾT]` trong checklist.
