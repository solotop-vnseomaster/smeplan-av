# Kernel-mode drivers (ELAM + Minifilter + phần mở rộng) — mã nguồn tham chiếu

**[HẠN CHẾ ĐÃ BIẾT — đọc trước]**: Năm driver/phần mở rộng driver trong
thư mục này (`elam/`, `minifilter/`, `wfp-firewall/`,
`process-hollowing-guard/`) là mã nguồn C tham chiếu, viết đúng theo mô tả
kỹ thuật trong `spec-output/v1/modules/02-kien-truc.md`, các tài liệu liên
quan, và `tai lieu moi.txt` (tài liệu mở rộng — firewall/ransomware/process
hollowing). Chúng **chưa được biên dịch, ký số, hay nạp thử** trong phiên
làm việc này vì môi trường thực thi không có:

- Windows Driver Kit (WDK) khớp phiên bản Windows SDK — chỉ có Windows SDK
  (qua Visual Studio 2022 Community), không có các header kernel-mode
  (`fltKernel.h`, `ntddk.h`, `wdmsec.h`...) hay `.lib` tương ứng (`FltMgr.lib`,
  `ntoskrnl.lib`...).
- EV Code Signing Certificate lưu trên USB token phần cứng (bắt buộc theo
  chuẩn EV, không thể mô phỏng bằng self-signed certificate cho bản phát
  hành thật).
- Tài khoản Microsoft Partner Center đã xác minh danh tính công ty, và tư
  cách thành viên chương trình ELAM/Antimalware EKU cùng Microsoft Virus
  Initiative (MVI).

Đây đúng là những phụ thuộc bên ngoài mà chính tài liệu spec
(`ops/08-trien-khai.md`, `security/09-bao-mat.md`) đã liệt kê là bắt buộc —
không có ngoại lệ self-signed cho máy bật Secure Boot mặc định. Theo
Definition of Done trong `tests/07-kiem-thu.md`, hạng mục này được ghi
nhận rõ ràng ở đây thay vì bỏ sót âm thầm.

## Để biên dịch thật (khi có đủ điều kiện)

1. Cài Visual Studio kèm workload "Desktop development with C++".
2. Cài Windows Driver Kit (WDK) khớp đúng phiên bản Windows SDK đang dùng
   (tải riêng từ Hardware Dev Center — WDK không tự cài kèm Visual Studio).
3. Mở từng thư mục driver trong Visual Studio dưới dạng dự án "Kernel Mode
   Driver, Empty (KMDF)"/"Filter Driver" tương ứng, thêm các file `.c`/`.h`
   đã có sẵn ở đây vào dự án đó (các file này viết đúng chuẩn API nhưng
   chưa đóng gói `.vcxproj` vì không thể tạo project WDK hợp lệ mà không có
   chính WDK cài trên máy).
4. Bật `bcdedit /set testsigning on` + tạo self-signed test certificate để
   nạp thử trên máy dev (`ops/scripts/enable-dev-testsigning.ps1`).
5. Build Release, ký bằng EV Code Signing Certificate, nộp qua Microsoft
   Partner Center để lấy attestation/WHQL signing — xem
   `spec-output/v1/ops/08-trien-khai.md` mục 3 cho đầy đủ 12 bước.

## `minifilter/` — Real-time Protection

Mức độ tin cậy kỹ thuật: **cao**. Filter Manager (`fltmgr.sys`) là API
kernel-mode được tài liệu hoá công khai đầy đủ bởi Microsoft; các hàm dùng
trong `minifilter.c` (`FltRegisterFilter`, `FltCreateCommunicationPort`,
`PsSetCreateProcessNotifyRoutineEx`, `FltSendMessage`...) đều là API chuẩn,
có chữ ký hàm chính xác theo WDK. Logic nghiệp vụ (chặn đồng bộ nhóm file
thực thi, hỏi service qua communication port, mặc định deny-and-log khi
timeout) bám sát `flows/11-luong-xu-ly.md` và `business-rules/05-nghiep-vu.md`.

## `minifilter/` mở rộng — Ransomware pre-write/rename hook (EXT-RW-01)

`minifilter.c`/`minifilter.h` được **mở rộng** trong phiên này (không tạo
driver riêng) để thêm `IRP_MJ_WRITE` + `IRP_MJ_SET_INFORMATION` vào cùng
`Callbacks[]` đã có — hợp lý vì đây vẫn là cùng một Filter Manager
instance, chỉ đăng ký thêm loại IRP cần chặn. Điểm khác biệt cốt lõi so
với `RansomwareGuardService.cs` (dùng `FileSystemWatcher` user-mode làm
fallback): hook kernel này chặn được **TRƯỚC** khi ghi/đổi tên xảy ra thật
sự, cho service cơ hội snapshot bản sạch đúng thời điểm, đúng như kiến
trúc lý tưởng mà tài liệu mô tả (`RansomwareGuardService.cs` đã ghi rõ
đây là hạn chế của cách tiếp cận user-mode). Danh sách thư mục bảo vệ được
service **PUSH xuống** qua `MessageNotifyCallback` mới thêm trên cùng
communication port (khác hướng với `FltSendMessage` sẵn có — driver hỏi
service — đây là service chủ động gửi xuống driver).

## `wfp-firewall/` — Application Firewall qua WFP callout (EXT-FW-01/04)

Mức độ tin cậy kỹ thuật: **trung bình**. WFP (Windows Filtering Platform)
là API kernel-mode được tài liệu hoá công khai đầy đủ
(`FwpsCalloutRegister3`, `FwpmCalloutAdd0`, `FwpmFilterAdd0`,
`FWPM_LAYER_ALE_AUTH_CONNECT_V4`...), nhưng phần cấu hình chi tiết (bật
`FWPM_LAYER_FLAG_QUERY_APP_ID` để `FWPS_METADATA_FIELD_PROCESS_PATH` được
điền) bị lược bớt trong bản tham chiếu để giữ trọng tâm vào luồng quyết
định chính — **[ĐỀ XUẤT: CẦN KIỂM TRA THÊM]** trước khi biên dịch thật,
đối chiếu trực tiếp với sample `Windows-driver-samples/network/trans`
hoặc `WFPSampler` chính thức của Microsoft. Driver này là một `.sys`
**riêng**, giao tiếp với service qua `IoCreateDevice`/IOCTL (khác cơ chế
`FltCreateCommunicationPort` của minifilter, vì WFP callout không phải
minifilter). Điểm thiết kế quan trọng nhất — vì sao `classifyFn` không
thể "hỏi đồng bộ" người dùng như tài liệu gốc gợi ý — được ghi chi tiết ở
đầu `wfp_callout.c`.

## `process-hollowing-guard/` — ObRegisterCallbacks (EXT-EXP-02)

Mức độ tin cậy kỹ thuật: **trung bình**. Bám sát đúng ví dụ C trong
`tai lieu moi.txt` (`PreOperationCallback` kiểm tra
`PROCESS_VM_WRITE`/`PROCESS_VM_OPERATION` trên `PsProcessType`). Hai hàm
tài liệu chỉ nêu tên mà không đặc tả (`IsUnrelatedProcess`,
`IsWhitelistedDebuggerOrTool`) được triển khai cụ thể với lý do ghi rõ ở
đầu `ob_callbacks.c` — quan hệ cha-con qua chính
`PsSetCreateProcessNotifyRoutineEx` driver này tự đăng ký, và whitelist
được service PUSH xuống (không thể tra SQLite/WinVerifyTrust từ kernel).
Luôn trả `OB_PREOP_SUCCESS` — không bao giờ chặn handle, chỉ ghi nhận,
đúng nguyên tắc "log-only trước khi enforce" mà tài liệu nhấn mạnh cho
mọi module mới.

## `elam/` — Early Launch Antimalware

Mức độ tin cậy kỹ thuật: **trung bình, có giới hạn công khai**. Cơ chế
ELAM là một bề mặt API rất hẹp, chủ yếu tài liệu hoá qua chương trình đối
tác Microsoft chứ không phải MSDN công khai đầy đủ như minifilter. Phần
chắc chắn đúng (driver boot-start, certificate EKU riêng, resource
`MSElamCertificateInfo` làm cơ chế phân loại chính) được viết trong
`elam.c`/`elam.h`/`elam.rc`; phần còn mơ hồ (ví dụ có callback runtime tùy
biến hay không ngoài resource khai báo) được **ghi chú rõ là chưa có bằng
chứng kỹ thuật cụ thể** thay vì bịa ra một API không chắc chắn — khi triển
khai thật, đối chiếu trực tiếp với sample chính thức của Microsoft
(`Windows-driver-samples/general/elam` trên GitHub).

## Quy ước đặt tên hàm (đã đồng bộ giữa 4 driver)

Mỗi driver dùng một prefix `SmePlanAv<Mã driver>` riêng cho các hàm export/
dùng trong `FLT_OPERATION_REGISTRATION`/`DriverObject->MajorFunction`, để
tránh trùng tên khi debug nhiều driver cùng lúc (WinDbg symbol resolution)
và để nhất quán khi đọc chéo giữa các file:

- `minifilter/` → `SmePlanAvMf...` (vd. `SmePlanAvMfPreCreateCallback`)
- `wfp-firewall/` → `SmePlanAvFw...` (vd. `SmePlanAvFwDeviceControl`)
- `process-hollowing-guard/` → `SmePlanAvOb...` (vd. `SmePlanAvObPreOperationCallback`)
- `elam/` → `SmePlanAvElam...` (vd. `SmePlanAvElamUnload`)

Ngoại lệ duy nhất: `DriverEntry` giữ nguyên tên (điểm vào driver bắt buộc
theo quy ước WDK/INF, không được đổi tên). Trước đây `minifilter.c` không
theo quy ước này (hàm không có prefix nào, vd. `PreCreateCallback` trần) và
`elam.c` dùng `Elam` thay vì `SmePlanAvElam` — đã đồng bộ lại cả hai cho
khớp với `wfp-firewall/`/`process-hollowing-guard/` vốn đã theo đúng quy
ước từ đầu.

## Kiểm thử (tests/07-kiem-thu.md)

TC-03 (minifilter chặn mở file EICAR) và TC-07 (test signing) yêu cầu
driver đã nạp thật trên máy Windows có quyền Administrator — không thực
thi được trong môi trường phiên làm việc này. Test đơn vị thay thế cho
logic quyết định (không phải cho chính cơ chế chặn kernel) nằm trong
`app/service/Service.Tests/ProcessTrustEngineTests.cs`, dùng chung state
machine `ProcessTrustEngine` mà driver thật sẽ gọi tới qua communication
port.
