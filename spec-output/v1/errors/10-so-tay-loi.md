---
id: "so-tay-loi"
kind: error-catalog
title: "Sổ tay lỗi"
spec_version: "v1"
module: "so-tay-loi"
created_at: "2026-08-01T15:55:12.591571+00:00"
sources:
  - { source_id: "S1", loc: "chunk#40 Những lỗi thường gặp khi tự xây antivirus", hash: "f337bd98c9a969567f2a3a2849d5f0d8c8aeb664fa08dd3143032ae6d671f345" }
  - { source_id: "S1", loc: "chunk#26 Ký số driver với Microsoft", hash: "86cf57e26ce6aa8219dd02178bb6368ecdabd98941ecb7feaeadd677ee519848" }
  - { source_id: "S1", loc: "chunk#1 Tổng quan kiến trúc app antivirus Windows", hash: "b142a39c6bc430bae5289b9f8ef71a468f7f5d0d7b27c4ceb33d86a64a77f17f" }
  - { source_id: "S1", loc: "chunk#30 Cập nhật cơ sở dữ liệu virus tự động", hash: "50e50f2343f3f260ae921b918770fb538289ed51bf6ecb9d4f2f5465cdd3ba87" }
  - { source_id: "S1", loc: "chunk#37 Logging và báo cáo cho người dùng", hash: "538bc9459381222d16e8d5bf3c9692b1b3e9d087e2496b7d0f7dc738f0f90aad" }
  - { source_id: "S1", loc: "chunk#25 Viết Early Launch Antimalware driver cơ bản", hash: "f41b68505282e58b734c1adc5e3581a2968329011499fedca868e830669419c2" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#24 Giảm độ trễ khi quét theo thời gian thực", hash: "c95bc499a4f1bea0c0989dab031faddacda3d388d59691bca876214cf8810ac0" }
  - { source_id: "S1", loc: "chunk#9 Giao diện tùy biến quyền cho ứng dụng bên thứ 3", hash: "03948fea0e449152ae61d582b0d81821a5bf18aaaabb6079dcf3fcfca9c22cdf" }
  - { source_id: "S1", loc: "chunk#7 Giới hạn của whitelist theo chữ ký số", hash: "40ff3f848503ba100ca44a546f2f028712d34596abfe0cb201f97edc9ebd80a1" }
  - { source_id: "S1", loc: "chunk#14 Xây dựng cơ sở dữ liệu signature dựa trên hash", hash: "8de40e7324bdcaa66f177c8e534b2f37953c2d4ca49074643ede798407cddead" }
  - { source_id: "S1", loc: "chunk#27 Giám sát riêng thư mục Downloads", hash: "2c250a52583f3208242ad843aef00370be7ca79dbfbffe35b3fd4d92763dc4f0" }
  - { source_id: "S1", loc: "chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa", hash: "bcf95a76fd630c410fa5205a4cb67cf644f19f86b3c5e705b59ccecbe07ef035" }
  - { source_id: "S1", loc: "chunk#18 Tối ưu hiệu năng khi quét sâu", hash: "6651987e1a5f94a302fefea430b892f7713846471fc366e723235c419fcf9f23" }
  - { source_id: "S1", loc: "chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ", hash: "80eee532e66bbb3dcf94905b34d298864ce356a9f5347704f9d66c9d38f3f976" }
  - { source_id: "S1", loc: "chunk#29 Cơ chế Quarantine cách ly file nghi ngờ", hash: "c0d0d265c33eefbe75d7d1c6ec0772dae67f0eeefa2112b992b52c7b021289ad" }
  - { source_id: "S1", loc: "chunk#16 Tích hợp YARA rules vào scan engine", hash: "09f3633e6e1995108b8c8a01daa26dd7a383faf54cee9139abed99d3278ad6b4" }
  - { source_id: "S1", loc: "chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender", hash: "5803b7b4e05da0cb47c25597863ce39af922cf6099f3fd5b04bcf74f101eff07" }
  - { source_id: "S1", loc: "chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường", hash: "e44c7e7f08017f68ab3e6a509472b314de4aa80c6e8173374d4bc431d09998bf" }
  - { source_id: "S1", loc: "chunk#39 Đóng gói, ký số installer và checklist phát hành", hash: "4237edd642b7c565dd067daad5463c98cbdac0dd3656d4aea610d1f9c301badf" }
---

# Sổ tay lỗi

Hệ thống là một ứng dụng desktop/driver Windows, không phải dịch vụ HTTP, nên "mã lỗi"
dưới đây là mã trạng thái Windows API, verdict/flag nội bộ, và các lỗi thiết kế thường
gặp có bằng chứng trong tài liệu nguồn — nhóm theo domain/module.

## Mục lục
- [Whitelist & Quyết định tiến trình](#whitelist--quyết-định-tiến-trình)
- [Real-time Protection](#real-time-protection)
- [Full/Deep Scan](#fulldeep-scan)
- [Quét file nén](#quét-file-nén)
- [Quarantine & False Positive](#quarantine--false-positive)
- [Ký số driver & Phát hành](#ký-số-driver--phát-hành)
- [Windows Security Center / Windows Defender](#windows-security-center--windows-defender)
- [Update Service](#update-service)

## Whitelist & Quyết định tiến trình

| Mã lỗi/tình huống | Message/mô tả | Nguyên nhân | Cách xử lý khuyến nghị |
|---|---|---|---|
| ERR-TRUST-01 | Whitelist theo tên file bị mạo danh (ví dụ `explorer.exe` giả) | Dùng tên file hoặc đường dẫn làm căn cứ chính để coi một tiến trình là app Windows gốc — cả hai đều là chuỗi văn bản mà bất kỳ file nào cũng copy được [S1] | Dùng whitelist ba lớp: chữ ký số Authenticode hợp lệ + publisher khớp chính xác + vị trí thư mục được WRP bảo vệ, kết hợp cả ba chứ không tách rời [S1] |

## Real-time Protection

| Mã lỗi/tình huống | Message/mô tả | Nguyên nhân | Cách xử lý khuyến nghị |
|---|---|---|---|
| `STATUS_ACCESS_DENIED` | Trả về trong `PreCreateCallback` khi một thao tác mở file bị chặn | Service nền trả quyết định BLOCK qua `FltSendMessage` cho driver [S1] | Đây là hành vi mong đợi khi phát hiện chặn, không phải lỗi hệ thống; driver set `Data->IoStatus.Status = STATUS_ACCESS_DENIED` và trả `FLT_PREOP_COMPLETE` [S1] |
| ERR-RT-01 | Người dùng cảm nhận giật lag ngay từ lần dùng thử đầu, dẫn tới gỡ cài đặt | Quét đồng bộ mọi loại file (kể cả ảnh, văn bản) qua `IRP_MJ_CREATE`, gửi xuống service chờ kết quả trước khi cho mở [S1] | Chỉ chặn đồng bộ nhóm file có khả năng thực thi trực tiếp (`.exe`, `.dll`, `.ps1`, `.bat`, `.scr`, magic bytes `MZ`); file dữ liệu thông thường cho mở ngay và quét bất đồng bộ [S1] |

## Full/Deep Scan

| Mã lỗi/tình huống | Message/mô tả | Nguyên nhân | Cách xử lý khuyến nghị |
|---|---|---|---|
| `ERROR_SHARING_VIOLATION` | Trả về khi polling `CreateFile` mở exclusive thất bại trên một file đang được ghi dở dang | Một tiến trình khác (ví dụ trình duyệt) vẫn giữ handle ghi trên file [S1] | Tiếp tục polling theo chu kỳ ngắn (ví dụ mỗi 200ms, timeout tổng sau 30 giây với file lớn); không coi là lỗi vĩnh viễn [S1] |
| `ScanError` | Verdict trả về khi engine không đọc được file, ví dụ file bị khóa hoặc hỏng [S1] | File bị khóa độc quyền bởi tiến trình khác, hoặc file bị hỏng [S1] | Không được mặc định coi `ScanError` là `Clean` khi gặp lỗi này [S1] |
| ERR-SCAN-01 | Tính năng "deep scan" gây treo máy trên phần cứng phổ thông trong thực tế | Bỏ qua việc đo hiệu năng trên phần cứng thật (HDD cũ) trước khi ship, chỉ test trên máy dev cấu hình cao với SSD NVMe [S1] | Benchmark full scan trên cả HDD và SSD; áp dụng các kỹ thuật tối ưu hiệu năng khi quét sâu (hạ I/O priority, phát hiện idle, sắp xếp theo LBA trên HDD) trước khi ship [S1] |

## Quét file nén

| Mã lỗi/tình huống | Message/mô tả | Nguyên nhân | Cách xử lý khuyến nghị |
|---|---|---|---|
| `FLAG_SUSPICIOUS_ZIPBOMB` | Trả về khi vượt tỷ lệ nén tối đa hoặc trần dung lượng giải nén tuyệt đối trong lúc giải nén streaming [S1] | File nén có tỷ lệ nén bất thường (ví dụ vượt 100 lần) hoặc tổng dung lượng giải nén vượt mốc cố định (ví dụ 1GB) [S1] | Dừng giải nén ngay, gắn cờ `Suspicious` (không tự động `Malicious`); cảnh báo và để người dùng quyết định vì file nén hợp lệ nhưng rất lớn vẫn có thể vô tình chạm ngưỡng [S1] |
| `FLAG_SUSPICIOUS_TOO_DEEP` | Trả về khi vượt độ sâu lồng nhau tối đa của file nén (ví dụ 5 lớp) [S1] | File nén trong file nén nhiều lớp bất thường [S1] | Dừng và gắn cờ nghi ngờ thay vì đệ quy vô hạn [S1] |

## Quarantine & False Positive

| Mã lỗi/tình huống | Message/mô tả | Nguyên nhân | Cách xử lý khuyến nghị |
|---|---|---|---|
| ERR-QUAR-01 | Xóa nhầm vĩnh viễn một công cụ hợp lệ của người dùng, không có đường lùi | Xử lý kết quả `Suspicious` giống hệt `Malicious` (xóa ngay, không cho khôi phục), trong khi heuristic/YARA luôn có tỷ lệ false positive khác không [S1] | Không bao giờ tự động xóa file `Malicious` ngay lập tức; luôn quarantine trước, chỉ xóa vĩnh viễn sau xác nhận thủ công của người dùng [S1] |

## Ký số driver & Phát hành

| Mã lỗi/tình huống | Message/mô tả | Nguyên nhân | Cách xử lý khuyến nghị |
|---|---|---|---|
| ERR-REL-01 | Driver bị Microsoft Partner Center từ chối ký, tốn thời gian xử lý lại | Nộp driver lên Partner Center mà chưa tự phát hiện lỗi trước [S1] | Chạy bộ test Hardware Lab Kit (HLK) cục bộ trước khi nộp để tự phát hiện lỗi sớm [S1] |
| ERR-REL-02 | Lịch phát hành bị trễ hàng tháng dù phần code kỹ thuật đã xong từ lâu | Coi driver signing và tham gia MVI là bước hành chính có thể làm sau cùng; cả hai đều có thời gian xử lý tính bằng tuần [S1] | Đăng ký tài khoản Microsoft Partner Center và nộp hồ sơ MVI ngay từ giai đoạn phát triển, chạy song song với việc viết code, không đợi tới gần phát hành [S1] |

## Windows Security Center / Windows Defender

| Mã lỗi/tình huống | Message/mô tả | Nguyên nhân | Cách xử lý khuyến nghị |
|---|---|---|---|
| ERR-WSC-01 | Hai minifilter driver tranh chấp lock trên cùng file, gây lỗi khó chẩn đoán hoặc giảm hiệu năng đáng kể | App chưa được chấp nhận vào Microsoft Virus Initiative (MVI) nên Windows Defender vẫn coi máy "không có bảo vệ của bên thứ 3" và tiếp tục tự bật real-time protection song song [S1] | Tham gia chương trình MVI để được đăng ký hợp lệ trong Windows Security Center; trong giai đoạn dev/test, loại trừ tạm thời thư mục cài đặt và tiến trình app khỏi phạm vi quét Defender bằng PowerShell quyền Administrator (`Add-MpPreference`) — chỉ dùng cho máy dev/test, không áp dụng cho người dùng cuối [S1] |

## Update Service

| Mã lỗi/tình huống | Message/mô tả | Nguyên nhân | Cách xử lý khuyến nghị |
|---|---|---|---|
| ERR-UPD-01 | CSDL bị thao túng khiến phần mềm hợp lệ bị nhận diện là mã độc hoặc ngược lại (đã từng xảy ra thực tế với vài sản phẩm bảo mật) | Máy chủ CDN hoặc kênh phân phối CSDL bị xâm nhập, đẩy một CSDL giả xuống máy người dùng [S1] | Verify chữ ký số mọi gói CSDL (full hoặc delta) bằng `WinVerifyTrust` trước khi áp dụng, ký bằng chính certificate của công ty [S1] |
| ERR-UPD-02 | CSDL ở trạng thái ghi dở dang nếu update service bị crash hoặc mất điện giữa chừng | Ghi trực tiếp đè lên file CSDL đang dùng thay vì qua file tạm [S1] | Ghi CSDL mới vào một file tạm, rồi đổi tên hoán đổi nguyên tử bằng `MoveFileEx` với `MOVEFILE_REPLACE_EXISTING` để thay thế file cũ [S1] |


## Nguồn tham chiếu
- S1 (final.md, chunk#40 Những lỗi thường gặp khi tự xây antivirus)
- S1 (final.md, chunk#26 Ký số driver với Microsoft)
- S1 (final.md, chunk#1 Tổng quan kiến trúc app antivirus Windows)
- S1 (final.md, chunk#30 Cập nhật cơ sở dữ liệu virus tự động)
- S1 (final.md, chunk#37 Logging và báo cáo cho người dùng)
- S1 (final.md, chunk#25 Viết Early Launch Antimalware driver cơ bản)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#24 Giảm độ trễ khi quét theo thời gian thực)
- S1 (final.md, chunk#9 Giao diện tùy biến quyền cho ứng dụng bên thứ 3)
- S1 (final.md, chunk#7 Giới hạn của whitelist theo chữ ký số)
- S1 (final.md, chunk#14 Xây dựng cơ sở dữ liệu signature dựa trên hash)
- S1 (final.md, chunk#27 Giám sát riêng thư mục Downloads)
- S1 (final.md, chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa)
- S1 (final.md, chunk#18 Tối ưu hiệu năng khi quét sâu)
- S1 (final.md, chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ)
- S1 (final.md, chunk#29 Cơ chế Quarantine cách ly file nghi ngờ)
- S1 (final.md, chunk#16 Tích hợp YARA rules vào scan engine)
- S1 (final.md, chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender)
- S1 (final.md, chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường)
- S1 (final.md, chunk#39 Đóng gói, ký số installer và checklist phát hành)
