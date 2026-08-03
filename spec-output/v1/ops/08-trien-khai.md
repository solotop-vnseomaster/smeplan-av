---
id: "trien-khai"
kind: deployment
title: "Triển khai & Vận hành"
spec_version: "v1"
module: "trien-khai"
created_at: "2026-08-01T15:51:52.987922+00:00"
sources:
  - { source_id: "S1", loc: "chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender", hash: "5803b7b4e05da0cb47c25597863ce39af922cf6099f3fd5b04bcf74f101eff07" }
  - { source_id: "S1", loc: "chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", hash: "4f3ee047f0e2b9eff547e6871b1da177a8c0f97319d67e1f99089eb8b83d305c" }
  - { source_id: "S1", loc: "chunk#4 Thiết lập môi trường phát triển", hash: "beaf2b68b93b9f502335ca2eca154631972f52fddf86d0463ff3633378aa4d1b" }
  - { source_id: "S1", loc: "chunk#41 Kết luận", hash: "3eec6601c076d2c8892032d28b2554d458259a89bb1b7db59f4c6a37b4d41d6a" }
  - { source_id: "S1", loc: "chunk#39 Đóng gói, ký số installer và checklist phát hành", hash: "4237edd642b7c565dd067daad5463c98cbdac0dd3656d4aea610d1f9c301badf" }
  - { source_id: "S1", loc: "chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật", hash: "738f35b68d00a2f40c9d8bee712457df7a70bd4107526f29106a9b8ede50cf74" }
  - { source_id: "S1", loc: "chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường", hash: "e44c7e7f08017f68ab3e6a509472b314de4aa80c6e8173374d4bc431d09998bf" }
  - { source_id: "S1", loc: "chunk#38 Đóng gói, ký số installer và checklist phát hành", hash: "60cfca34d7df11c73c83d6274602016ded4c89187fa0bb95f67bce7df25f722b" }
  - { source_id: "S1", loc: "chunk#10 Lưu trữ và quản lý rule phân quyền", hash: "2eef23f72066b39840103d0f6b4062d1b7da7382f05a22662890b36504d838f9" }
  - { source_id: "S1", loc: "chunk#40 Những lỗi thường gặp khi tự xây antivirus", hash: "f337bd98c9a969567f2a3a2849d5f0d8c8aeb664fa08dd3143032ae6d671f345" }
  - { source_id: "S1", loc: "chunk#8 Thiết kế chính sách kiểm soát ứng dụng bằng AppLocker/WDAC", hash: "d5236d1041a2aeab5679f1aa092a0a979342c01c9e86f60b1f7302bc8dbde2fa" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#7 Giới hạn của whitelist theo chữ ký số", hash: "40ff3f848503ba100ca44a546f2f028712d34596abfe0cb201f97edc9ebd80a1" }
  - { source_id: "S1", loc: "chunk#26 Ký số driver với Microsoft", hash: "86cf57e26ce6aa8219dd02178bb6368ecdabd98941ecb7feaeadd677ee519848" }
  - { source_id: "S1", loc: "chunk#37 Logging và báo cáo cho người dùng", hash: "538bc9459381222d16e8d5bf3c9692b1b3e9d087e2496b7d0f7dc738f0f90aad" }
  - { source_id: "S1", loc: "chunk#16 Tích hợp YARA rules vào scan engine", hash: "09f3633e6e1995108b8c8a01daa26dd7a383faf54cee9139abed99d3278ad6b4" }
  - { source_id: "S1", loc: "chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ", hash: "80eee532e66bbb3dcf94905b34d298864ce356a9f5347704f9d66c9d38f3f976" }
  - { source_id: "S1", loc: "chunk#12 Luồng xử lý khi một ứng dụng thực thi", hash: "21565980c6961104b59cc82412e55d2b9a3571deb663d93a41f6b4bc5f69a825" }
  - { source_id: "S1", loc: "chunk#5 Nguyên tắc mặc định tin cậy ứng dụng gốc Windows", hash: "092c498ec704be0cb77634e0ebf538fbc1f968c8fca05166290df872ff02ba23" }
  - { source_id: "S1", loc: "chunk#25 Viết Early Launch Antimalware driver cơ bản", hash: "f41b68505282e58b734c1adc5e3581a2968329011499fedca868e830669419c2" }
---

# Triển khai & Vận hành

## Mục lục
- [1. Yêu cầu hạ tầng/dependency](#1-yêu-cầu-hạ-tầngdependency)
- [2. Bảng biến môi trường](#2-bảng-biến-môi-trường)
- [3. Các bước cài đặt/chạy/migration](#3-các-bước-cài-đặtchạymigration)
- [4. Khác biệt cấu hình theo môi trường](#4-khác-biệt-cấu-hình-theo-môi-trường)
- [5. Rollback/khôi phục khi triển khai lỗi](#5-rollbackkhôi-phục-khi-triển-khai-lỗi)

## 1. Yêu cầu hạ tầng/dependency

- Visual Studio (bản Community đủ dùng cho phát triển, cần bản trả phí nếu công ty cần
  hỗ trợ chính thức) kèm hai workload bắt buộc: "Desktop development with C++" (cho scan
  engine và UI C++ nếu có) và ".NET desktop development" (cho WinUI3/WPF và service C#)
  [S1].
- Windows Driver Kit (WDK) khớp đúng phiên bản với Windows SDK đang dùng — WDK không tự
  cài kèm Visual Studio, phải tải riêng từ Hardware Dev Center [S1].
- Self-signed test certificate (`MakeCert`/`New-SelfSignedCertificate`) cho môi trường
  dev [S1]; EV Code Signing Certificate (mua qua Microsoft Partner Center, bắt buộc lưu
  trên USB token phần cứng, không cho export ra file mềm) cho bản phát hành chính thức
  [S1].
- Tài khoản Microsoft Partner Center (mục Hardware), yêu cầu xác minh danh tính công ty
  bằng giấy tờ pháp lý, không chấp nhận tài khoản cá nhân cho việc ký driver antivirus
  [S1].
- Chứng nhận từ một phòng test độc lập được Microsoft công nhận (AV-Test, AV-Comparatives,
  hoặc ICSA Labs) để tham gia chương trình Microsoft Virus Initiative (MVI), điều kiện
  tiên quyết để được đăng ký hiển thị trong Windows Security Center [S1].
- Công cụ đóng gói installer: WiX Toolset hoặc Inno Setup, cả hai hỗ trợ tốt việc cài
  driver kernel-mode kèm ứng dụng [S1].
- Thư viện `libyara` (mã nguồn mở) nhúng vào scan engine [S1]; SQLite cục bộ cho lưu trữ
  rule phân quyền, không cần một hệ quản trị CSDL riêng [S1].

## 2. Bảng biến môi trường

TODO [UNKNOWN] — đây là một ứng dụng desktop/driver Windows, ngữ cảnh được cấp không nêu
bảng biến môi trường runtime dạng key-value (kiểu `.env`); cấu hình được đề cập trong
nguồn là các thiết lập cấp máy/registry (ví dụ chế độ testsigning, đường dẫn CSDL, bảng
rule) chứ không phải biến môi trường ứng dụng.

## 3. Các bước cài đặt/chạy/migration

1. Cài Visual Studio kèm hai workload bắt buộc nêu ở mục 1 [S1].
2. Cài Windows Driver Kit (WDK) khớp phiên bản Windows SDK, sau khi đã có Visual Studio
   vì WDK cắm thêm project template driver vào IDE [S1].
3. Trên máy dev: bật test signing mode bằng `bcdedit /set testsigning on` rồi khởi động
   lại, để nạp được driver tự ký trong lúc phát triển [S1].
4. Tạo self-signed test certificate và đăng ký vào certificate store cục bộ (`Trusted
   Root` và `Trusted Publisher`) để Windows chấp nhận driver ký thử trong quá trình dev
   [S1].
5. Đăng ký sớm tài khoản Microsoft Partner Center (mục Hardware) ngay từ giai đoạn phát
   triển, không đợi tới gần phát hành, vì quy trình xác minh danh tính công ty và mua EV
   Code Signing Certificate thường mất vài ngày đến vài tuần [S1].
6. Mua và cài EV Code Signing Certificate, lưu trên USB token phần cứng theo yêu cầu bắt
   buộc của chuẩn EV [S1].
7. Build driver ở chế độ Release, ký bằng EV Code Signing Certificate [S1].
8. Chạy bộ test Hardware Lab Kit (HLK) cục bộ trước khi nộp lên Partner Center, để tự
   phát hiện lỗi sớm vì mỗi lần nộp và bị từ chối đều tốn thời gian xử lý lại [S1].
9. Nộp driver qua Microsoft Partner Center, chờ kết quả ký chính thức — attestation
   signing thường mất vài giờ đến một ngày; WHQL signing (yêu cầu pass bộ test HLK toàn
   diện trên nhiều cấu hình phần cứng) chậm hơn nhiều nhưng nên chọn ngay từ giai đoạn
   beta nội bộ cho driver cấp antivirus (minifilter, ELAM) vì lỗi ở tầng này có thể gây
   blue screen [S1].
10. Đóng gói installer bằng WiX Toolset hoặc Inno Setup, ký installer bằng CÙNG EV Code
    Signing Certificate đã dùng để ký driver, không dùng certificate khác, vì SmartScreen
    đánh giá độ tin cậy dựa một phần vào uy tín tích lũy của certificate đó qua thời gian
    [S1].
11. Song song, nộp hồ sơ tham gia chương trình Microsoft Virus Initiative (MVI) để được
    cấp quyền đăng ký hiển thị trong Windows Security Center [S1].
12. Trước khi đưa bản build đầu tiên cho người dùng thật ngoài nhóm phát triển, xác nhận
    đủ checklist phát hành (xem tài liệu Kiểm thử, mục Definition of Done): driver đã qua
    attestation/WHQL, rule heuristic/YARA đã qua log-only đủ lâu, quarantine đã test khôi
    phục, update service đã test incremental delta và fallback full download, service đã
    chạy PPL Antimalware (hoặc hạn chế đã ghi nhận), trạng thái đăng ký MVI/WSC đã quyết
    định rõ, bộ test EICAR đã chạy qua cả ba luồng [S1].

## 4. Khác biệt cấu hình theo môi trường

- **Môi trường dev/test**: bật `bcdedit /set testsigning on` để nạp driver tự ký; dùng
  self-signed certificate đăng ký vào `Trusted Root`/`Trusted Publisher`; loại trừ chủ
  động thư mục cài đặt và tiến trình của app khỏi phạm vi quét Windows Defender bằng
  PowerShell quyền Administrator (`Add-MpPreference -ExclusionPath`,
  `-ExclusionProcess`) để hai engine antivirus không tranh chấp lock trên cùng file khi
  app chưa qua MVI [S1].
- **Môi trường phát hành (production)**: không được dùng testsigning — driver phải ký
  qua Microsoft (attestation signing hoặc WHQL); không được yêu cầu người dùng cuối tự
  chạy lệnh loại trừ Windows Defender cho một app chưa được công nhận chính thức, vì làm
  vậy tắt một lớp bảo vệ thật của Windows mà không có gì thay thế đáng tin cậy tương
  đương cho tới khi app đã qua MVI [S1]; nếu bản phát hành vẫn chưa qua MVI, tài liệu
  hướng dẫn cài đặt cho người dùng cần nêu rõ khả năng xung đột với Windows Defender và
  cách xử lý [S1].
- **Môi trường staging**: TODO [UNKNOWN] — không có bằng chứng riêng cho một môi trường
  staging tách biệt trong ngữ cảnh được cấp.

## 5. Rollback/khôi phục khi triển khai lỗi

- Nếu driver bị Microsoft Partner Center từ chối ký (attestation hoặc WHQL), quy trình
  là sửa lỗi và nộp lại từ bước build Release; không có cơ chế tự động, mỗi lần nộp và bị
  từ chối đều tốn thời gian xử lý lại nên khuyến nghị chạy bộ test HLK cục bộ trước khi
  nộp để tự phát hiện lỗi sớm [S1].
- Nếu bản phát hành chưa qua MVI/Windows Security Center và xảy ra xung đột với Windows
  Defender (hai minifilter driver tranh chấp lock trên cùng file, gây lỗi khó chẩn đoán
  hoặc giảm hiệu năng), biện pháp là tài liệu hướng dẫn cài đặt phải nêu rõ khả năng xung
  đột và cách xử lý cho người dùng, thay vì im lặng để người dùng tự phát hiện [S1].
- Với hạng mục nào trong checklist phát hành chưa hoàn thiện ở bản đầu tiên, phải ghi
  nhận rõ ràng thành hạn chế đã biết (ví dụ service chưa chạy được PPL Antimalware vì
  chưa có certificate phù hợp), thay vì bị bỏ sót âm thầm [S1].
- Cơ chế rollback ở cấp dữ liệu (ví dụ khi cập nhật CSDL thất bại giữa chừng) hoặc rollback
  bản cài đặt installer: TODO [UNKNOWN] — không có bằng chứng cụ thể trong ngữ cảnh được
  cấp cho tài liệu này.


## Nguồn tham chiếu
- S1 (final.md, chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender)
- S1 (final.md, chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*)
- S1 (final.md, chunk#4 Thiết lập môi trường phát triển)
- S1 (final.md, chunk#41 Kết luận)
- S1 (final.md, chunk#39 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật)
- S1 (final.md, chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường)
- S1 (final.md, chunk#38 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#10 Lưu trữ và quản lý rule phân quyền)
- S1 (final.md, chunk#40 Những lỗi thường gặp khi tự xây antivirus)
- S1 (final.md, chunk#8 Thiết kế chính sách kiểm soát ứng dụng bằng AppLocker/WDAC)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#7 Giới hạn của whitelist theo chữ ký số)
- S1 (final.md, chunk#26 Ký số driver với Microsoft)
- S1 (final.md, chunk#37 Logging và báo cáo cho người dùng)
- S1 (final.md, chunk#16 Tích hợp YARA rules vào scan engine)
- S1 (final.md, chunk#28 Luồng xử lý khi phát hiện file tải về đáng ngờ)
- S1 (final.md, chunk#12 Luồng xử lý khi một ứng dụng thực thi)
- S1 (final.md, chunk#5 Nguyên tắc mặc định tin cậy ứng dụng gốc Windows)
- S1 (final.md, chunk#25 Viết Early Launch Antimalware driver cơ bản)
