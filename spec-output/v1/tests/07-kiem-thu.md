---
id: "kiem-thu"
kind: test
title: "Kiểm thử"
spec_version: "v1"
module: "kiem-thu"
created_at: "2026-08-01T15:50:24.030221+00:00"
sources:
  - { source_id: "S1", loc: "chunk#31 Kiểm thử với file EICAR và bộ mẫu an toàn", hash: "abdb9b35f56c583575412af59759875cfdffb5f5c05efcebaef64ac1d84e2618" }
  - { source_id: "S1", loc: "chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", hash: "4f3ee047f0e2b9eff547e6871b1da177a8c0f97319d67e1f99089eb8b83d305c" }
  - { source_id: "S1", loc: "chunk#6 Kiểm tra chữ ký số Authenticode để whitelist mặc định", hash: "cce87f8a3c8cd1398b9083926e9a18d87ec17594835fcb6ba821adcc3f787d01" }
  - { source_id: "S1", loc: "chunk#7 Giới hạn của whitelist theo chữ ký số", hash: "40ff3f848503ba100ca44a546f2f028712d34596abfe0cb201f97edc9ebd80a1" }
  - { source_id: "S1", loc: "chunk#41 Kết luận", hash: "3eec6601c076d2c8892032d28b2554d458259a89bb1b7db59f4c6a37b4d41d6a" }
  - { source_id: "S1", loc: "chunk#33 Xử lý false positive với whitelist nhiều lớp", hash: "66ff8147f168732ddf02f1b46144a34efab0bd1641498b8c729cf35ca1995f9d" }
  - { source_id: "S1", loc: "chunk#4 Thiết lập môi trường phát triển", hash: "beaf2b68b93b9f502335ca2eca154631972f52fddf86d0463ff3633378aa4d1b" }
  - { source_id: "S1", loc: "chunk#40 Những lỗi thường gặp khi tự xây antivirus", hash: "f337bd98c9a969567f2a3a2849d5f0d8c8aeb664fa08dd3143032ae6d671f345" }
  - { source_id: "S1", loc: "chunk#0 Tự Xây Antivirus Windows: Kiểm Quyền, Quét Sâu, Real-time", hash: "d3b7349fba4476f51a55fa969fa36745722e2e44e4209f386f840b9727e037ea" }
  - { source_id: "S1", loc: "chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật", hash: "738f35b68d00a2f40c9d8bee712457df7a70bd4107526f29106a9b8ede50cf74" }
  - { source_id: "S1", loc: "chunk#30 Cập nhật cơ sở dữ liệu virus tự động", hash: "50e50f2343f3f260ae921b918770fb538289ed51bf6ecb9d4f2f5465cdd3ba87" }
  - { source_id: "S1", loc: "chunk#18 Tối ưu hiệu năng khi quét sâu", hash: "6651987e1a5f94a302fefea430b892f7713846471fc366e723235c419fcf9f23" }
  - { source_id: "S1", loc: "chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa", hash: "bcf95a76fd630c410fa5205a4cb67cf644f19f86b3c5e705b59ccecbe07ef035" }
  - { source_id: "S1", loc: "chunk#8 Thiết kế chính sách kiểm soát ứng dụng bằng AppLocker/WDAC", hash: "d5236d1041a2aeab5679f1aa092a0a979342c01c9e86f60b1f7302bc8dbde2fa" }
  - { source_id: "S1", loc: "chunk#1 Tổng quan kiến trúc app antivirus Windows", hash: "b142a39c6bc430bae5289b9f8ef71a468f7f5d0d7b27c4ceb33d86a64a77f17f" }
  - { source_id: "S1", loc: "chunk#26 Ký số driver với Microsoft", hash: "86cf57e26ce6aa8219dd02178bb6368ecdabd98941ecb7feaeadd677ee519848" }
  - { source_id: "S1", loc: "chunk#11 Engine giám sát tiến trình theo thời gian thực", hash: "3362274f397f853363dbd50458567edaa7502b4cb582fb56b36a7a697dbaffb2" }
  - { source_id: "S1", loc: "chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật", hash: "59cc3cbd79938b6365158b712f193e4f01658bfe18f760c6cf660ec23ef6811d" }
  - { source_id: "S1", loc: "chunk#39 Đóng gói, ký số installer và checklist phát hành", hash: "4237edd642b7c565dd067daad5463c98cbdac0dd3656d4aea610d1f9c301badf" }
  - { source_id: "S1", loc: "chunk#38 Đóng gói, ký số installer và checklist phát hành", hash: "60cfca34d7df11c73c83d6274602016ded4c89187fa0bb95f67bce7df25f722b" }
---

# Kiểm thử

## Mục lục
- [Danh sách ca kiểm thử](#danh-sách-ca-kiểm-thử)
- [Definition of Done](#definition-of-done)

## Danh sách ca kiểm thử

| id | Loại test | Mục tiêu | Các bước thực hiện | Kết quả mong đợi |
|---|---|---|---|---|
| TC-01 | e2e | Xác nhận full scan phát hiện mã độc đã biết qua đúng nhánh hash | Đặt file EICAR tĩnh vào một thư mục thường, chạy full scan [S1] | Engine trả về `Malicious` qua đúng nhánh CSDL hash (vì EICAR nằm sẵn trong hầu hết CSDL signature công khai), không rơi vào nhánh heuristic [S1] |
| TC-02 | e2e | Xác nhận luồng giám sát Downloads tự động quét file tải về | Copy file EICAR vào thư mục Downloads, đo thời gian từ lúc file xuất hiện tới lúc cảnh báo hiện ra [S1] | Luồng giám sát Downloads bắt được sự kiện rename/added và tự động quét, cảnh báo hiển thị cho người dùng [S1] |
| TC-03 | integration | Xác nhận minifilter chặn mở file độc hại trước khi đọc được nội dung | Cố mở trực tiếp file EICAR bằng một chương trình bất kỳ [S1] | Minifilter chặn thao tác mở trước khi chương trình đọc được nội dung, không phải chặn sau khi đã đọc [S1] |
| TC-04 | security | Đo tỷ lệ false positive của engine trên tập dữ liệu sạch trước khi enforce rule mới | Chạy engine trên bộ mẫu sạch đa dạng: toàn bộ file trong `Program Files` của máy Windows cài mới, phần mềm hợp pháp dùng packer (ví dụ dùng UPX), định dạng file nén hợp lệ tỷ lệ nén cao [S1] | Đo được tỷ lệ false positive cụ thể trên tập sạch; chỉ coi rule heuristic/YARA mới là sẵn sàng enforce khi tỷ lệ này bằng không hoặc thấp tới mức chấp nhận được [S1] |
| TC-05 | integration | Xác nhận quy trình log-only trước khi enforce cho rule mới | Chạy rule heuristic/YARA mới ở chế độ log-only tối thiểu vài ngày trên tập file sạch, ghi log kèm hash và đường dẫn cho mọi lần khớp mà không kích hoạt chặn/quarantine [S1] | Rule chỉ chuyển sang chế độ enforce thật khi tỷ lệ match trên tập sạch bằng không hoặc thấp tới mức chấp nhận được [S1] |
| TC-06 | edge-case | Xác nhận quy trình khôi phục khi false positive xảy ra sau khi đã enforce | Giả lập một rule đã enforce gắn cờ nhầm một file hợp lệ; thử khôi phục file từ quarantine về đúng vị trí gốc, sau đó thêm ngoại lệ whitelist theo đúng `scope` (hash cho file tĩnh ít thay đổi, publisher thumbprint cho phần mềm được build liên tục) [S1] | File được khôi phục đúng vị trí gốc bằng metadata đã lưu, và không bị gắn cờ lại ở lần quét sau nhờ ngoại lệ whitelist đúng scope [S1] |
| TC-07 | integration | Xác nhận driver tự ký nạp được trên máy dev nhưng không dùng được cho bản phát hành | Bật `bcdedit /set testsigning on`, tạo self-signed test certificate bằng `MakeCert`/`New-SelfSignedCertificate`, đăng ký vào `Trusted Root`/`Trusted Publisher`, nạp driver đã ký thử [S1] | Driver ký thử (testsigning) nạp được trên máy dev đã bật chế độ này; không dùng được cho bản phát hành thật, cần driver ký qua Microsoft (attestation/WHQL) [S1] |
| TC-08 | edge-case | Xác nhận full scan fallback đúng trên volume không hỗ trợ USN Journal | Chạy full scan trên một volume định dạng FAT32 hoặc exFAT, sau khi kiểm tra file system type qua `GetVolumeInformation` [S1] | Hệ thống fallback về duyệt cây thư mục thông thường (`FindFirstFile`/`FindNextFile`) thay vì dùng `FSCTL_ENUM_USN_DATA`, vì FAT32/exFAT không hỗ trợ USN Journal [S1] |
| TC-09 | integration | Xác nhận cơ chế quarantine khôi phục đúng trên cả file thường và trường hợp giả lập gắn cờ nhầm file hệ thống | Chạy thử khôi phục quarantine trên (a) một file thường bị quarantine, và (b) trường hợp giả lập engine gắn cờ nhầm một file nằm trong thư mục hệ thống được bảo vệ [S1] | Cả hai trường hợp khôi phục thành công về đúng vị trí gốc; trường hợp (b) phải đã đi qua bước xác nhận thủ công trước khi quarantine (không tự động quarantine file hệ thống) [S1] |
| TC-10 | integration | Xác nhận update service xử lý đúng cả luồng incremental delta lẫn fallback full download | Kiểm tra update service tải các gói delta còn thiếu theo đúng thứ tự và áp dụng tuần tự; kiểm tra trường hợp client bị tụt quá xa (ví dụ hơn 30 phiên bản) chuyển sang tải full CSDL; verify chữ ký số của gói CSDL tải về bằng `WinVerifyTrust` trước khi áp dụng [S1] | Cả luồng incremental delta và luồng fallback full download hoạt động đúng; gói CSDL không hợp lệ chữ ký số bị từ chối, không được áp dụng [S1] |
| TC-11 | performance | Đo hiệu năng full/deep scan trên phần cứng thật, không chỉ trên máy dev cấu hình cao | Benchmark full scan trên cả máy có ổ HDD cũ và máy có SSD NVMe, đo mức độ giật lag cảm nhận được [S1] | Kết quả đo trên phần cứng phổ thông (HDD cũ) không bị treo máy hay giật lag nghiêm trọng; nếu tính năng deep scan chưa được test trên HDD, phải ghi nhận rõ ràng thành hạn chế đã biết thay vì công bố đã hoàn thiện [S1] |

## Definition of Done

Một yêu cầu/tính năng của hệ thống chỉ được coi là hoàn thành khi thỏa các tiêu chí sau
(theo checklist phát hành nêu trong tài liệu nguồn); nếu một mục chưa đạt, phải được ghi
nhận rõ ràng thành hạn chế đã biết thay vì bị bỏ sót âm thầm, vì một antivirus tự nhận có
tính năng nhưng chưa test đầy đủ gây hiểu lầm nguy hiểm hơn việc công khai nói rõ tính
năng nào còn ở giai đoạn thử nghiệm [S1]:

- Driver ELAM và minifilter đã qua attestation signing hoặc WHQL, không còn dùng
  testsigning [S1].
- Toàn bộ rule heuristic/YARA đã qua giai đoạn log-only đủ lâu trên tập file sạch đa
  dạng, không còn rule nào mới chưa đo tỷ lệ false positive [S1].
- Cơ chế quarantine đã test khôi phục thành công cả trên file thường và trên trường hợp
  giả lập gắn cờ nhầm file hệ thống [S1].
- Update service đã test được luồng incremental delta lẫn fallback full download, và
  verify chữ ký số CSDL tải về hoạt động đúng [S1].
- Tiến trình service đã chạy ở PPL Antimalware nếu đã có certificate phù hợp, hoặc đã
  ghi rõ trong tài liệu nội bộ đây là hạn chế đã biết nếu chưa có certificate này [S1].
- Đã quyết định rõ trạng thái đăng ký MVI/Windows Security Center; nếu chưa qua MVI, tài
  liệu hướng dẫn cài đặt cho người dùng phải nêu rõ khả năng xung đột với Windows Defender
  và cách xử lý [S1].
- Bộ test EICAR đã chạy qua cả ba luồng (full scan, Downloads, real-time) và cho kết quả
  đúng ở mỗi luồng [S1].


## Nguồn tham chiếu
- S1 (final.md, chunk#31 Kiểm thử với file EICAR và bộ mẫu an toàn)
- S1 (final.md, chunk#32 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*)
- S1 (final.md, chunk#6 Kiểm tra chữ ký số Authenticode để whitelist mặc định)
- S1 (final.md, chunk#7 Giới hạn của whitelist theo chữ ký số)
- S1 (final.md, chunk#41 Kết luận)
- S1 (final.md, chunk#33 Xử lý false positive với whitelist nhiều lớp)
- S1 (final.md, chunk#4 Thiết lập môi trường phát triển)
- S1 (final.md, chunk#40 Những lỗi thường gặp khi tự xây antivirus)
- S1 (final.md, chunk#0 Tự Xây Antivirus Windows: Kiểm Quyền, Quét Sâu, Real-time)
- S1 (final.md, chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật)
- S1 (final.md, chunk#30 Cập nhật cơ sở dữ liệu virus tự động)
- S1 (final.md, chunk#18 Tối ưu hiệu năng khi quét sâu)
- S1 (final.md, chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa)
- S1 (final.md, chunk#8 Thiết kế chính sách kiểm soát ứng dụng bằng AppLocker/WDAC)
- S1 (final.md, chunk#1 Tổng quan kiến trúc app antivirus Windows)
- S1 (final.md, chunk#26 Ký số driver với Microsoft)
- S1 (final.md, chunk#11 Engine giám sát tiến trình theo thời gian thực)
- S1 (final.md, chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật)
- S1 (final.md, chunk#39 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#38 Đóng gói, ký số installer và checklist phát hành)
