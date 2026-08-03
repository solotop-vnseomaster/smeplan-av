---
id: "api"
kind: api
title: "API"
spec_version: "v1"
module: "api"
created_at: "2026-08-01T15:44:36.791348+00:00"
sources:
  - { source_id: "S1", loc: "chunk#16 Tích hợp YARA rules vào scan engine", hash: "09f3633e6e1995108b8c8a01daa26dd7a383faf54cee9139abed99d3278ad6b4" }
  - { source_id: "S1", loc: "chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender", hash: "5803b7b4e05da0cb47c25597863ce39af922cf6099f3fd5b04bcf74f101eff07" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường", hash: "e44c7e7f08017f68ab3e6a509472b314de4aa80c6e8173374d4bc431d09998bf" }
  - { source_id: "S1", loc: "chunk#6 Kiểm tra chữ ký số Authenticode để whitelist mặc định", hash: "cce87f8a3c8cd1398b9083926e9a18d87ec17594835fcb6ba821adcc3f787d01" }
  - { source_id: "S1", loc: "chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật", hash: "738f35b68d00a2f40c9d8bee712457df7a70bd4107526f29106a9b8ede50cf74" }
  - { source_id: "S1", loc: "chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật", hash: "59cc3cbd79938b6365158b712f193e4f01658bfe18f760c6cf660ec23ef6811d" }
  - { source_id: "S1", loc: "chunk#25 Viết Early Launch Antimalware driver cơ bản", hash: "f41b68505282e58b734c1adc5e3581a2968329011499fedca868e830669419c2" }
  - { source_id: "S1", loc: "chunk#30 Cập nhật cơ sở dữ liệu virus tự động", hash: "50e50f2343f3f260ae921b918770fb538289ed51bf6ecb9d4f2f5465cdd3ba87" }
  - { source_id: "S1", loc: "chunk#40 Những lỗi thường gặp khi tự xây antivirus", hash: "f337bd98c9a969567f2a3a2849d5f0d8c8aeb664fa08dd3143032ae6d671f345" }
  - { source_id: "S1", loc: "chunk#26 Ký số driver với Microsoft", hash: "86cf57e26ce6aa8219dd02178bb6368ecdabd98941ecb7feaeadd677ee519848" }
  - { source_id: "S1", loc: "chunk#1 Tổng quan kiến trúc app antivirus Windows", hash: "b142a39c6bc430bae5289b9f8ef71a468f7f5d0d7b27c4ceb33d86a64a77f17f" }
  - { source_id: "S1", loc: "chunk#14 Xây dựng cơ sở dữ liệu signature dựa trên hash", hash: "8de40e7324bdcaa66f177c8e534b2f37953c2d4ca49074643ede798407cddead" }
  - { source_id: "S1", loc: "chunk#27 Giám sát riêng thư mục Downloads", hash: "2c250a52583f3208242ad843aef00370be7ca79dbfbffe35b3fd4d92763dc4f0" }
  - { source_id: "S1", loc: "chunk#37 Logging và báo cáo cho người dùng", hash: "538bc9459381222d16e8d5bf3c9692b1b3e9d087e2496b7d0f7dc738f0f90aad" }
  - { source_id: "S1", loc: "chunk#23 NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL", hash: "06f81b36fd2a8fc5200f665027562b08c60e062f94aaec6507423e2c846d58e1" }
  - { source_id: "S1", loc: "chunk#7 Giới hạn của whitelist theo chữ ký số", hash: "40ff3f848503ba100ca44a546f2f028712d34596abfe0cb201f97edc9ebd80a1" }
  - { source_id: "S1", loc: "chunk#31 Kiểm thử với file EICAR và bộ mẫu an toàn", hash: "abdb9b35f56c583575412af59759875cfdffb5f5c05efcebaef64ac1d84e2618" }
  - { source_id: "S1", loc: "chunk#18 Tối ưu hiệu năng khi quét sâu", hash: "6651987e1a5f94a302fefea430b892f7713846471fc366e723235c419fcf9f23" }
  - { source_id: "S1", loc: "chunk#9 Giao diện tùy biến quyền cho ứng dụng bên thứ 3", hash: "03948fea0e449152ae61d582b0d81821a5bf18aaaabb6079dcf3fcfca9c22cdf" }
---

# API

Ngữ cảnh được cấp cho tài liệu này chỉ có bằng chứng về một nhóm giao tiếp dạng
HTTPS/JSON: dịch vụ cập nhật CSDL virus gọi ra ngoài để kiểm tra và tải phiên bản CSDL
mới [S1]. Các giao tiếp nội bộ khác của hệ thống (driver ↔ service qua
`FltSendMessage`/`DeviceIoControl`, service C# ↔ scan engine C++ qua P/Invoke/COM
interop) không phải API dạng request/response qua mạng nên không được liệt kê theo khuôn
endpoint ở đây; các giao tiếp đó đã được mô tả trong tài liệu Kiến trúc.

### {TODO [UNKNOWN]} {TODO [UNKNOWN]} — Kiểm tra phiên bản CSDL mới nhất
- Headers: TODO [UNKNOWN]
- Request: TODO [UNKNOWN] — nguồn chỉ nêu update service gọi ra một "endpoint HTTPS" theo
  chu kỳ ngắn (ví dụ mỗi 1-4 giờ) để kiểm tra phiên bản mới, không nêu rõ tham số truyền
  vào [S1]
- Validation: TODO [UNKNOWN]
- Business rule liên quan: client so sánh số phiên bản trả về với phiên bản CSDL đang có
  cục bộ trước khi quyết định tải về; nếu client tụt quá xa (ví dụ hơn 30 phiên bản), sẽ
  chuyển sang tải full CSDL thay vì tải nhiều gói delta liên tiếp [S1]
- Response (thành công): metadata dạng JSON gồm trường số phiên bản CSDL mới nhất (kiểu
  dữ liệu TODO [UNKNOWN]) và trường checksum của gói CSDL (kiểu dữ liệu TODO [UNKNOWN])
  [S1]
- Mã lỗi: TODO [UNKNOWN]
- Quyền hạn (role được phép gọi): gọi bởi một update service riêng, tách khỏi service
  điều phối chính của app [S1]
- Rate limit: không có rate limit phía server được nêu; phía client tự giới hạn tần suất
  gọi theo chu kỳ ví dụ 1-4 giờ một lần vì mối đe dọa mới không xuất hiện theo giây [S1]
- Idempotency: TODO [UNKNOWN]
- Audit log: TODO [UNKNOWN]

### {TODO [UNKNOWN]} {TODO [UNKNOWN]} — Tải gói CSDL (delta hoặc full)
- Headers: TODO [UNKNOWN]
- Request: TODO [UNKNOWN] — nguồn nêu server lưu sẵn các gói diff theo tên dạng
  `v100_to_v101.delta` giữa mỗi cặp phiên bản liên tiếp, ngụ ý client cần xác định gói
  delta còn thiếu theo đúng thứ tự để tải, nhưng không nêu rõ cơ chế truyền tham số này
  qua request [S1]
- Validation: TODO [UNKNOWN]
- Business rule liên quan: client tải các gói delta còn thiếu theo đúng thứ tự và áp
  dụng tuần tự lên CSDL cục bộ để lên phiên bản mới nhất; chỉ tải full CSDL khi client bị
  tụt quá xa (ví dụ hơn 30 phiên bản) [S1]. Mỗi gói tải về, dù full hay delta, phải được
  xác minh chữ ký số bằng `WinVerifyTrust` trước khi áp dụng, ký bằng chính certificate
  của công ty, để một kênh phân phối bị xâm nhập không thể đẩy một CSDL giả xuống máy
  người dùng [S1]. Sau khi verify, CSDL mới được ghi vào file tạm rồi đổi tên hoán đổi
  nguyên tử (`MoveFileEx` với `MOVEFILE_REPLACE_EXISTING`) thay thế file cũ [S1]
- Response (thành công): nội dung nhị phân của gói CSDL (full hoặc delta) [S1]; các
  trường cụ thể khác của response TODO [UNKNOWN]
- Mã lỗi: TODO [UNKNOWN]
- Quyền hạn (role được phép gọi): gọi bởi update service riêng, tách khỏi service điều
  phối chính [S1]
- Rate limit: TODO [UNKNOWN]
- Idempotency: TODO [UNKNOWN]
- Audit log: TODO [UNKNOWN]


## Nguồn tham chiếu
- S1 (final.md, chunk#16 Tích hợp YARA rules vào scan engine)
- S1 (final.md, chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường)
- S1 (final.md, chunk#6 Kiểm tra chữ ký số Authenticode để whitelist mặc định)
- S1 (final.md, chunk#3 Yêu cầu và rào cản của Windows với phần mềm bảo mật)
- S1 (final.md, chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật)
- S1 (final.md, chunk#25 Viết Early Launch Antimalware driver cơ bản)
- S1 (final.md, chunk#30 Cập nhật cơ sở dữ liệu virus tự động)
- S1 (final.md, chunk#40 Những lỗi thường gặp khi tự xây antivirus)
- S1 (final.md, chunk#26 Ký số driver với Microsoft)
- S1 (final.md, chunk#1 Tổng quan kiến trúc app antivirus Windows)
- S1 (final.md, chunk#14 Xây dựng cơ sở dữ liệu signature dựa trên hash)
- S1 (final.md, chunk#27 Giám sát riêng thư mục Downloads)
- S1 (final.md, chunk#37 Logging và báo cáo cho người dùng)
- S1 (final.md, chunk#23 NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
- S1 (final.md, chunk#7 Giới hạn của whitelist theo chữ ký số)
- S1 (final.md, chunk#31 Kiểm thử với file EICAR và bộ mẫu an toàn)
- S1 (final.md, chunk#18 Tối ưu hiệu năng khi quét sâu)
- S1 (final.md, chunk#9 Giao diện tùy biến quyền cho ứng dụng bên thứ 3)
