---
id: "phi-chuc-nang"
kind: nfr
title: "Phi chức năng"
spec_version: "v1"
module: "phi-chuc-nang"
created_at: "2026-08-01T15:49:10.415419+00:00"
sources:
  - { source_id: "S1", loc: "chunk#24 Giảm độ trễ khi quét theo thời gian thực", hash: "c95bc499a4f1bea0c0989dab031faddacda3d388d59691bca876214cf8810ac0" }
  - { source_id: "S1", loc: "chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật", hash: "59cc3cbd79938b6365158b712f193e4f01658bfe18f760c6cf660ec23ef6811d" }
  - { source_id: "S1", loc: "chunk#18 Tối ưu hiệu năng khi quét sâu", hash: "6651987e1a5f94a302fefea430b892f7713846471fc366e723235c419fcf9f23" }
  - { source_id: "S1", loc: "chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường", hash: "e44c7e7f08017f68ab3e6a509472b314de4aa80c6e8173374d4bc431d09998bf" }
  - { source_id: "S1", loc: "chunk#23 NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL", hash: "06f81b36fd2a8fc5200f665027562b08c60e062f94aaec6507423e2c846d58e1" }
  - { source_id: "S1", loc: "chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa", hash: "bcf95a76fd630c410fa5205a4cb67cf644f19f86b3c5e705b59ccecbe07ef035" }
  - { source_id: "S1", loc: "chunk#40 Những lỗi thường gặp khi tự xây antivirus", hash: "f337bd98c9a969567f2a3a2849d5f0d8c8aeb664fa08dd3143032ae6d671f345" }
  - { source_id: "S1", loc: "chunk#26 Ký số driver với Microsoft", hash: "86cf57e26ce6aa8219dd02178bb6368ecdabd98941ecb7feaeadd677ee519848" }
  - { source_id: "S1", loc: "chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender", hash: "5803b7b4e05da0cb47c25597863ce39af922cf6099f3fd5b04bcf74f101eff07" }
  - { source_id: "S1", loc: "chunk#38 Đóng gói, ký số installer và checklist phát hành", hash: "60cfca34d7df11c73c83d6274602016ded4c89187fa0bb95f67bce7df25f722b" }
  - { source_id: "S1", loc: "chunk#7 Giới hạn của whitelist theo chữ ký số", hash: "40ff3f848503ba100ca44a546f2f028712d34596abfe0cb201f97edc9ebd80a1" }
  - { source_id: "S1", loc: "chunk#13 Thiết kế tổng thể bộ máy quét (scan engine)", hash: "ba5ae0252457e4cd57d7a36e7f505015f8b3e606cf862f209f5b68dae1328466" }
  - { source_id: "S1", loc: "chunk#5 Nguyên tắc mặc định tin cậy ứng dụng gốc Windows", hash: "092c498ec704be0cb77634e0ebf538fbc1f968c8fca05166290df872ff02ba23" }
  - { source_id: "S1", loc: "chunk#39 Đóng gói, ký số installer và checklist phát hành", hash: "4237edd642b7c565dd067daad5463c98cbdac0dd3656d4aea610d1f9c301badf" }
  - { source_id: "S1", loc: "chunk#12 Luồng xử lý khi một ứng dụng thực thi", hash: "21565980c6961104b59cc82412e55d2b9a3571deb663d93a41f6b4bc5f69a825" }
  - { source_id: "S1", loc: "chunk#11 Engine giám sát tiến trình theo thời gian thực", hash: "3362274f397f853363dbd50458567edaa7502b4cb582fb56b36a7a697dbaffb2" }
  - { source_id: "S1", loc: "chunk#29 Cơ chế Quarantine cách ly file nghi ngờ", hash: "c0d0d265c33eefbe75d7d1c6ec0772dae67f0eeefa2112b992b52c7b021289ad" }
  - { source_id: "S1", loc: "chunk#0 Tự Xây Antivirus Windows: Kiểm Quyền, Quét Sâu, Real-time", hash: "d3b7349fba4476f51a55fa969fa36745722e2e44e4209f386f840b9727e037ea" }
  - { source_id: "S1", loc: "chunk#4 Thiết lập môi trường phát triển", hash: "beaf2b68b93b9f502335ca2eca154631972f52fddf86d0463ff3633378aa4d1b" }
  - { source_id: "S1", loc: "chunk#10 Lưu trữ và quản lý rule phân quyền", hash: "2eef23f72066b39840103d0f6b4062d1b7da7382f05a22662890b36504d838f9" }
---

# Phi chức năng

Phần Bảo mật của tài liệu phi chức năng được tách riêng sang tài liệu Bảo mật & Phân
quyền để tránh trùng lặp; tài liệu này chỉ giữ Hiệu năng, Độ sẵn sàng, và Quan trắc.

## Mục lục
- [Hiệu năng](#hiệu-năng)
- [Độ sẵn sàng](#độ-sẵn-sàng)
- [Quan trắc](#quan-trắc)

## Hiệu năng

- **NFR-PERF-01** — Real-time protection không được gây cảm giác giật khi mở file đã
  từng quét sạch. Metric: độ trễ đo bằng `QueryPerformanceCounter` chèn ở đầu và cuối
  `PreCreateCallback`, tính theo microsecond [S1]. Ngưỡng chấp nhận: giữ overhead dưới
  khoảng một chục mili giây cho file đã có trong cache (khóa cache gồm đường dẫn, thời
  gian sửa đổi cuối, kích thước file); chấp nhận vài chục đến hơn trăm mili giây cho lần
  đầu quét một file thực thi mới và lớn; không có ngưỡng chuẩn chính thức bắt buộc của
  ngành, cần tự benchmark trên phần cứng thật trước/sau khi bật driver [S1].
- **NFR-PERF-02** — Chuỗi quyết định cho phép/chặn một tiến trình mới không được giữ
  tiến trình ở trạng thái chờ quá lâu. Metric: thời gian từ lúc driver gửi thông tin
  xuống service tới lúc nhận được quyết định cuối cùng [S1]. Ngưỡng chấp nhận: dưới 50
  mili giây cho trường hợp chỉ cần tra rule có sẵn; tối đa 30 giây cho trường hợp cần
  hiển thị hộp thoại hỏi người dùng và chờ phản hồi [S1].
- **NFR-PERF-03** — Full/deep scan trên ổ HDD không được tạo seek thrashing làm giảm
  throughput. Metric: số luồng song song đang đọc file, thứ tự đọc theo vị trí cluster
  vật lý (LBA) [S1]. Ngưỡng chấp nhận: trên HDD (xác định qua
  `IOCTL_STORAGE_QUERY_PROPERTY`/`StorageDeviceSeekPenaltyProperty`), giảm số luồng song
  song xuống 1 và sắp xếp hàng đợi đọc theo LBA tăng dần (lấy qua
  `FSCTL_GET_RETRIEVAL_POINTERS`); kỹ thuật này không áp dụng cho SSD vì SSD không có chi
  phí seek cơ học [S1].
- **NFR-PERF-04** — Full scan chạy nền không được cạnh tranh tài nguyên với thao tác của
  người dùng đang diễn ra. Metric: thời gian rảnh của người dùng đo qua
  `GetLastInputInfo`, mức ưu tiên I/O của tiến trình quét [S1]. Ngưỡng chấp nhận: hạ mức
  ưu tiên I/O bằng `SetPriorityClass`/`PROCESS_MODE_BACKGROUND_BEGIN` và
  `FileIoPriorityHintInformation`/`IoPriorityLow`; giảm hoặc tạm dừng hoàn toàn số luồng
  scan song song khi người dùng vừa tương tác trong vài giây gần nhất; khôi phục tốc độ
  quét bình thường khi máy idle quá 60 giây không có input [S1].

## Độ sẵn sàng

- **NFR-AVAIL-01** — Quét file nén không được làm treo máy hoặc làm đầy đĩa do zip bomb.
  Metric: tổng dung lượng đã giải nén thực tế (đo trong lúc giải nén, không đọc từ
  header), tỷ lệ nén thực tế, độ sâu lồng nhau của file nén [S1]. Ngưỡng chấp nhận: dừng
  và gắn cờ `Suspicious` ngay khi vượt bất kỳ giới hạn nào trong ba giới hạn — tỷ lệ nén
  tối đa (ví dụ 100 lần), độ sâu lồng nhau tối đa (ví dụ 5 lớp), hoặc trần dung lượng
  giải nén tuyệt đối cho một file gốc (ví dụ 1GB) [S1].
- **NFR-AVAIL-02** — Driver kernel-mode (ELAM, minifilter) không được gây blue screen
  làm máy người dùng không khởi động được. Metric: kết quả bộ test Hardware Lab Kit
  (HLK) trên nhiều cấu hình phần cứng [S1]. Ngưỡng chấp nhận: driver cấp antivirus nên đi
  thẳng tới WHQL/HLK ngay từ giai đoạn beta nội bộ thay vì dừng ở attestation signing, vì
  lỗi trong driver chặn filesystem hay driver nạp ở giai đoạn boot ảnh hưởng trực tiếp
  đến khả năng khởi động của máy, rủi ro nghiêm trọng hơn nhiều loại driver khác [S1].
- **NFR-AVAIL-03** — Hệ thống không được để lộ khoảng hở an toàn khi service nền không
  phản hồi kịp cho một quyết định cấp quyền. Metric: hành vi mặc định khi hết timeout tra
  rule [S1]. Ngưỡng chấp nhận: mặc định deny-and-log khi service không phản hồi kịp (an
  toàn hơn allow mù), trừ khi tiến trình đã đạt điều kiện trusted-by-default ngay ở tầng
  driver mà không cần chờ service [S1].
- **NFR-AVAIL-04** — Full/deep scan không được mất toàn bộ tiến độ nếu người dùng cần
  dừng giữa chừng để dùng máy cho việc nặng khác. Metric: khả năng tạm dừng/tiếp tục quét
  mà không phải quét lại từ đầu [S1]. Ngưỡng chấp nhận: lưu vị trí `FileReferenceNumber`
  cuối cùng đã xử lý vào một file trạng thái nhỏ, hỗ trợ tạm dừng và tiếp tục giữa chừng
  trên cả HDD lẫn SSD [S1].

## Quan trắc

- **NFR-OBS-01** — Độ trễ thực tế của real-time protection phải đo được trên máy mục
  tiêu thay vì chỉ dựa vào ước tính lý thuyết. Metric: delta thời gian giữa đầu và cuối
  `PreCreateCallback`, đo bằng `QueryPerformanceCounter` theo đơn vị microsecond, ghi vào
  một buffer log trong driver để xuất ra phân tích định kỳ [S1]. Ngưỡng chấp nhận: không
  có ngưỡng chuẩn chính thức bắt buộc của ngành cho con số này; yêu cầu bắt buộc là luôn
  benchmark trước và sau khi bật driver để biết con số thực tế trên phần cứng mục tiêu,
  thay vì tin vào một con số lý thuyết [S1].


## Nguồn tham chiếu
- S1 (final.md, chunk#24 Giảm độ trễ khi quét theo thời gian thực)
- S1 (final.md, chunk#2 Lựa chọn ngôn ngữ và stack kỹ thuật)
- S1 (final.md, chunk#18 Tối ưu hiệu năng khi quét sâu)
- S1 (final.md, chunk#15 Kỹ thuật heuristic phát hiện hành vi bất thường)
- S1 (final.md, chunk#23 NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
- S1 (final.md, chunk#17 Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa)
- S1 (final.md, chunk#40 Những lỗi thường gặp khi tự xây antivirus)
- S1 (final.md, chunk#26 Ký số driver với Microsoft)
- S1 (final.md, chunk#34 Đăng ký với Windows Security Center và tránh xung đột Defender)
- S1 (final.md, chunk#38 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#7 Giới hạn của whitelist theo chữ ký số)
- S1 (final.md, chunk#13 Thiết kế tổng thể bộ máy quét (scan engine))
- S1 (final.md, chunk#5 Nguyên tắc mặc định tin cậy ứng dụng gốc Windows)
- S1 (final.md, chunk#39 Đóng gói, ký số installer và checklist phát hành)
- S1 (final.md, chunk#12 Luồng xử lý khi một ứng dụng thực thi)
- S1 (final.md, chunk#11 Engine giám sát tiến trình theo thời gian thực)
- S1 (final.md, chunk#29 Cơ chế Quarantine cách ly file nghi ngờ)
- S1 (final.md, chunk#0 Tự Xây Antivirus Windows: Kiểm Quyền, Quét Sâu, Real-time)
- S1 (final.md, chunk#4 Thiết lập môi trường phát triển)
- S1 (final.md, chunk#10 Lưu trữ và quản lý rule phân quyền)
