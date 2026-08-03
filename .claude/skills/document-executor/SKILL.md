---
name: document-executor
description: >
  Dùng skill này khi được giao một tệp tài liệu, đặc tả, hoặc yêu cầu tính
  năng (spec, PRD, feature list) và được yêu cầu triển khai/code theo đúng
  tài liệu đó. Đảm bảo thực thi đầy đủ mọi tính năng được liệt kê, không bỏ
  sót, đồng thời không tự ý sửa, viết lại, hay tạo phiên bản khác của tài
  liệu gốc khi chưa được người dùng xác nhận rõ ràng.
---

## Hai ràng buộc cốt lõi

1. **Không bỏ sót**: triển khai đủ 100% những gì tài liệu yêu cầu.
2. **Không tự ý viết phiên bản khác**: không sửa, không tạo file mới trùng
   lặp nội dung tài liệu gốc (tóm tắt, bản rõ hơn, bản chuẩn hoá...) khi
   chưa được xác nhận.

Mọi hành động không tường minh phải được biến thành hành động tường minh,
kiểm tra lại được: checklist file cho ràng buộc 1, xác nhận qua
AskUserQuestion cho ràng buộc 2.

## Instructions

Làm theo đúng thứ tự, không bỏ qua bước nào:

1. **Đọc toàn bộ** tài liệu được giao, từ đầu đến cuối, trước khi viết bất
   kỳ dòng code nào, kể cả khi các mục đầu tiên đã đủ rõ để bắt đầu. Đặc
   biệt chú ý các mục nằm giữa và cuối tài liệu (yêu cầu phi chức năng,
   trường hợp biên, ghi chú bổ sung) — đây là vị trí dễ bị bỏ sót nhất.

2. **Trích xuất checklist** mọi tính năng trong tài liệu, lưu vào
   `features.md` ở thư mục làm việc hiện tại. Mỗi tính năng là một dòng
   riêng, có ID và số mục tham chiếu trong tài liệu gốc:
   `- [ ] F01: Mô tả tính năng (mục X.X)`. Không gộp hai tính năng khác
   nhau vào một dòng. Mục nào mơ hồ tới mức một cách hiểu sai có thể khiến
   người dùng phải yêu cầu sửa lại sau khi thấy kết quả, gắn nhãn
   `[CẦN LÀM RÕ]`. Gom hết các điểm mơ hồ, hỏi một lần qua AskUserQuestion
   trước khi triển khai (bước 3) — không hỏi rời rạc giữa chừng. Tiêu chí
   phân loại mơ hồ chi tiết: [references/behavior-rules.md](references/behavior-rules.md).

3. **Triển khai từng tính năng.** Với mỗi dòng trong `features.md`, tạo một
   task bằng TaskCreate (subject lấy đúng nội dung dòng, kèm ID). Đánh dấu
   `in_progress` khi bắt đầu, `completed` chỉ khi tính năng đã chạy được và
   có bằng chứng cụ thể (file + vị trí code), không đánh dấu dựa trên cảm
   giác "chắc là xong". Chỉ triển khai đúng những gì có trong `features.md`
   — không thêm tính năng, endpoint, hay ràng buộc nào không có trong tài
   liệu gốc dù nó "có vẻ nên có". Nếu phát hiện thiếu sót đáng kể trong tài
   liệu, không tự thêm, ghi thành mục riêng gắn nhãn
   `[ĐỀ XUẤT: CHƯA CÓ TRONG SPEC]` và báo lại cuối phiên.

4. **Đối chiếu trước khi báo hoàn thành.** Đọc lại toàn bộ `features.md`.
   Với mỗi mục, trả lời cụ thể: file nào, đoạn code nào hiện thực mục này?
   Không chỉ ra được thì mục đó coi như CHƯA XONG, quay lại triển khai.
   Chạy cổng chặn cuối:
   ```bash
   python scripts/check_coverage.py features.md
   ```
   Chỉ báo hoàn thành khi mọi mục (trừ mục đã hỏi và bị từ chối) đều có
   bằng chứng cụ thể và script trả về không lỗi.

5. **Không tự ý thay đổi tài liệu gốc.** Chỉ được tự sửa không cần hỏi với
   phạm vi rất hẹp (lỗi chính tả 1-2 từ, định dạng markdown không đổi nội
   dung). Mọi thay đổi khác — kể cả tạo file mới trùng lặp nội dung tài
   liệu gốc dù đặt tên gì (spec-v2, spec-final, tóm tắt...) — phải dừng lại
   và dùng AskUserQuestion với lựa chọn cụ thể (tạo file mới riêng / ghi đè
   bản gốc / không làm) trước khi hành động. Một nhận xét bâng quơ ("tài
   liệu này hơi rối") không phải mệnh lệnh, không tự suy diễn thành yêu cầu
   viết lại. Trước khi ghi bất kỳ file `.md`/`.txt` mới nào ngoài
   `features.md`, có thể kiểm khách quan bằng:
   ```bash
   python scripts/diff_guard.py <tài-liệu-gốc>
   ```
   Ranh giới đầy đủ giữa "sửa nhỏ được phép" và "viết lại cần xác nhận":
   [references/behavior-rules.md](references/behavior-rules.md).

## Ví dụ hành vi đúng/sai

Tình huống: tài liệu `spec.md` có mục "3.2: Giới hạn tốc độ API: hợp lý
theo nhu cầu thực tế" — chi tiết mơ hồ ảnh hưởng tới hành vi quan sát được.

**SAI:**
1. Tự chọn 60 request/phút, code luôn, không hỏi.
2. Tạo file `spec-clarified.md`, viết lại mục 3.2 cho "rõ hơn" rồi code
   theo file mới đó.

Cả hai đều sai: (1) vi phạm không bịa chi tiết ảnh hưởng hành vi quan sát
được; (2) vi phạm không tự tạo phiên bản khác của tài liệu.

**ĐÚNG:**
1. Gắn nhãn `[CẦN LÀM RÕ]` vào dòng tương ứng trong `features.md`.
2. Dùng AskUserQuestion hỏi mức giới hạn cụ thể, kèm vài lựa chọn gợi ý.
3. Sau khi có câu trả lời, cập nhật `features.md` (ghi rõ đây là quyết
   định của người dùng), rồi mới code. `spec.md` gốc không bị đụng tới.

Tình huống khác: người dùng nói "spec này viết hơi khó đọc" — đây KHÔNG
phải lệnh viết lại. Hỏi lại ý định thay vì tự động tạo bản mới.

## Tham khảo thêm

- [references/behavior-rules.md](references/behavior-rules.md) — whitelist
  sửa nhỏ, tiêu chí phân loại mơ hồ, quy tắc chặn file "spec-v2" song song.
- [references/testing-scenarios.md](references/testing-scenarios.md) — ba
  kịch bản test để tự kiểm skill sau khi chỉnh sửa.
- [assets/sample_spec.md](assets/sample_spec.md) — tài liệu spec mẫu dùng
  để test skill (có sẵn điểm mơ hồ và mục dễ bị bỏ sót).
