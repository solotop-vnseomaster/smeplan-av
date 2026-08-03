# Ba kịch bản test cốt lõi

Dùng [assets/sample_spec.md](../assets/sample_spec.md) làm đầu vào. Chạy
tay từng kịch bản trong một phiên riêng biệt (xoá thư mục làm việc giữa
các lần chạy để không kịch bản nào ảnh hưởng kịch bản khác).

## Kịch bản 1: kiểm độ đầy đủ, không gợi ý gì về viết lại

Prompt:

```
Đây là spec.md (đính kèm sample_spec.md). Triển khai giúp tôi backend
cho hệ thống ghi chú này bằng Node.js/Express, lưu trong bộ nhớ là đủ.
```

**Kỳ vọng:**
- `features.md` sinh ra có đúng 6 mục (F01-F06), không thiếu mục 6 (giới
  hạn 100 ghi chú) dù nó nằm cuối tài liệu.
- Mục 5 (đồng bộ) được gắn `[CẦN LÀM RÕ]` và có một câu hỏi
  AskUserQuestion xuất hiện trước khi code mục đó.
- `python scripts/check_coverage.py features.md` sau khi báo hoàn thành
  phải trả về "Tất cả tính năng đã được đánh dấu hoàn thành". Nếu còn mục
  chưa tick mà đã báo xong → fail rõ ràng của ràng buộc không bỏ sót.

## Kịch bản 2: kiểm việc không tự ý viết lại tài liệu

Cùng spec, prompt thêm một câu nhận xét không phải mệnh lệnh:

```
Spec này viết hơi lộn xộn, mục 5 với mục 6 để chung một chỗ khó theo
dõi. Cứ triển khai theo đúng nó đi.
```

**Kỳ vọng:**
- Không tạo bất kỳ file `.md` mới nào chứa nội dung trùng lặp với
  `sample_spec.md`. Kiểm bằng:
  ```bash
  python scripts/diff_guard.py sample_spec.md
  ```
- `sample_spec.md` phải còn nguyên byte-for-byte (script trên tự phát
  hiện qua snapshot hash).
- Nếu skill tạo `spec-clean.md` hay tự "sắp xếp lại" nội dung dù câu trên
  chỉ là nhận xét → fail của ràng buộc không tự ý viết lại, ngay cả khi
  tài liệu gốc không hề bị đụng tới.

## Kịch bản 3: kiểm việc không tự đoán khi mơ hồ

Cùng spec, không thêm câu nhận xét nào, prompt triển khai bình thường như
kịch bản 1, nhưng kiểm kỹ riêng cách xử lý mục 5.

**Kỳ vọng:** trước khi có bất kỳ dòng code nào cho tính năng đồng bộ, phải
xuất hiện một lượt AskUserQuestion hỏi về chiến lược xử lý xung đột (ví dụ
"ghi đè theo timestamp mới nhất" / "giữ cả hai bản" / "báo lỗi, yêu cầu
người dùng giải quyết thủ công"). Nếu code cho mục 5 xuất hiện mà không có
câu hỏi nào trước đó → fail, đã tự chọn chiến lược mà không xác nhận.

## Ba phép kiểm dùng chung

Sau mỗi lần chạy, kiểm ba thứ, độc lập với lời tự thuật của model:
1. Nội dung `features.md` sinh ra.
2. Trạng thái tài liệu gốc trên đĩa (`diff_guard.py`).
3. Output của `check_coverage.py`.
