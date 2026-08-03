---
id: "doi-chieu-cheo"
kind: consistency-check
title: "Đối chiếu chéo"
spec_version: "v1"
module: "doi-chieu-cheo"
created_at: "2026-08-01T15:58:47.204698+00:00"
sources:
  - { source_id: "UNKNOWN", loc: "", hash: "" }
---

# Đối chiếu chéo

| Vấn đề | Tệp A | Tệp B | Đề xuất thống nhất |
|---|---|---|---|
| "Update service" cập nhật CSDL được mô tả không nhất quán về việc có phải là một tiến trình/thành phần riêng biệt hay không. File Kiến trúc gộp cơ chế cập nhật vào chung "khối thứ sáu" (CSDL signature cùng cơ chế cập nhật) mà không tách thành một tiến trình riêng trong danh sách 6 thành phần; trong khi các file API, Bảo mật và Triển khai đều mô tả rõ đây là "một update service riêng, tách khỏi service điều phối chính". | modules/02-kien-truc.md (mục 1. Danh sách thành phần) | apis/03-api.md, security/09-bao-mat.md, ops/08-trien-khai.md | Thống nhất lại danh sách thành phần kiến trúc: hoặc bổ sung "Update service" thành một thành phần độc lập thứ 7 trong file Kiến trúc, hoặc làm rõ trong cả 4 file rằng update service là một tiến trình con nằm trong phạm vi "khối thứ sáu" chứ không phải một service ngang hàng với service điều phối chính. |
| Business Rules mô tả vòng đời (state machine) của file trong Quarantine gồm nhiều trạng thái (`Active`, `PendingManualConfirmation`, `Quarantined`, `Restored`), nhưng schema `QuarantineRecord` trong file Dữ liệu không có trường nào lưu trạng thái hiện tại của bản ghi để theo dõi các trạng thái này. | business-rules/05-nghiep-vu.md (mục "File trong Quarantine") | data-models/04-du-lieu.md (mục "QuarantineRecord") | Bổ sung một trường trạng thái (ví dụ `status`) vào schema `QuarantineRecord` trong file Dữ liệu để phản ánh đúng vòng đời đã mô tả ở Business Rules, hoặc nếu trạng thái được suy ra gián tiếp từ sự tồn tại/không tồn tại của bản ghi, cần ghi chú rõ điều này trong file Dữ liệu. |


## Nguồn tham chiếu
- (không có, xem TODO trong nội dung)
