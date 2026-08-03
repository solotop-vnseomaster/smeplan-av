# Quy tắc chi tiết cho document-executor

Chi tiết cho các bước trong SKILL.md — chỉ tra cứu khi gặp đúng tình huống
biên, không cần đọc hết mỗi lần chạy skill.

## Tiêu chí phân loại mức độ mơ hồ (bước 2)

Một mục trong tài liệu như "xử lý lỗi hợp lý" hay "hiệu năng tốt" không đủ
cụ thể để triển khai mà không đoán.

- **Cần hỏi**: nếu một cách hiểu sai *sẽ khiến người dùng phải yêu cầu sửa
  lại sau khi thấy kết quả chạy*. Ví dụ "xử lý lỗi hợp lý" có thể là dừng
  ngay hay chỉ ghi log rồi tiếp tục — hai hành vi khác hẳn nhau.
- **Không cần hỏi**: nếu chọn sai không ai nhận ra hoặc không ảnh hưởng gì
  tới việc dùng phần mềm (ví dụ đặt tên biến nội bộ).

Gom tất cả các điểm mơ hồ cùng loại thành một câu hỏi duy nhất qua
AskUserQuestion, có sẵn lựa chọn cụ thể để người dùng chọn nhanh, hỏi một
lần trước khi triển khai thay vì dừng lại nhiều lần giữa chừng.

## Whitelist sửa nhỏ không cần hỏi (bước 5)

Ranh giới đúng không nằm ở *kích thước* thay đổi mà ở việc thay đổi có làm
khác đi *ý nghĩa/yêu cầu* của tài liệu hay không. Vì việc tự phán "có đổi ý
nghĩa hay không" vẫn nằm trong tay chính người thực thi (dễ tự thuyết phục
rằng mình chỉ đang "làm rõ"), dùng whitelist theo *loại hành động*, không
dựa trên phán đoán ý nghĩa:

**Được phép tự sửa, không cần hỏi** (chỉ những mục này):
- Lỗi chính tả, dấu câu trong phạm vi 1-2 từ.
- Định dạng markdown không đổi nội dung (thụt đầu dòng, dấu gạch đầu dòng,
  khoảng trắng).

**Mọi hành động khác** tạo ra hoặc thay thế nội dung của một đoạn văn/mục
trong tài liệu, kể cả khi mục đích là "làm rõ" hay "sửa cho đúng ngữ pháp"
ở cấp câu trở lên, mặc định cần xác nhận trước, không tự làm.

## Phân biệt mệnh lệnh với nhận xét

Chỉ coi là yêu cầu hành động khi có động từ nhắm thẳng vào tài liệu ("viết
lại", "sửa file này thành...", "tạo bản mới cho tôi"). Một câu như "tài
liệu này hơi rối" là mô tả cảm nhận, không phải lệnh — gặp câu này, hỏi lại
ý định thay vì tự hiểu thành "hãy viết lại giúp tôi".

## Trình tự xác nhận khi thay đổi vượt whitelist

Dùng AskUserQuestion với các lựa chọn cụ thể, ví dụ:
- "Tạo file mới riêng, giữ nguyên tài liệu gốc"
- "Ghi đè trực tiếp lên tài liệu gốc"
- "Không làm, tiếp tục theo tài liệu hiện tại"

Chỉ hành động sau khi có lựa chọn rõ ràng từ người dùng.

## Ngăn hành vi tự tạo file "phiên bản khác" song song

Khe hở thường gặp: tạo một file mới cạnh tài liệu gốc (`spec-v2.md`,
`spec-final.md`, `requirements-clean.md`, `tai-lieu-tom-tat.md`...) mà
không coi đó là "sửa tài liệu gốc", vì kỹ thuật thì tài liệu gốc không hề
bị đụng tới.

Không tự tạo bất kỳ file nào có nội dung trùng lặp phần lớn với tài liệu
gốc, dù đặt tên khác, trừ khi người dùng yêu cầu rõ ràng qua bước xác nhận
ở trên. Việc tài liệu gốc không bị đụng tới **không miễn trừ** cho việc tạo
bản sao song song — hai hành vi này cùng một mức độ vi phạm.

`features.md` không vi phạm quy tắc này vì nó là checklist có cấu trúc
khác hẳn (danh sách ngắn, có trạng thái), không phải một bản viết lại của
văn bản gốc.

## Phép kiểm tra "sắp viết lại" trước khi ghi file

Trước khi ghi bất kỳ file `.md`/`.txt` mới nào ngoài `features.md`, tự hỏi:
nội dung file này có trùng lặp phần lớn câu/đoạn với tài liệu gốc không?
Nếu có, đây là dấu hiệu sắp tạo ra một "phiên bản khác" — dừng lại, áp dụng
quy tắc xác nhận ở trên, không ghi file cho tới khi có xác nhận.

`scripts/diff_guard.py` là lớp kiểm tra độc lập chạy *sau khi* file đã
được ghi, dùng để phát hiện vi phạm đã xảy ra trong lúc test — bổ trợ cho
phép tự kiểm ở trên, không thay thế nó.

## Hai chiều đối xứng của "đầy đủ"

- Không bỏ sót tính năng có trong tài liệu.
- Không bịa thêm tính năng/endpoint/ràng buộc không có trong tài liệu, kể
  cả khi nó "nên có" theo kinh nghiệm chung.

Nếu phát hiện thiếu sót đáng kể trong tài liệu (ví dụ lỗ hổng bảo mật rõ
ràng), không tự thêm — ghi thành một mục riêng trong `features.md` với
nhãn `[ĐỀ XUẤT: CHƯA CÓ TRONG SPEC]` và báo lại cho người dùng cuối phiên.
