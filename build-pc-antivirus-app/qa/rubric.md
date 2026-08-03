# QA rubric — bài "Tự Xây Antivirus Windows"

Lint script: `hard: 0  review: 0  soft: 4` (4 soft = near-duplicate giữa các dòng code
trong cùng snippet minh họa, ví dụ cặp `WinVerifyTrust(...)` gọi verify rồi gọi close,
hoặc `InitializeProcThreadAttributeList` gọi hai lần theo đúng idiom Windows API — không
phải lặp câu văn xuôi, chấp nhận được).

| # | Check | Kết quả | Ghi chú |
|---|---|---|---|
| 1 | Bám sát topic_summary, không chạm out_of_scope | PASS | Không đề cập mobile/macOS/Linux, ML training, reverse engineering, EDR/XDR doanh nghiệp |
| 2 | Mọi in_scope item được một section phục vụ | PASS | 31 in_scope item khớp với 34 section trong outline |
| 3 | Mọi explicit_requirement được đáp ứng đầy đủ | PASS (HARD) | 4 chức năng cốt lõi đều có section riêng: whitelist app gốc (5-10), deep scan (13-19), real-time (20-23), Downloads (24-25); có code minh họa đầy đủ |
| 4 | objective được thể hiện qua cấu trúc bài | PASS | Bài đi từ kiến trúc đến từng cơ chế cụ thể, kết thúc bằng checklist phát hành |
| 5 | depth (Practitioner) nhất quán | PASS | Không định nghĩa lại thuật ngữ cơ bản, đi thẳng vào cơ chế và API cụ thể |
| 6 | Depth Expert: đối chiếu common vs correct practice | N/A | depth = Practitioner, không áp dụng |
| 7 | Không section nào đọc như đoạn bị cắt cụt | PASS | Mỗi section có mở-triển khai-kết đầy đủ |
| 8 | Có ít nhất một ví dụ điền đầy đủ, không placeholder | PASS | Nhiều ví dụ hoàn chỉnh: code C WinVerifyTrust, WDAC XML, YARA rule, USN Journal, PPL, chuỗi EICAR, PowerShell exclusion |
| 9 | Có section lỗi thường gặp/gotchas | PASS | Section 34 "Những lỗi thường gặp khi tự xây antivirus" |
| 10 | Không còn marker [KHÔNG CHẮC]/[UNSURE] nào | PASS (HARD) | Đã sửa section 22 (ELAM callback), grep xác nhận 0 marker còn lại |
| 11 | Không có em-dash | PASS | Đã thay toàn bộ 123 em-dash bằng dấu phẩy/câu, lint xác nhận 0 |
| 12 | Không có CTA, không có FAQ riêng | PASS | Không có |
| 13 | Không section nào mở đầu bằng bullet list | PASS | Mọi section có câu văn xuôi mở đầu trước bullet (nếu có) |
| 14 | Không có meta-commentary về quá trình viết/nghiên cứu | PASS (HARD) | Không có |
| 15 | reader_secondary được điều chỉnh giọng văn tại chỗ liên quan | PASS | Giải thích cơ chế (không chỉ code) phục vụ cả người học bảo mật hệ thống |
| 16 | Không nhắc lại knowledge_gap/objective nguyên văn | PASS | Không có câu kiểu "lỗ hổng kiến thức của bạn là..." |
| 17 | Không có hai section trùng nội dung | PASS (HARD) | Các cặp section gần nhau (5-7, 20-21, 24-25) mỗi section có góc độ riêng biệt |
| 18 | Không có heading lộ số thứ tự pipeline | PASS (HARD) | Heading là tên nội dung thật, không có "Part X/Y" |
| 19 | Không section nào mở bằng câu recap ("như đã nói ở trên...") | PASS | Câu mở đầu luôn là nội dung mới của section đó |
| 20 | Không section nào kết bằng lời mời kiểu chat | PASS (HARD) | Mọi section kết bằng nội dung thực chất |
| 21 | Toàn bộ code/lệnh/config nằm trong fenced block | PASS (HARD) | Lint xác nhận không có code ngoài fence |
| 22 | Không có câu lặp gần như nguyên văn ở hai chỗ khác nhau | PASS (soft) | 4 flag còn lại đều là dòng code idiom lặp lại tự nhiên (verify/close, init x2), không phải câu văn xuôi |
| — | Title ≤ 60 ký tự | PASS | 57 ký tự |
| — | Intro ≤ 60 từ | PASS | 59 từ |

Không còn hard-fail nào sau vòng sửa đầu tiên (fix marker [KHÔNG CHẮC] ở section 22 và
thay toàn bộ em-dash). Bài sẵn sàng đóng gói.
