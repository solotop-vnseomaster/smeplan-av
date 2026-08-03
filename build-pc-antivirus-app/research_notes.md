# Research notes (internal — not shown to reader)

## Step 1-3: Expand → Deepen → Filter (summary)

Expand pool (20 candidates) covered: phân biệt app hệ thống thật vs giả mạo tên/đường dẫn;
thứ tự nạp ELAM driver lúc boot; ký số driver qua attestation/WHQL và Secure Boot; deep
scan hàng triệu file không chặn I/O người dùng; on-access scanning không gây độ trễ mở
file; phát hiện threat chưa có signature (zero-day); theo dõi thư mục Downloads qua nhiều
trình duyệt (file tạm rồi rename); xử lý zip bomb khi quét sâu; UI tùy biến quyền tự nó
không thành vector tấn công; đăng ký với Windows Security Center mà không xung đột
Defender; hai AV engine tranh chấp file lock; false positive với dev tool hợp lệ; khôi phục
khi quarantine nhầm file hệ thống; sống sót qua Windows feature update đổi driver ABI;
chống người dùng/malware tắt AV qua Task Manager; đo real-time protection có chặn EICAR
trước khi file chạm đĩa; đo độ phủ deep scan (hidden file, ADS); xác nhận flow ký số
test-signing vs production trước khi ship; đo latency thêm vào mỗi lần mở file; xác nhận
whitelist app Windows không bị giả mạo.

Sau khi áp deepening (đổi chủ thể — máy có Secure Boot bật/tắt; thêm ràng buộc tài nguyên —
laptop cũ ổ HDD; đảo ngược — "làm sao để driver KHÔNG được nạp?"; yêu cầu đo lường — độ trễ
tính bằng ms; đào mechanism — chính xác API nào chặn IRP) và lọc theo 3 tiêu chí (boundary
condition thật, có thể verify, loại được ít nhất 1 câu trả lời sai), 9 câu hỏi sau được
chọn vì tác động lớn nhất đến cấu trúc bài và có thể trả lời chắc chắn:

## Final ranked questions + 3-beat answers

### Q1: Làm sao phân biệt đáng tin cậy một file thực thi Windows gốc thật với một malware giả mạo cùng tên/đường dẫn (ví dụ svchost.exe đặt sai thư mục), theo cách không thể bị qua mặt chỉ bằng cách copy file vào System32?

**Trả lời**: Không dựa vào tên file hay đường dẫn làm tiêu chí chính — cả hai đều copy
được. Tiêu chí đáng tin cậy là: (1) chữ ký số Authenticode với certificate chain dẫn về
Microsoft Root CA còn hiệu lực (kiểm bằng WinVerifyTrust hoặc Get-AuthenticodeSignature),
(2) publisher name khớp đúng "Microsoft Windows" trong subject của cert, (3) đối chiếu vị
trí file có nằm trong thư mục được bảo vệ bởi Windows Resource Protection (WRP) hay không
— các thư mục như System32 được ACL bảo vệ nên một tiến trình thường không tự ghi được vào
đó nếu không có quyền TrustedInstaller. Kết hợp cả ba điều kiện, không dùng riêng lẻ.

**Tự vấn điểm yếu**: Nếu Windows Update hoặc bản thân Windows bị OS-level compromise
(rootkit chiếm quyền TrustedInstaller), chữ ký số vẫn hợp lệ dù binary đã bị tráo — vậy cơ
chế này còn tin cậy không?

**Trả lời câu tự vấn**: Đúng, đây là giới hạn thật của cách tiếp cận signature-based — nó
bảo vệ khỏi malware giả mạo bằng cách "đặt file cùng tên", không bảo vệ khỏi rootkit đã có
quyền hệ thống để ký lại hoặc thay thế binary hợp lệ. Vì vậy tài liệu này trình bày kiểm
tra chữ ký số + vị trí thư mục như tuyến phòng thủ đầu (chặn 99% trường hợp giả mạo phổ
biến), không phải giải pháp chống rootkit toàn diện — việc đó cần kernel integrity
monitoring nằm ngoài phạm vi bài.

### Q2: Driver ELAM (Early Launch Antimalware) phải được nạp theo thứ tự nào lúc boot để có tác dụng, và điều gì xảy ra nếu đăng ký sai nhóm load-order?

**Trả lời**: Windows Boot Manager nạp driver theo group thứ tự được định nghĩa trong
`HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder`. Driver ELAM phải được đăng ký
với `Start = 0` (SERVICE_BOOT_START) và group `"Early-Launch"`, group này được xếp trước
tất cả group driver boot-start khác. Windows gọi vào driver ELAM đã đăng ký (thông qua
callback `IoRegisterBootDriverCallback` không dùng nữa — cơ chế thực tế là driver ELAM
implement `AmClassificationCallback` được Boot Manager gọi cho từng driver boot-start
khác trước khi driver đó được phép nạp) để trả về phân loại
Good/Bad/BadCritical/Unknown, dùng để quyết định driver đó có được nạp tiếp hay không.

**Tự vấn điểm yếu**: Có chắc tên callback và cơ chế gọi (`AmClassificationCallback`) là
chính xác 100% theo tài liệu WDK hiện hành không?

**Trả lời câu tự vấn**: [KHÔNG CHẮC: tên chính xác của callback entry point ELAM trong
phiên bản WDK hiện tại] — cơ chế tổng thể (group "Early-Launch", boot-start, phân loại
good/bad/unknown) là chắc chắn và ổn định qua nhiều năm, nhưng tên hàm callback cụ thể cần
đối chiếu lại trong Windows Driver Kit samples (`elamsample` trong WDK) tại thời điểm code
thật — bài viết sẽ nêu cơ chế và hướng người đọc tới sample chính thức của WDK thay vì
khẳng định tên hàm.

### Q3: Driver kernel-mode của app cần ký số theo quy trình nào để nạp được trên máy bật Secure Boot, và điều gì xảy ra nếu chỉ dùng test-signing?

**Trả lời**: Từ Windows 10 bản 1607 trở đi, driver kernel-mode mới phải được ký bởi chính
Microsoft mới nạp được trên máy Secure Boot bật ở chế độ mặc định — self-signed hay
CA thương mại thông thường không đủ. Quy trình thực tế: đăng ký tài khoản Microsoft
Partner Center (Hardware program), có EV Code Signing Certificate đứng tên công ty, build
driver, nộp qua Partner Center để được "attestation signing" (ký tự động, không cần HLK
test đầy đủ — dành cho driver không phải WHQL) hoặc "WHQL signing" (yêu cầu pass Hardware
Lab Kit test, cần cho driver antivirus muốn đạt độ tin cậy cao nhất). Test-signing
(`bcdedit /set testsigning on`) chỉ dùng được trên máy dev đã bật chế độ này thủ công —
không chạy được trên máy người dùng thật vì Secure Boot sẽ chặn, và bật testsigning cũng
hiện watermark trên desktop nên không dùng được cho bản phát hành.

**Tự vấn điểm yếu**: Attestation signing và WHQL signing khác nhau thế nào về mức độ tin
cậy mà driver antivirus thực sự cần?

**Trả lời câu tự vấn**: Attestation signing đủ để driver nạp được trên máy Secure Boot,
nhưng không đảm bảo driver tương thích/ổn định trên mọi phần cứng — vì bỏ qua HLK test.
Với driver cấp antivirus (minifilter chặn I/O, ELAM), khuyến nghị thực tế đi thẳng tới
WHQL/HLK ngay từ bản beta nội bộ, vì driver antivirus lỗi có thể gây blue screen ảnh hưởng
trực tiếp đến việc máy người dùng có boot được hay không — rủi ro này cao hơn nhiều loại
driver khác.

### Q4: Deep scan toàn ổ đĩa với hàng triệu file cần thực hiện thế nào để không làm máy người dùng bị treo hoặc phản hồi chậm khi họ vẫn đang dùng máy?

**Trả lời**: Ba kỹ thuật kết hợp: (1) enumerate file bằng `FindFirstFile`/`FindNextFile`
hoặc USN Journal (đọc `$MFT` qua `FSCTL_ENUM_USN_DATA`) thay vì đệ quy thư mục thông
thường — USN Journal cho phép liệt kê toàn bộ file trên volume NTFS nhanh hơn nhiều lần so
với duyệt cây thư mục; (2) giới hạn I/O bằng cách gọi hàm đọc file ở priority thấp
(`SetPriorityClass` cho tiến trình scan = `PROCESS_MODE_BACKGROUND_BEGIN`, đồng thời dùng
`SetFileIoOverlappedRange`/`I/O priority hint` = Low qua `NtSetInformationFile` với
`FileIoPriorityHintInformation`) để scheduler ưu tiên I/O của người dùng trước; (3) chia
việc quét thành các batch nhỏ, chạy đa luồng có giới hạn (thread pool cỡ = số core - 1),
và tạm dừng/giảm tốc khi phát hiện người dùng đang tương tác (theo dõi input idle time qua
`GetLastInputInfo`).

**Tự vấn điểm yếu**: Nếu máy có ổ HDD cũ (không phải SSD), các kỹ thuật hạ priority I/O
có đủ để tránh giật lag không, khi bản thân seek time của HDD đã là bottleneck?

**Trả lời câu tự vấn**: Không đủ nếu chỉ hạ priority — trên HDD, đọc ngẫu nhiên hàng loạt
file nhỏ trong lúc scan gây seek thrashing bất kể priority nào, vì đầu đọc vật lý phải di
chuyển liên tục giữa yêu cầu của scan engine và yêu cầu của người dùng. Giải pháp thực tế
trên HDD là sắp xếp thứ tự đọc file theo vị trí cluster vật lý trên đĩa (đọc bằng
`FSCTL_GET_RETRIEVAL_POINTERS` để lấy vị trí cluster rồi sort theo LBA trước khi quét) để
giảm số lần seek, và mặc định giảm số luồng song song xuống 1 khi phát hiện ổ đĩa không
phải SSD (kiểm bằng `DeviceIoControl` với `IOCTL_STORAGE_QUERY_PROPERTY` /
`StorageDeviceSeekPenaltyProperty`).

### Q5: Real-time protection (on-access scanning) cần được implement thế nào để không gây độ trễ nhận biết được khi người dùng mở file, và có thể đo mức trễ đó bằng cách nào?

**Trả lời**: Đăng ký minifilter driver qua Filter Manager (`FltRegisterFilter`) với một
"altitude" xin cấp từ Microsoft (dải altitude dành cho antivirus là 320000-329999) và hook
`IRP_MJ_CREATE` ở pre-operation callback. Khi file được mở, callback tạm giữ request, gửi
thông tin file (đường dẫn, hash nếu đã cache) xuống user-mode service qua
`FltSendMessage`/port communication để service quyết định scan hay bỏ qua, sau đó trả kết
quả lại driver để driver cho phép hoặc chặn open. Để giảm trễ: cache kết quả "đã scan sạch"
theo hash + thời gian sửa đổi file (nếu file không đổi từ lần scan trước thì bỏ qua),
và chỉ scan đồng bộ (chặn open) với file thực thi (.exe, .dll, .ps1...) — file dữ liệu
thông thường có thể scan bất đồng bộ sau khi đã cho mở. Đo độ trễ bằng cách log timestamp
tại thời điểm callback nhận IRP và thời điểm trả kết quả, tính delta theo microsecond qua
`QueryPerformanceCounter`.

**Tự vấn điểm yếu**: Ngưỡng độ trễ "chấp nhận được" là bao nhiêu mili giây cụ thể, và con
số đó lấy từ đâu?

**Trả lời câu tự vấn**: [KHÔNG CHẮC: một con số ngưỡng chính thức chung của ngành] — không
có chuẩn công khai bắt buộc, nhưng thực hành phổ biến của các AV thương mại là giữ overhead
mở file thực thi dưới khoảng 5-10ms cho file đã cache/sạch, và chấp nhận vài chục tới hơn
100ms cho lần quét đầu tiên của một file mới lớn — vì vậy bài viết sẽ trình bày đây là mục
tiêu kỹ thuật hợp lý cần tự đo trên phần cứng thật của mình bằng benchmark trước/sau khi
bật driver, không khẳng định đây là con số chuẩn bắt buộc của ngành.

### Q6: Theo dõi thư mục Downloads cần xử lý thế nào để không quét nhầm file khi nó chưa tải xong, khi các trình duyệt khác nhau (Chrome, Edge, Firefox) đều lưu file tạm rồi mới đổi tên?

**Trả lời**: Đăng ký `ReadDirectoryChangesW` (user-mode, đơn giản hơn minifilter cho use
case này) trên thư mục Downloads với cờ `FILE_NOTIFY_CHANGE_FILE_NAME`. Các trình duyệt
Chromium-based (Chrome, Edge) lưu file tạm với đuôi `.crdownload` trong lúc tải, Firefox
dùng `.part`; khi tải xong, trình duyệt gọi `MoveFile`/rename bỏ đuôi tạm. Sự kiện cần bắt
là `FILE_ACTION_RENAMED_NEW_NAME`, không phải `FILE_ACTION_ADDED` (file tạm) — quét ngay
khi thấy action "added" sẽ hoặc quét file rỗng/chưa đầy đủ, hoặc bị lock bởi trình duyệt
gây lỗi đọc. Sau khi bắt được rename thành tên cuối, đợi thêm một khoảng ngắn kiểm tra file
không còn bị handle nào khác giữ (`CreateFile` với `FILE_SHARE_READ` thất bại nghĩa là vẫn
đang bị khóa) trước khi bắt đầu quét.

**Tự vấn điểm yếu**: Điều gì xảy ra nếu người dùng tải file trực tiếp bằng công cụ dòng
lệnh (`curl`, `wget`) hoặc app khác không dùng cơ chế đuôi tạm này?

**Trả lời câu tự vấn**: Trường hợp này `ReadDirectoryChangesW` vẫn bắt được sự kiện
`FILE_ACTION_ADDED` với tên file cuối cùng ngay lập tức vì không có bước rename trung
gian — nhưng file có thể vẫn đang được ghi dở dang. Giải pháp chung cho cả hai trường hợp
là không quét ngay tại sự kiện, mà đưa file vào hàng đợi và chỉ quét khi handle ghi cuối
cùng đã đóng — kiểm tra bằng cách polling `CreateFile` mở exclusive cho tới khi thành công,
hoặc dùng `FltRegisterFilter` với `IRP_MJ_CLEANUP` nếu đã có sẵn minifilter cho real-time
protection (Q5) để tái sử dụng cùng cơ chế thay vì polling.

### Q7: Khi quét sâu gặp file nén (zip, rar) lồng nhau nhiều lớp, làm sao tránh bị "zip bomb" (file nén rất nhỏ nhưng giải nén ra hàng chục GB) làm hết dung lượng đĩa hoặc bộ nhớ?

**Trả lời**: Không giải nén toàn bộ ra đĩa trước khi quét. Dùng streaming decompression
(đọc và quét từng buffer ngay khi giải nén, không ghi hết ra file tạm) kết hợp ba giới hạn
cứng: (1) tỷ lệ nén tối đa cho phép — nếu dung lượng giải nén ước tính vượt quá X lần
(ví dụ 100 lần) dung lượng file nén gốc thì dừng và gắn cờ nghi ngờ thay vì tiếp tục giải
nén; (2) giới hạn độ sâu lồng nhau (ví dụ tối đa 5 lớp zip trong zip); (3) giới hạn tổng
dung lượng giải nén tuyệt đối cho một file (ví dụ dừng ở 1GB dù tỷ lệ nén chưa vượt
ngưỡng). Đọc header của định dạng nén trước (kích thước uncompressed ghi trong local file
header của ZIP) để ước tính tỷ lệ mà không cần giải nén thật.

**Tự vấn điểm yếu**: Header ZIP ghi kích thước uncompressed có thể bị làm giả (zip bomb
kinh điển như "42.zip" cố tình khai sai) — vậy ước tính từ header có đáng tin không?

**Trả lời câu tự vấn**: Đúng là không nên tin tuyệt đối vào con số trong header vì có thể
bị chỉnh sai để đánh lừa bộ ước tính. Vì vậy giới hạn (2) và (3) — độ sâu lồng nhau và trần
dung lượng giải nén tuyệt đối, đo trong lúc giải nén thực tế chứ không chỉ đọc header —
mới là tuyến phòng thủ chính; con số trong header chỉ dùng để lọc nhanh trường hợp rõ ràng
mà không cần giải nén, không phải cơ chế bảo vệ duy nhất.

### Q8: Khi engine heuristic gắn cờ nhầm một công cụ hợp lệ (ví dụ một packer mà lập trình viên hợp pháp dùng để nén .exe), quy trình xử lý false positive nên chạy như thế nào để không lặp lại?

**Trả lời**: Ba lớp: (1) trước khi enforce block, mọi rule heuristic mới nên chạy ở chế độ
"log only" trên một tỷ lệ người dùng nhỏ (nếu có telemetry) hoặc nội bộ trong thời gian
thử nghiệm, thu thập tỷ lệ match trên tập file sạch đã biết (ví dụ toàn bộ file trong
`Program Files` của một máy Windows sạch) trước khi bật chế độ chặn thật; (2) khi người
dùng gặp false positive, cho phép họ "khôi phục từ quarantine + thêm ngoại lệ theo hash cụ
thể" (không phải ngoại lệ theo tên file, vì tên có thể trùng với file độc hại khác) —
ngoại lệ theo hash đảm bảo không vô tình whitelist một bản malware khác cùng tên; (3) đưa
hash + rule đã gây false positive vào một danh sách "cần review" nội bộ để tinh chỉnh rule
heuristic đó, tránh gắn cờ lại các biến thể tương tự của cùng công cụ hợp lệ.

**Tự vấn điểm yếu**: Whitelist theo hash cụ thể có tác dụng gì khi lập trình viên đó build
lại tool của họ (hash thay đổi mỗi lần build)?

**Trả lời câu tự vấn**: Đúng, whitelist theo hash tuyệt đối sẽ vô tác dụng cho case build
liên tục — với các publisher build thường xuyên (CI/CD của chính người dùng), cơ chế bổ
sung cần là whitelist theo chữ ký số của publisher (nếu tool được ký) hoặc theo signing
certificate thumbprint của chính người dùng (self-signed cert dùng nội bộ), thay vì theo
hash. Bài viết sẽ trình bày cả hai lớp whitelist (theo hash cho trường hợp file tĩnh,
theo publisher/cert cho trường hợp build liên tục) thay vì chỉ một.

### Q9: App cần làm gì để được Windows Security Center công nhận là antivirus provider đang hoạt động (thay vì bị Windows Defender coi là chưa có AV nào bảo vệ máy), và điều gì xảy ra nếu chỉ tự gọi API mà không qua quy trình chính thức?

**Trả lời**: Đây là điểm dễ hiểu nhầm nhất: không có một API công khai đơn giản nào để
một ứng dụng tự "đăng ký" mình làm AV provider và được Windows tin ngay. Con đường thực tế
là tham gia chương trình **Microsoft Virus Initiative (MVI)** — yêu cầu công ty đạt chứng
nhận từ một phòng test độc lập được Microsoft công nhận (ví dụ AV-Test, AV-Comparatives,
hoặc ICSA Labs) và tuân thủ bộ yêu cầu kỹ thuật của MVI (bao gồm việc phải tự cung cấp bộ
phát hiện thật, không giả lập). Sau khi được chấp nhận vào MVI, Microsoft mới cấp quyền để
sản phẩm đăng ký hiển thị trong Windows Security Center qua interface WSC dành riêng cho
provider đã được duyệt. Nếu tự ý gọi các API/registry key liên quan đến WSC provider mà
không qua MVI, Windows sẽ không công nhận app là AV hợp lệ — Windows Defender vẫn coi máy
là "không có bảo vệ của bên thứ 3" và có thể tự bật lại real-time protection của chính nó
song song, gây xung đột file lock giữa hai engine.

**Tự vấn điểm yếu**: Trong giai đoạn phát triển/học tập (chưa qua MVI), người đọc bài này
có cách nào hợp lệ để test app của họ chạy song song Defender mà không xung đột không?

**Trả lời câu tự vấn**: Có — trong giai đoạn phát triển, cách hợp lệ và thực tế là chủ
động đưa thư mục cài đặt và tiến trình của app vào danh sách loại trừ (exclusion) của
Windows Defender qua PowerShell (`Add-MpPreference -ExclusionPath`/`-ExclusionProcess`),
để hai engine không cùng tranh chấp lock trên cùng file trong lúc dev/test. Đây chỉ là
giải pháp tạm cho môi trường phát triển, không phải giải pháp cho bản phát hành thật —
bản phát hành thật vẫn cần đi qua MVI nếu muốn được công nhận chính thức trong Security
Center.
