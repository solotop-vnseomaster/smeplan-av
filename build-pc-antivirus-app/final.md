# Tự Xây Antivirus Windows: Kiểm Quyền, Quét Sâu, Real-time

Bài viết trình bày kiến trúc đầy đủ để tự xây antivirus Windows: mặc định tin cậy app gốc hệ thống, cho tùy biến quyền với app bên thứ 3, quét sâu toàn ổ đĩa, phát hiện sớm theo thời gian thực và giám sát thư mục Downloads, minh họa bằng C++ cho engine/driver và C#/.NET cho giao diện.

## Tổng quan kiến trúc app antivirus Windows

Một app antivirus hoạt động được trên Windows luôn tách thành năm khối riêng biệt, chạy ở hai tầng quyền khác nhau, và giao tiếp với nhau qua kênh có kiểm soát chứ không gọi trực tiếp lẫn nhau.

Ở tầng user-mode có ba khối: giao diện người dùng (UI) chỉ chịu trách nhiệm hiển thị và nhận thao tác, không tự xử lý logic phát hiện; service nền chạy dưới quyền SYSTEM, sống độc lập với UI (để khi người dùng đóng cửa sổ, bảo vệ vẫn tiếp tục chạy) và giữ toàn bộ logic điều phối; scan engine là thư viện xử lý việc quét file thực tế, được service nền gọi vào, dùng chung cho cả full scan lẫn real-time scanning để không phải viết hai bộ logic phát hiện khác nhau cho hai luồng.

Ở tầng kernel-mode có hai khối bắt buộc nếu muốn có real-time protection thật sự: driver ELAM (Early Launch Antimalware) nạp sớm nhất trong quá trình boot để phân loại các driver boot-start khác, và minifilter driver chặn thao tác mở/đọc/ghi file ở cấp filesystem trước khi Windows cho phép thao tác đó hoàn tất. Hai driver này giao tiếp ngược lên service nền qua filter communication port (`FltCreateCommunicationPort`), vì logic quét phức tạp (heuristic, YARA, tra CSDL hash) không nên và không thể chạy trong kernel, code kernel-mode lỗi gây blue screen ngay lập tức, nên nguyên tắc thiết kế là giữ kernel-mode càng mỏng càng tốt: chỉ chặn và hỏi, không tự quyết định.

Khối thứ sáu, nằm ngoài vòng đời chạy nhưng vẫn là một phần kiến trúc, là CSDL signature cùng cơ chế cập nhật, được lưu cục bộ dưới dạng file (không phải chạy trong process) để cả scan engine lẫn driver có thể tra cứu nhanh mà không phụ thuộc kết nối mạng liên tục. Các phần tiếp theo của bài đi sâu vào từng khối này, bắt đầu từ việc chọn công cụ và ngôn ngữ phù hợp cho từng tầng.

## Lựa chọn ngôn ngữ và stack kỹ thuật

Driver kernel-mode (ELAM và minifilter) chỉ có hai lựa chọn thực tế: C hoặc C++ giới hạn (không exception, không STL đầy đủ), viết trên Windows Driver Kit (WDK). Rust đang được Microsoft thử nghiệm cho driver qua dự án `windows-drivers-rs`, nhưng tính đến thời điểm viết bài, hệ sinh thái sample và tài liệu cho driver antivirus vẫn xoay quanh C/C++, chọn Rust ở tầng này nghĩa là tự vá phần lớn tooling, chỉ hợp lý nếu team đã có kinh nghiệm Rust kernel sâu.

Ở tầng scan engine (user-mode nhưng xử lý nặng: hash, YARA, heuristic), C++ vẫn là lựa chọn mặc định vì hai lý do cụ thể: engine này phải load được từ cả service .NET lẫn có thể tái sử dụng logic tương tự (hoặc gọi chung) từ context driver-adjacent, và hiệu năng xử lý hàng triệu file khi full scan nhạy với overhead runtime, GC pause của .NET hay Java giữa lúc quét hàng loạt file nhỏ tạo ra độ trễ không đoán trước được, điều tối kỵ với real-time protection.

Ở tầng UI và service điều phối, C#/.NET (WinUI 3 hoặc WPF cho UI, Windows Service viết bằng .NET cho service nền) hợp lý hơn C++ thuần vì tốc độ phát triển UI nhanh hơn, có sẵn binding tốt với Windows Security Center API và dễ maintain hơn về lâu dài, phần này không nằm trên đường găng về hiệu năng nên đánh đổi này chấp nhận được. Giao tiếp giữa service C# và scan engine C++ qua P/Invoke hoặc COM interop, giữa service và driver qua `DeviceIoControl`/filter port.

Kết hợp ba tầng ngôn ngữ này, không cố gò về một ngôn ngữ duy nhất, là cách các sản phẩm antivirus thương mại thực tế đang tổ chức code, và các phần code minh họa trong bài dùng đúng cách chia này: pseudo-code kernel/scan engine viết theo phong cách C/C++, phần UI/rule storage viết theo phong cách C#.

## Yêu cầu và rào cản của Windows với phần mềm bảo mật

Từ Windows 10 phiên bản 1607 trở đi, một driver kernel-mode mới hoàn toàn (chưa từng được ký trước đó) chỉ nạp được trên máy bật Secure Boot ở cấu hình mặc định nếu nó được chính Microsoft ký, không có ngoại lệ cho self-signed certificate hay chứng chỉ từ CA thương mại thông thường, dù certificate đó hợp lệ cho việc ký ứng dụng thông thường. Đây không phải giới hạn kỹ thuật ngẫu nhiên: trước thời điểm này, rootkit ký bằng certificate bị đánh cắp hoặc certificate của công ty vỏ bọc là một trong những vector tấn công kernel phổ biến nhất, và việc bắt buộc ký qua Microsoft chuyển việc xác minh danh tính nhà phát triển về một điểm kiểm soát duy nhất mà Microsoft có thể thu hồi khi phát hiện lạm dụng.

Rào cản thứ hai là ELAM: Windows chỉ cho một số lượng driver ELAM giới hạn nạp ở giai đoạn boot sớm nhất, và để driver được công nhận là ELAM hợp lệ, nó phải mang certificate có Enhanced Key Usage (EKU) riêng cho Early Launch Antimalware, certificate này không tự xin được, phải qua chương trình đối tác của Microsoft. Việc giới hạn này tồn tại vì driver ELAM có quyền quyết định driver boot-start khác có được nạp hay không; nếu mở tự do, chính ELAM giả mạo sẽ trở thành cách hoàn hảo để chặn driver bảo mật thật của người khác nạp lên trước.

Rào cản thứ ba, ít được nói tới nhưng ảnh hưởng trực tiếp đến sản phẩm cuối, là việc Windows Security Center không mở API công khai để bất kỳ ai tự đăng ký app của mình là AV provider đang hoạt động, phần này được trình bày chi tiết ở mục về đăng ký với Windows Security Center. Ba rào cản trên không phải trở ngại nên né tránh mà là khung ràng buộc cần thiết kế app xoay quanh ngay từ đầu, vì thay đổi kiến trúc sau khi đã viết xong driver để đáp ứng chúng thường tốn công hơn nhiều so với thiết kế đúng từ mục tiếp theo.

## Thiết lập môi trường phát triển

Cài Visual Studio (bản Community đủ dùng cho phát triển, cần bản trả phí nếu công ty cần hỗ trợ chính thức) kèm hai workload bắt buộc: "Desktop development with C++" cho scan engine và UI C++ nếu có, cùng ".NET desktop development" cho phần WinUI3/WPF và service C#. Sau đó cài riêng Windows Driver Kit (WDK) khớp đúng phiên bản với Windows SDK đang dùng, WDK không tự cài kèm Visual Studio, phải tải riêng từ trang Hardware Dev Center và cài sau khi đã có Visual Studio, vì nó cắm thêm project template driver vào IDE.

Trên máy dev, bật test signing mode bằng lệnh `bcdedit /set testsigning on` rồi khởi động lại, để có thể nạp driver tự ký trong lúc phát triển mà không cần chờ quy trình ký chính thức của Microsoft, nhớ đây chỉ dùng được trên máy dev, không dùng được cho bản phát hành như đã nêu ở phần rào cản trước. Kèm theo đó, tạo self-signed test certificate bằng `MakeCert`/`New-SelfSignedCertificate` và đăng ký vào certificate store cục bộ (`Trusted Root` và `Trusted Publisher`) để Windows chấp nhận driver ký thử trong quá trình dev.

Song song, đăng ký sớm tài khoản Microsoft Partner Center (mục Hardware) ngay từ giai đoạn này chứ không đợi đến lúc gần phát hành, quy trình xác minh danh tính công ty và mua EV Code Signing Certificate (bắt buộc cho việc ký driver chính thức) thường mất vài ngày đến vài tuần, và không thể bắt đầu build kernel driver có thể ship được nếu chưa có certificate này. Checklist tối thiểu trước khi viết dòng code driver đầu tiên: Visual Studio + hai workload trên, WDK khớp phiên bản SDK, testsigning đã bật trên máy dev, self-signed cert đã cài, và đơn đăng ký Partner Center đã nộp.

## Nguyên tắc mặc định tin cậy ứng dụng gốc Windows

Đừng dùng tên file hay đường dẫn làm căn cứ chính để coi một tiến trình là "app Windows gốc", cả hai đều là chuỗi văn bản mà bất kỳ file nào cũng copy được nguyên xi. Một binary tên `svchost.exe` đặt trong `C:\Users\Public\svchost.exe` chứng minh chính xác điều đó: cùng tên, khác hoàn toàn về độ tin cậy.

Ba tiêu chí sau, dùng kết hợp cả ba chứ không tách rời, mới đủ để coi một tiến trình là app gốc Windows đáng tin cậy mặc định:

1. **Chữ ký số Authenticode hợp lệ với chain dẫn về Microsoft Root CA.** Certificate còn hiệu lực, chưa bị thu hồi, và chain xác thực đầy đủ tới root certificate của Microsoft chứ không dừng ở một intermediate CA lạ.
2. **Publisher name trong subject của certificate khớp chính xác** với các giá trị chính thức như "Microsoft Windows" hoặc "Microsoft Corporation", không chấp nhận so khớp gần đúng hay chứa chuỗi con, vì kỹ thuật giả mạo publisher name bằng ký tự Unicode trông giống hệt là có thật.
3. **Vị trí file nằm trong thư mục được Windows Resource Protection (WRP) bảo vệ**, ví dụ `C:\Windows\System32`, với ACL cho thấy chỉ `TrustedInstaller` mới có quyền ghi, nếu một file nằm đúng tên trong đúng thư mục nhưng ACL đã bị nới lỏng bất thường (không còn giữ nguyên quyền TrustedInstaller mặc định), đó là dấu hiệu đáng ngờ cần hạ mức tin cậy xuống thay vì tự động allow.

Chỉ khi cả ba điều kiện cùng đúng, engine mới gắn nhãn "trusted by default" cho tiến trình đó và không yêu cầu người dùng xác nhận quyền, bất kỳ điều kiện nào thiếu, tiến trình rơi vào nhóm "ứng dụng bên thứ 3" và đi qua luồng tùy biến quyền được trình bày ở các phần sau. Cách tiếp cận ba lớp này cũng là nền cho toàn bộ cơ chế whitelist mặc định, được hiện thực hóa cụ thể bằng code ở phần tiếp theo.

## Kiểm tra chữ ký số Authenticode để whitelist mặc định

Việc kiểm tra chữ ký số của một tiến trình dựa trên hàm `WinVerifyTrust` của Windows, gọi với action GUID `WINTRUST_ACTION_GENERIC_VERIFY_V2` trên đường dẫn file thực thi. Hàm này tự kiểm tra toàn bộ chain certificate, thời hạn hiệu lực và trạng thái thu hồi (revocation) nếu có kết nối mạng để kiểm tra CRL/OCSP, không cần tự viết lại logic xác thực chain.

```c
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>

BOOL IsSignedByMicrosoft(LPCWSTR filePath) {
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = filePath;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &action, &trustData);

    BOOL trusted = FALSE;
    if (status == ERROR_SUCCESS) {
        // Chain hợp lệ, tiếp tục kiểm tra publisher name khớp Microsoft
        trusted = CheckPublisherIsMicrosoft(filePath);
    }

    // Luôn giải phóng trust data theo state action WTD_STATEACTION_CLOSE
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &trustData);

    return trusted;
}
```

`CheckPublisherIsMicrosoft` không nằm trong API chuẩn, tự viết bằng cách lấy certificate chain qua `CertGetCertificateChain`, đọc trường Subject của leaf certificate qua `CertGetNameStringW` với `CERT_NAME_SIMPLE_DISPLAY_TYPE`, rồi so sánh chuỗi kết quả với danh sách publisher name chính thức đã biết trước (`"Microsoft Windows"`, `"Microsoft Corporation"`) bằng so khớp chuỗi chính xác, không dùng hàm chứa chuỗi con (`wcsstr`) để tránh bị qua mặt bằng publisher name chứa chuỗi Microsoft ở giữa một tên dài hơn.

Kết quả của hàm này ghép với điều kiện vị trí thư mục ở phần trước tạo thành điều kiện đủ để service nền quyết định gắn nhãn "trusted by default" cho một tiến trình mới sinh ra, trước khi nó chạm tới engine giám sát tiến trình theo thời gian thực.

## Giới hạn của whitelist theo chữ ký số

Cơ chế ba lớp ở hai phần trước bảo vệ đúng một loại tấn công cụ thể: malware cố tình mạo danh app Windows bằng cách đặt file trùng tên vào đúng thư mục hệ thống hoặc tự ký bằng certificate giả. Nó không bảo vệ khỏi trường hợp một rootkit đã chiếm được quyền hệ thống ở mức cao hơn cả TrustedInstaller, khi đó, kẻ tấn công có thể thay thế trực tiếp một binary hệ thống hợp lệ bằng bản đã chỉnh sửa nhưng giữ nguyên chữ ký số cũ (nếu chưa bị phát hiện thay đổi hash) hoặc lợi dụng lỗ hổng để chèn code vào tiến trình đã được whitelist mà không cần thay file trên đĩa.

Vì lý do này, whitelist theo chữ ký số cần được hiểu đúng vị trí của nó trong hệ thống phòng thủ: đây là tuyến chặn nhanh, chi phí thấp, xử lý được phần lớn trường hợp giả mạo phổ biến (kẻ tấn công không có quyền hệ thống sẵn, chỉ cố đặt file giả), không phải giải pháp chống rootkit toàn diện. Việc phát hiện code injection vào tiến trình đã tin cậy hay việc xác minh tính toàn vẹn kernel ở cấp sâu hơn đòi hỏi kỹ thuật khác, kernel integrity monitoring, giám sát thay đổi trong vùng nhớ tiến trình đang chạy, nằm ngoài phạm vi của app được mô tả trong bài này.

Hệ quả thiết kế cụ thể: whitelist theo chữ ký số chỉ nên dùng để quyết định có cần hỏi người dùng về quyền hay không (tầng kiểm soát ứng dụng, các phần tiếp theo), không nên dùng làm căn cứ duy nhất để loại trừ một tiến trình khỏi việc quét real-time. Ngay cả tiến trình đã được whitelist vẫn nên nằm trong phạm vi giám sát hành vi bất thường ở mức độ nhẹ hơn, thay vì bị loại trừ hoàn toàn khỏi mọi kiểm tra.

## Thiết kế chính sách kiểm soát ứng dụng bằng AppLocker/WDAC

Thay vì tự viết toàn bộ engine chặn thực thi từ đầu, tận dụng Windows Defender Application Control (WDAC), cơ chế enforcement cấp kernel đã có sẵn trong Windows, được chính app của bạn cấu hình qua policy XML thay vì phải tự viết driver chặn process creation từ số không. App tạo và deploy policy, Windows lo phần enforcement ở tầng thấp nhất.

Một policy WDAC tối giản, mặc định allow mọi thứ ký bởi Microsoft và chuyển phần còn lại về chế độ "audit" (ghi log thay vì chặn cứng, dùng trong giai đoạn đầu để tránh chặn nhầm) trông như sau:

```xml
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <Rules>
    <Rule>
      <Option>Enabled:Audit Mode</Option>
    </Rule>
    <Rule>
      <Option>Enabled:Unsigned System Integrity Policy</Option>
    </Rule>
  </Rules>
  <FileRules>
    <Allow ID="ID_ALLOW_MICROSOFT"
           FriendlyName="Allow Microsoft signed binaries"
           MinimumFileVersion="0.0.0.0" />
  </FileRules>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_WINDOWS">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_MICROSOFT" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <Signers>
    <Signer ID="ID_SIGNER_MICROSOFT" Name="Microsoft Windows Publisher">
      <CertRoot Type="TBS" Value="[thumbprint của Microsoft Root CA]" />
    </Signer>
  </Signers>
</SiPolicy>
```

Sau khi build policy XML này thành file `.cip` bằng công cụ `ConvertFrom-CIPolicy` và deploy vào `C:\Windows\System32\CodeIntegrity\CIPolicies\Active`, Windows tự động enforce rule allow-by-signer ở cấp kernel, không cần app tự viết code chặn process creation cho trường hợp này. Với phần "ứng dụng bên thứ 3" nằm ngoài rule allow tường minh, policy để ở chế độ audit trong giai đoạn phát triển, sau đó chuyển dần sang enforce theo rule tùy biến mà người dùng thiết lập qua giao diện được trình bày ở phần tiếp theo, không nên bật enforce cứng ngay từ đầu vì bất kỳ thiếu sót nào trong rule allow cũng có thể chặn nhầm phần mềm hợp lệ của chính người dùng.

## Giao diện tùy biến quyền cho ứng dụng bên thứ 3

Khi một tiến trình không đạt cả ba tiêu chí "trusted by default" ở phần 5, luồng UI hiển thị một hộp thoại chặn (modal, không cho phép người dùng thao tác gì khác trên máy trong lúc chờ) với tối thiểu bốn thông tin: tên file và đường dẫn đầy đủ, publisher (nếu có ký số, dù không phải Microsoft) hoặc "Không xác định" nếu unsigned, hash SHA-256 rút gọn để người dùng có thể tự tra cứu trên VirusTotal nếu nghi ngờ, và ba lựa chọn rõ ràng: Cho phép luôn (lưu rule vĩnh viễn), Chỉ lần này (không lưu rule, hỏi lại lần sau), Chặn.

Điểm dễ bị bỏ qua nhất khi thiết kế hộp thoại này: chính giao diện đó có thể trở thành vector tấn công nếu không được bảo vệ đúng cách, vì malware hoàn toàn có thể lợi dụng nếu hộp thoại dễ bị tự động hóa. Ba biện pháp cụ thể cần có:

- **Hộp thoại phải chạy trong một tiến trình UI riêng ở mức toàn vẹn cao (High Integrity Level) hoặc trong secure desktop**, tương tự cách UAC hoạt động, để một tiến trình malware ở mức toàn vẹn thấp hơn không thể gửi window message giả lập click "Cho phép" vào nút bấm.
- **Nút "Cho phép luôn" mặc định không được focus sẵn** và cần một khoảng trễ tối thiểu (ví dụ nửa giây) trước khi nhận input, để loại trừ trường hợp một script tự động gửi phím Enter ngay khi hộp thoại vừa xuất hiện.
- **Không hiển thị hộp thoại từ chính tiến trình đang bị đánh giá**, hộp thoại luôn do service nền (chạy quyền SYSTEM, tách biệt hoàn toàn với tiến trình đang xin quyền) khởi tạo, để tiến trình khả nghi không có cách nào can thiệp trực tiếp vào nội dung hoặc hành vi của hộp thoại đang hỏi về chính nó.

Rule được người dùng chọn ("Cho phép luôn" hoặc "Chặn") cần được lưu lại có cấu trúc để không phải hỏi lại mỗi lần, cách lưu trữ và tra cứu rule này được trình bày ở phần tiếp theo.

## Lưu trữ và quản lý rule phân quyền

Lưu rule trong một file SQLite cục bộ (đơn giản hơn triển khai một hệ quản trị CSDL riêng, và đủ nhanh cho khối lượng truy vấn của use case này) đặt trong thư mục dữ liệu được ACL bảo vệ chỉ cho SYSTEM và Administrator ghi được, nếu để một tiến trình thường có thể ghi trực tiếp vào file rule, toàn bộ cơ chế phân quyền sụp đổ vì malware chỉ cần tự thêm rule "Cho phép luôn" cho chính nó.

Schema tối thiểu cho bảng rule:

```sql
CREATE TABLE app_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256_hash TEXT NOT NULL,
    publisher_thumbprint TEXT,        -- NULL nếu file không ký số
    file_path TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
    scope TEXT NOT NULL CHECK(scope IN ('hash', 'publisher')),
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL          -- 'user' hoặc 'default_policy'
);
CREATE INDEX idx_rules_hash ON app_rules(sha256_hash);
CREATE INDEX idx_rules_publisher ON app_rules(publisher_thumbprint);
```

Cột `scope` phân biệt hai loại rule quan trọng: rule theo `hash` chỉ áp dụng cho đúng file có hash đó (an toàn tuyệt đối nhưng mất hiệu lực khi file được build lại), rule theo `publisher` áp dụng cho mọi file được ký bởi cùng certificate thumbprint (tiện cho phần mềm cập nhật thường xuyên nhưng rủi ro cao hơn nếu certificate đó từng bị lộ). Khi service nền tra cứu quyền cho một tiến trình mới, thứ tự ưu tiên là: tìm rule theo hash chính xác trước, không có mới tìm theo publisher thumbprint, không có nữa mới rơi về luồng hỏi người dùng ở phần trước.

Việc phân tách `scope` này còn được dùng lại nguyên vẹn ở phần xử lý false positive cho heuristic engine sau này, nên thiết kế đúng ngay từ bảng rule gốc giúp tránh phải viết thêm một bảng riêng cho whitelist detection sau này.

## Engine giám sát tiến trình theo thời gian thực

Có hai cách bắt sự kiện "một tiến trình mới vừa được tạo", khác nhau về vị trí chạy và độ tin cậy. Cách thứ nhất, đơn giản hơn để bắt đầu, là đăng ký ETW (Event Tracing for Windows) với provider `Microsoft-Windows-Kernel-Process`, lắng nghe event ID 1 (process start), chạy hoàn toàn ở user-mode, không cần viết driver, nhưng có độ trễ nhỏ giữa lúc tiến trình thực sự bắt đầu chạy và lúc event tới được listener, và về lý thuyết một tiến trình có đặc quyền cao có thể tắt hoặc can thiệp phiên ETW trước khi event kịp gửi đi.

Cách thứ hai, đáng tin cậy hơn vì chạy trong kernel, là driver đăng ký callback qua `PsSetCreateProcessNotifyRoutineEx`, callback này được kernel gọi đồng bộ ngay tại thời điểm tiến trình được tạo, trước khi tiến trình đó thực thi được dòng lệnh đầu tiên, cho phép service (thông qua driver) từ chối cho tiến trình chạy tiếp bằng cách set `CreationStatus = STATUS_ACCESS_DENIED` trong callback. Đây là cơ chế mà driver ELAM và nhiều thành phần của Windows Defender thực tế sử dụng cho việc chặn thực thi thời gian thực.

Thiết kế thực tế nên dùng cả hai, không chọn một: ETW cho mục đích logging/audit trail (không cần độ trễ bằng không, dữ liệu phong phú hơn để hiển thị cho người dùng) và `PsSetCreateProcessNotifyRoutineEx` trong driver cho mục đích chặn thật (cần đồng bộ, cần chạy trước khi tiến trình thực thi). Khi callback trong driver bắt được tiến trình mới, nó gửi thông tin (đường dẫn, PID, hash nếu đã tính sẵn) qua filter communication port xuống service nền để tra bảng rule đã lưu ở phần trước, rồi service trả quyết định allow/block ngược lại cho driver hoàn tất hoặc từ chối việc tạo tiến trình, luồng quyết định đầy đủ này được trình bày chi tiết ở phần tiếp theo.

## Luồng xử lý khi một ứng dụng thực thi

Khi callback `PsSetCreateProcessNotifyRoutineEx` trong driver bắt được một tiến trình mới, luồng xử lý đi qua bốn bước tuần tự trước khi tiến trình được phép chạy tiếp: (1) driver gửi đường dẫn file và PID xuống service qua filter communication port; (2) service tính SHA-256 của file (hoặc lấy từ cache nếu đã tính trước đó và file chưa đổi timestamp sửa đổi); (3) service tra bảng rule theo thứ tự hash rồi publisher như đã nêu ở phần lưu trữ rule; (4) nếu không tìm thấy rule nào và tiến trình không đạt tiêu chí "trusted by default", service kích hoạt hộp thoại hỏi người dùng và chờ phản hồi trước khi trả kết quả cuối cùng về driver.

Toàn bộ chuỗi bốn bước này phải hoàn tất trong một khoảng thời gian có giới hạn trên rõ ràng, vì driver đang giữ tiến trình ở trạng thái chờ trong lúc này, đặt timeout cứng (ví dụ 30 giây cho trường hợp cần hỏi người dùng, dưới 50 mili giây cho trường hợp chỉ tra rule có sẵn) và quyết định hành vi mặc định khi hết timeout: với rule tra cứu thông thường, mặc định deny-and-log nếu service không phản hồi kịp (an toàn hơn allow mù) trừ khi tiến trình đã đạt điều kiện trusted-by-default ở tầng driver mà không cần chờ service.

Việc tính hash ở bước (2) là điểm nghẽn hiệu năng dễ bị bỏ qua nhất: hash toàn bộ nội dung file mỗi lần tiến trình khởi động (kể cả những ứng dụng người dùng mở nhiều lần trong ngày) tạo overhead I/O không cần thiết. Cache kết quả hash theo cặp khóa (đường dẫn file, thời gian sửa đổi file, kích thước file) và chỉ tính lại khi một trong ba giá trị đổi, cùng cơ chế cache này được tái sử dụng ở phần giảm độ trễ real-time protection sau này, nên nên implement như một service cache dùng chung ngay từ đầu thay vì viết riêng cho từng luồng.

## Thiết kế tổng thể bộ máy quét (scan engine)

Scan engine nên được viết như một thư viện độc lập (DLL/static lib C++) nhận vào một file handle hoặc buffer và trả về kết quả phân loại, không biết và không cần biết ai đang gọi nó, full scan gọi nó theo vòng lặp trên hàng triệu file, real-time protection gọi nó đồng bộ trên một file duy nhất mỗi lần mở, cả hai dùng chung một pipeline xử lý bên trong thay vì hai bộ logic phát hiện tách biệt dễ lệch nhau theo thời gian.

Pipeline bên trong engine chạy theo thứ tự tăng dần chi phí tính toán, dừng lại ngay khi có kết luận đủ chắc chắn thay vì luôn chạy hết mọi bước: (1) tra hash SHA-256 trong CSDL signature cục bộ trước, nhanh nhất, nếu khớp mã độc đã biết thì kết luận ngay, không cần chạy các bước sau; (2) nếu không khớp CSDL hash, chạy tập rule YARA, chi phí trung bình, phát hiện được biến thể/họ mã độc chứ không chỉ bản sao chính xác; (3) nếu vẫn chưa kết luận, chạy heuristic (entropy, cấu trúc PE bất thường, API call đáng ngờ nếu có thể phân tích tĩnh), chi phí cao nhất, dành riêng cho trường hợp hai bước trước không đưa ra kết luận rõ ràng.

Kết quả trả về không nên chỉ là boolean sạch/độc hại, mà là một trong bốn trạng thái: `Clean` (đã quét, không phát hiện gì), `Malicious` (khớp signature/YARA rõ ràng), `Suspicious` (heuristic gắn cờ nhưng không chắc chắn, cần xử lý khác với `Malicious`, thường là cảnh báo thay vì tự động xóa), và `ScanError` (không đọc được file, ví dụ bị khóa hoặc hỏng, không được mặc định coi là `Clean` khi gặp lỗi này). Việc tách `Suspicious` khỏi `Malicious` ngay từ interface của engine, thay vì gộp chung rồi phân loại lại ở tầng gọi, là quyết định thiết kế quan trọng nhất của phần này, nó quyết định trực tiếp cách luồng quarantine và luồng xử lý false positive ở các phần sau vận hành mà không phải sửa lại interface engine.

## Xây dựng cơ sở dữ liệu signature dựa trên hash

CSDL signature ở dạng đơn giản nhất là tập hash SHA-256 của các mẫu mã độc đã biết, nhưng tra cứu trực tiếp trong một danh sách vài chục triệu hash bằng tìm kiếm tuần tự hoặc thậm chí B-tree thông thường sẽ chậm hơn mức chấp nhận được khi cần tra hàng nghìn lần mỗi phút lúc full scan. Giải pháp thực tế hai tầng: một Bloom filter nạp toàn bộ vào RAM để trả lời cực nhanh câu hỏi "hash này chắc chắn không có trong CSDL" (Bloom filter không có false negative, chỉ có false positive ở tỷ lệ rất thấp có thể cấu hình được, ví dụ 0.1%), và một file CSDL đầy đủ trên đĩa (dạng sorted array hoặc SQLite có index) chỉ được tra khi Bloom filter trả lời "có thể có", vì phần lớn file trên máy người dùng là sạch, Bloom filter lọc được tuyệt đại đa số truy vấn mà không cần chạm đĩa.

Cấu trúc file CSDL trên đĩa nên là mảng các bản ghi có độ dài cố định để hỗ trợ binary search trực tiếp mà không cần load toàn bộ vào bộ nhớ:

```
struct SignatureRecord {
    uint8_t  sha256[32];      // hash của mẫu mã độc
    uint32_t threat_id;       // ID tham chiếu tên/họ mã độc
    uint8_t  severity;        // 0-255, mức độ nguy hiểm
    uint32_t reserved;
};
```

Sắp xếp mảng này theo thứ tự tăng dần của `sha256` khi build CSDL cho phép binary search O(log n) trực tiếp trên file đã memory-map (`CreateFileMapping`/`MapViewOfFile`), không cần đọc toàn bộ file vào RAM cho một CSDL có thể lên tới vài trăm MB. Việc build Bloom filter và mảng sorted này là công việc của service cập nhật CSDL chạy định kỳ, được trình bày ở phần cập nhật CSDL virus tự động, engine lúc chạy chỉ đọc, không bao giờ tự ghi vào CSDL.

## Kỹ thuật heuristic phát hiện hành vi bất thường

Heuristic chạy sau cùng trong pipeline vì chi phí tính toán cao nhất và tỷ lệ false positive vốn có cao hơn signature/YARA, nó không tìm bản sao chính xác mà tìm đặc điểm thống kê bất thường, nên luôn có khả năng gắn cờ nhầm một file hợp lệ có đặc điểm giống mã độc một cách tình cờ.

Ba rule heuristic cụ thể, dễ implement và có giá trị thực tế cao:

- **Entropy Shannon của section code trong file PE cao bất thường** (thường trên ngưỡng khoảng 7.0-7.2 trên thang 0-8), dấu hiệu của packer hoặc mã hóa/nén nội dung thực thi để tránh signature-based detection. Tính bằng cách đọc từng section trong PE header, tính phân bố tần suất byte, áp công thức entropy Shannon chuẩn. Rule này một mình không đủ kết luận malicious vì nhiều phần mềm hợp lệ cũng dùng packer (UPX, Themida) để bảo vệ bản quyền, chỉ nên cộng điểm nghi ngờ, không tự động chặn.
- **Import Address Table chứa tổ hợp API nhạy cảm bất thường**, ví dụ một file cùng lúc import cả `VirtualAllocEx`, `WriteProcessMemory` và `CreateRemoteThread` (tổ hợp kinh điển của process injection) nhưng không import bất kỳ API UI/dialog thông thường nào, gợi ý một tiến trình không có giao diện đang có khả năng ghi code vào tiến trình khác.
- **File PE có Entry Point nằm ngoài mọi section được khai báo trong Section Table**, dấu hiệu rất mạnh của packer tự giải nén tại runtime (entry point thật bị ẩn), vì trình biên dịch hợp lệ luôn đặt entry point nằm trong section code đã khai báo.

Mỗi rule heuristic khớp cộng vào một điểm số tổng (weighted score), không tự động kết luận `Malicious` chỉ từ một rule đơn lẻ, vượt một ngưỡng điểm số tổng mới trả về trạng thái `Suspicious` (không phải `Malicious`, theo phân loại bốn trạng thái ở phần trước), để luồng xử lý phía sau đối xử khác với trường hợp khớp signature chắc chắn. Quy trình đưa rule mới vào chế độ log-only trước khi enforce, nhằm đo tỷ lệ false positive thực tế trên tập file sạch trước khi áp dụng, được trình bày chi tiết ở phần xử lý false positive.

## Tích hợp YARA rules vào scan engine

YARA lấp đúng khoảng trống giữa hash (chỉ khớp bản sao chính xác) và heuristic (chỉ xét đặc điểm thống kê chung chung): nó cho phép mô tả một họ mã độc bằng các đoạn byte/chuỗi đặc trưng cùng điều kiện logic kết hợp, khớp được các biến thể đã bị chỉnh sửa nhẹ mà vẫn giữ nguyên phần lõi hành vi. Thư viện `libyara` (chính thức, mã nguồn mở) cung cấp API C để nhúng trực tiếp vào scan engine mà không cần gọi công cụ dòng lệnh riêng.

Một rule YARA đơn giản khớp một họ mã độc giả định dựa trên chuỗi đặc trưng và điều kiện file PE:

```yara
rule Suspicious_Downloader_Pattern
{
    meta:
        description = "Phát hiện mẫu downloader dùng chuỗi C2 mã hóa đơn giản"
        severity = "medium"

    strings:
        $api1 = "URLDownloadToFileW" ascii
        $api2 = "WinExec" ascii
        $mz = { 4D 5A }                       // magic bytes đầu file PE

    condition:
        $mz at 0 and $api1 and $api2 and filesize < 500KB
}
```

Rule này khớp file PE (bắt đầu bằng `MZ`) nhỏ hơn 500KB có chứa cả hai chuỗi API `URLDownloadToFileW` và `WinExec`, tổ hợp thường gặp ở downloader tối giản (tải file thực thi khác về rồi chạy ngay). Trong scan engine, gọi `yr_rules_scan_file` (hoặc `yr_rules_scan_mem` nếu đang quét buffer trong bộ nhớ thay vì file trên đĩa, dùng cho trường hợp real-time cần tránh đọc lại file vừa mở) với con trỏ tới rule đã compile sẵn bằng `yr_compiler_add_string` lúc khởi động engine, không compile rule lại mỗi lần quét, vì compile là bước tốn CPU không cần lặp lại cho mỗi file.

Callback nhận kết quả match trả về danh sách rule đã khớp kèm `meta.severity`, được engine dùng để quyết định mức độ tin cậy của kết luận, một rule khớp với severity thấp chỉ cộng điểm vào tổng heuristic score, trong khi rule khớp với severity cao có thể tự đủ để trả về `Malicious` ngay mà không cần chờ heuristic score tổng, tùy vào cách cấu hình ngưỡng của từng rule.

## Xây dựng chức năng Full/Deep Scan toàn bộ ổ đĩa

Duyệt cây thư mục theo cách thông thường (`FindFirstFile`/`FindNextFile` đệ quy qua từng thư mục con) hoạt động đúng nhưng chậm trên volume có hàng triệu file, vì mỗi lần mở một thư mục là một round-trip I/O riêng và thứ tự duyệt theo cây không liên quan gì đến vị trí vật lý dữ liệu trên đĩa. Cách nhanh hơn đáng kể trên NTFS là đọc trực tiếp USN Journal của volume qua `DeviceIoControl` với mã điều khiển `FSCTL_ENUM_USN_DATA`, trả về danh sách toàn bộ file record trên volume theo thứ tự Master File Table (MFT), một lần gọi liệt kê được số lượng lớn file liên tiếp thay vì hàng nghìn lần gọi mở thư mục riêng lẻ.

```c
MFT_ENUM_DATA_V0 med = { 0 };
med.StartFileReferenceNumber = 0;
med.LowUsn = 0;
med.HighUsn = MAXLONGLONG;

BYTE buffer[65536];
DWORD bytesReturned;

while (DeviceIoControl(hVolume, FSCTL_ENUM_USN_DATA,
                        &med, sizeof(med),
                        buffer, sizeof(buffer),
                        &bytesReturned, NULL)) {
    PUSN_RECORD record = (PUSN_RECORD)((PUCHAR)buffer + sizeof(USN));
    while ((PUCHAR)record < buffer + bytesReturned) {
        // Xử lý record: lấy tên file, FileReferenceNumber, cờ thuộc tính
        EnqueueFileForScan(record);
        record = (PUSN_RECORD)((PUCHAR)record + record->RecordLength);
    }
    med.StartFileReferenceNumber = *(USN*)buffer;
}
```

Kết quả enumerate đưa vào một hàng đợi công việc (work queue) chia cho một thread pool có kích thước giới hạn (số core vật lý trừ 1, không tạo số luồng bằng đúng số core để chừa tài nguyên cho tiến trình khác của người dùng), mỗi thread gọi vào scan engine đã mô tả ở phần trước cho từng file. Mở `hVolume` cần quyền Administrator (`\\.\C:` với `GENERIC_READ` và cờ `FILE_SHARE_READ | FILE_SHARE_WRITE`), và cần fallback về duyệt cây thư mục thông thường cho các volume không phải NTFS (FAT32, exFAT không hỗ trợ USN Journal), kiểm tra file system type qua `GetVolumeInformation` trước khi chọn chiến lược enumerate.

## Tối ưu hiệu năng khi quét sâu

Ba kỹ thuật giảm cảm giác giật lag cho người dùng trong lúc full scan chạy nền, áp dụng đồng thời chứ không thay thế nhau. Thứ nhất, hạ mức ưu tiên I/O của tiến trình quét bằng `SetPriorityClass` với `PROCESS_MODE_BACKGROUND_BEGIN`, kết hợp gọi `NtSetInformationFile` với `FileIoPriorityHintInformation` đặt giá trị `IoPriorityLow` cho từng file handle đang đọc, hai lời gọi này báo cho I/O scheduler của Windows biết nhường băng thông đĩa cho các yêu cầu khác khi có tranh chấp, thay vì để scan engine cạnh tranh ngang hàng với thao tác của người dùng.

Thứ hai, theo dõi thời gian rảnh của người dùng qua `GetLastInputInfo` và giảm số luồng scan song song (thậm chí tạm dừng hoàn toàn) khi phát hiện người dùng vừa tương tác trong vài giây gần nhất, khôi phục tốc độ quét bình thường khi máy idle đủ lâu (ví dụ quá 60 giây không có input), cách này quan trọng hơn hạ I/O priority đơn thuần vì nó trực tiếp giải quyết đúng lúc người dùng cảm nhận được độ trễ nhất: trong lúc họ đang thao tác.

Thứ ba, và quan trọng riêng cho ổ HDD (không áp dụng cho SSD vì SSD không có chi phí seek cơ học): kiểm tra loại ổ đĩa bằng `DeviceIoControl` với `IOCTL_STORAGE_QUERY_PROPERTY` và `StorageDeviceSeekPenaltyProperty` trước khi bắt đầu quét. Nếu là HDD, sắp xếp lại thứ tự đọc file theo vị trí cluster vật lý (lấy qua `FSCTL_GET_RETRIEVAL_POINTERS` cho từng file, sort toàn bộ hàng đợi theo LBA tăng dần trước khi đọc) thay vì đọc theo thứ tự USN Journal trả về, để giảm số lần đầu đọc phải di chuyển qua lại giữa các vùng xa nhau trên đĩa; đồng thời giảm số luồng song song xuống 1 trên HDD, vì đọc đa luồng trên ổ cơ chỉ tạo thêm seek thrashing chứ không tăng throughput như trên SSD.

Trên cả hai loại ổ, việc quét nên hỗ trợ tạm dừng và tiếp tục giữa chừng (lưu vị trí `FileReferenceNumber` cuối cùng đã xử lý vào một file trạng thái nhỏ), để người dùng có thể chủ động dừng khi cần dùng máy cho việc nặng mà không mất tiến độ đã quét, thay vì phải quét lại từ đầu ở lần chạy tiếp theo.

## Quét trong file nén và chống zip bomb

Không giải nén toàn bộ một file zip/rar ra đĩa rồi mới quét, cách này vừa chậm (ghi đĩa thừa) vừa mở đúng lỗ hổng zip bomb: một file nén vài trăm KB có thể giải nén ra hàng chục GB nếu không giới hạn, làm đầy đĩa hoặc treo máy trước khi engine kịp phát hiện gì. Thay vào đó, dùng streaming decompression, đọc và quét từng khối buffer ngay khi giải nén ra, không bao giờ giữ toàn bộ nội dung đã giải nén trong bộ nhớ hay trên đĩa cùng lúc.

Ba giới hạn cứng áp dụng đồng thời trong lúc giải nén, không chỉ dựa vào con số ghi trong header của định dạng nén (giá trị uncompressed size trong local file header của ZIP có thể bị chỉnh sai cố ý để đánh lừa bộ ước tính, nên chỉ dùng để lọc nhanh trường hợp rõ ràng, không phải cơ chế bảo vệ chính):

- **Tỷ lệ nén tối đa**, nếu dung lượng đã giải nén thực tế (đo trong lúc giải nén, không phải đọc từ header) vượt quá một hệ số nhất định (ví dụ 100 lần) so với dung lượng file nén gốc, dừng ngay và gắn cờ `Suspicious` thay vì tiếp tục.
- **Độ sâu lồng nhau tối đa**, giới hạn số lớp file nén trong file nén (ví dụ tối đa 5 lớp); vượt quá, dừng và gắn cờ nghi ngờ thay vì đệ quy vô hạn.
- **Trần dung lượng giải nén tuyệt đối cho một file gốc**, dừng cứng khi tổng dung lượng đã giải nén từ một file nén duy nhất vượt một mốc cố định (ví dụ 1GB), bất kể tỷ lệ nén có vượt ngưỡng ở trên hay chưa, để chặn cả trường hợp file nén gốc đã lớn sẵn nên tỷ lệ nén không có vẻ bất thường.

```c
size_t total_decompressed = 0;
const size_t MAX_RATIO = 100;
const size_t MAX_ABSOLUTE = 1ULL * 1024 * 1024 * 1024; // 1GB
const int MAX_DEPTH = 5;

int ScanArchiveEntry(ArchiveEntry* entry, size_t compressedSize, int depth) {
    if (depth > MAX_DEPTH) return FLAG_SUSPICIOUS_TOO_DEEP;

    uint8_t buffer[65536];
    size_t bytesOut;
    while ((bytesOut = DecompressChunk(entry, buffer, sizeof(buffer))) > 0) {
        total_decompressed += bytesOut;
        if (total_decompressed > MAX_ABSOLUTE) return FLAG_SUSPICIOUS_ZIPBOMB;
        if (total_decompressed > compressedSize * MAX_RATIO) return FLAG_SUSPICIOUS_ZIPBOMB;
        ScanEngine_ScanBuffer(buffer, bytesOut); // gọi pipeline hash/YARA/heuristic
    }
    return FLAG_CLEAN;
}
```

Khi một trong ba giới hạn bị vượt, kết luận trả về là `Suspicious` chứ không tự động `Malicious`, file nén hợp lệ nhưng rất lớn (ví dụ ảnh disk image nén tốt) vẫn có thể vô tình chạm ngưỡng, nên hành vi mặc định là cảnh báo và cho người dùng quyết định, không tự động xóa.

## Kiến trúc Real-time Protection bằng minifilter driver

Minifilter driver là cơ chế chính thức của Windows để chặn thao tác filesystem trước khi chúng hoàn tất, đăng ký qua Filter Manager (`fltmgr.sys`) thay vì tự viết legacy file system filter driver (cách cũ, phức tạp và dễ xung đột hơn nhiều). Bước đầu tiên là xin một "altitude", một số định danh vị trí driver trong chuỗi filter, do Microsoft cấp phát để tránh xung đột giữa các sản phẩm bảo mật khác nhau cùng hook vào filesystem; dải altitude dành cho antivirus nằm trong khoảng 320000-329999, xin qua Microsoft (yêu cầu đăng ký, không tự chọn số tùy ý vì trùng altitude với driver khác gây driver không nạp được).

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    FLT_REGISTRATION filterRegistration = {
        sizeof(FLT_REGISTRATION),
        FLT_REGISTRATION_VERSION,
        0,
        NULL,                      // context registration
        Callbacks,                 // bảng callback, gồm PreCreate
        DriverUnload,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
    };

    PFLT_FILTER filterHandle;
    NTSTATUS status = FltRegisterFilter(DriverObject, &filterRegistration, &filterHandle);
    if (!NT_SUCCESS(status)) return status;

    return FltStartFiltering(filterHandle);
}

FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {

    // Lấy đường dẫn file từ Data->Iopb->TargetFileObject
    // Gửi thông tin xuống service qua FltSendMessage, chờ phản hồi (có timeout)
    // Nếu service trả BLOCK: Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    //                        return FLT_PREOP_COMPLETE;
    // Nếu ALLOW: return FLT_PREOP_SUCCESS_NO_CALLBACK;
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
```

Callback `PreCreateCallback` hook vào `IRP_MJ_CREATE`, mọi lần một file được mở (bởi Explorer, bởi trình duyệt, bởi tiến trình chạy .exe) đều đi qua đây trước khi Windows trả handle về cho bên yêu cầu. Việc gửi thông tin xuống service nền qua `FltSendMessage` là điểm nghẽn hiệu năng quan trọng nhất của toàn bộ real-time protection, vì driver phải giữ IRP chờ user-mode service trả lời trước khi tiếp tục, cách giảm độ trễ này ở mức chấp nhận được cho người dùng, bao gồm việc không gửi xuống service với mọi file, được trình bày ở phần tiếp theo.

## Giảm độ trễ khi quét theo thời gian thực

Điểm mấu chốt để real-time protection không gây cảm giác giật khi mở file: không phải mọi file đều cần round-trip xuống service ở mọi lần mở. Hai kỹ thuật giảm số lần round-trip thực sự cần thiết.

Thứ nhất, cache kết quả quét theo khóa tổng hợp gồm đường dẫn file, thời gian sửa đổi cuối, và kích thước file, nếu một file đã được quét sạch và ba giá trị này chưa đổi kể từ lần quét trước, driver có thể trả `FLT_PREOP_SUCCESS_NO_CALLBACK` ngay từ trong callback mà không cần gửi message xuống service, vì kết quả trước đó vẫn còn hợp lệ. Cache này nên nằm ngay trong driver (một bảng băm nhỏ trong kernel, giới hạn kích thước để không chiếm quá nhiều non-paged pool) để tránh cả chi phí chuyển ngữ cảnh xuống user-mode cho trường hợp phổ biến nhất: mở lại một file đã biết là sạch.

Thứ hai, phân loại file theo mức độ rủi ro ngay tại callback dựa trên phần mở rộng và magic bytes đầu file, chỉ chặn đồng bộ (giữ IRP chờ kết quả) với nhóm file có khả năng thực thi trực tiếp, `.exe`, `.dll`, `.ps1`, `.bat`, `.scr`, file bắt đầu bằng magic bytes `MZ`. Với file dữ liệu thông thường (ảnh, văn bản, video), driver cho phép mở ngay lập tức (`FLT_PREOP_SUCCESS_NO_CALLBACK`) và đưa file vào hàng đợi quét bất đồng bộ chạy sau, chấp nhận độ trễ giữa lúc file được mở và lúc kết quả quét sẵn sàng, đánh đổi này hợp lý vì rủi ro thực thi mã độc từ việc mở một file ảnh hay văn bản thấp hơn nhiều so với việc mở trực tiếp một file thực thi.

Đo độ trễ thực tế bằng cách chèn `QueryPerformanceCounter` ngay đầu và cuối `PreCreateCallback`, ghi lại delta theo microsecond vào một buffer log trong driver, xuất ra để phân tích định kỳ. Không có ngưỡng chuẩn chính thức bắt buộc của ngành cho con số này, mục tiêu kỹ thuật hợp lý cần tự đo trên phần cứng thật là giữ overhead dưới khoảng một chục mili giây cho file đã có trong cache, chấp nhận vài chục đến hơn trăm mili giây cho lần đầu quét một file thực thi mới và lớn, và luôn benchmark trước/sau khi bật driver để biết con số thực tế trên máy mục tiêu của mình thay vì tin vào một con số lý thuyết.

## Viết Early Launch Antimalware driver cơ bản

ELAM driver giải quyết một vấn đề khác hẳn với minifilter ở hai phần trước: nó không chặn file lúc người dùng dùng máy, mà quyết định driver boot-start nào khác được phép nạp trong giai đoạn boot sớm nhất, trước khi phần lớn hệ thống, kể cả chính minifilter của bạn, kịp khởi động. Đây là tuyến phòng thủ chống rootkit cố nạp driver độc hại trước cả antivirus.

Để driver được Windows công nhận là ELAM hợp lệ, ba điều kiện phải cùng đúng: driver được đăng ký với `Start = 0` (SERVICE_BOOT_START) trong service key registry, thuộc group `"Early-Launch"` trong `ServiceGroupOrder` (group này được Windows xếp trước mọi group boot-start khác), và quan trọng nhất, driver phải mang certificate có Enhanced Key Usage riêng cho Early Launch Antimalware, certificate này không tự tạo được như certificate ký driver thông thường mà phải xin qua chương trình đối tác của Microsoft dành riêng cho ELAM.

Về mặt logic, driver ELAM implement một boot-start driver classification callback được Boot Manager gọi cho từng driver boot-start khác trước khi driver đó được phép nạp tiếp, callback trả về một trong bốn phân loại: `Good` (driver đã biết là an toàn, cho nạp bình thường), `Bad` (driver đã biết độc hại, không cho nạp), `BadCritical` (driver độc hại nhưng việc chặn nó có thể khiến hệ thống không boot được, Windows sẽ hỏi người dùng qua Recovery Environment), và `Unknown` (không có thông tin, mặc định Windows vẫn cho nạp trừ khi chính sách cấu hình khác đi). Tên hàm callback cụ thể và chữ ký của nó thay đổi giữa các phiên bản WDK, nên đừng chép tay theo tài liệu cũ; cách an toàn để bắt đầu là mở trực tiếp project mẫu `elam` đi kèm trong WDK samples (tìm trong thư mục cài WDK, mục filesys/miniFilter hoặc elam tùy phiên bản) và đối chiếu đúng bản WDK đang cài trên máy, vì đây là điểm khởi đầu chính thức Microsoft cung cấp và luôn khớp với API hiện hành của phiên bản đó.

CSDL để ELAM callback tra cứu phân loại driver khác (tập hash hoặc chữ ký của driver độc hại đã biết) cần được đóng gói sẵn cùng driver ELAM dưới dạng resource nhúng, vì tại thời điểm ELAM chạy, service nền và CSDL signature chính chưa kịp khởi động, đây là lý do ELAM luôn có một CSDL riêng, nhỏ gọn hơn, tách biệt với CSDL đầy đủ dùng cho scan engine.

## Ký số driver với Microsoft

Có hai con đường ký driver khiến driver nạp được trên máy Secure Boot, khác nhau về độ nghiêm ngặt và mức độ tin cậy cần thiết cho từng loại driver. Attestation signing, nộp driver đã build và ký bằng EV Code Signing Certificate của công ty lên Microsoft Partner Center, Microsoft ký lại tự động mà không yêu cầu chạy bộ test Hardware Lab Kit (HLK) đầy đủ, phù hợp cho driver phổ thông, thời gian xử lý nhanh (thường vài giờ đến một ngày). WHQL signing yêu cầu driver phải pass bộ test HLK toàn diện trên nhiều cấu hình phần cứng trước khi được ký, quy trình chậm hơn nhiều nhưng chứng minh được driver đã qua kiểm định về tính ổn định, không chỉ về danh tính nhà phát triển.

Với driver cấp antivirus, đặc biệt là minifilter chặn I/O và ELAM driver mô tả ở các phần trước, nên đi thẳng tới WHQL/HLK ngay từ giai đoạn beta nội bộ thay vì dừng ở attestation signing, vì lý do cụ thể: một lỗi trong driver chặn filesystem hay driver nạp ở giai đoạn boot có thể gây blue screen ngay lập tức, ảnh hưởng trực tiếp đến việc máy người dùng có khởi động được hay không, rủi ro này nghiêm trọng hơn nhiều so với hầu hết loại driver khác (ví dụ driver máy in hay driver âm thanh), nơi lỗi thường chỉ làm mất một chức năng chứ không chặn cả máy boot.

Quy trình thực tế theo thứ tự: (1) hoàn tất xác minh danh tính công ty trên Partner Center (yêu cầu giấy tờ pháp lý công ty, không chấp nhận tài khoản cá nhân cho việc ký driver antivirus); (2) mua và cài EV Code Signing Certificate, lưu trên USB token phần cứng theo yêu cầu bắt buộc của chuẩn EV (không cho export ra file mềm); (3) build driver ở chế độ Release, ký bằng EV cert; (4) chạy bộ test HLK cục bộ trước khi nộp để tự phát hiện lỗi sớm, vì mỗi lần nộp lên Partner Center và bị từ chối đều tốn thời gian xử lý lại; (5) nộp qua Partner Center, chờ kết quả ký chính thức. Chỉ sau bước (5), driver mới có thể đóng gói vào installer phát hành cho người dùng thật, khác hẳn với driver ký bằng testsigning chỉ dùng được trên máy dev đã tự bật chế độ này.

## Giám sát riêng thư mục Downloads

Đăng ký `ReadDirectoryChangesW` trên thư mục Downloads của người dùng (`%USERPROFILE%\Downloads`, lấy đường dẫn thật qua `SHGetKnownFolderPath` với `FOLDERID_Downloads` thay vì hardcode, vì người dùng có thể đã đổi vị trí thư mục này) với cờ `FILE_NOTIFY_CHANGE_FILE_NAME`, chạy bất đồng bộ (overlapped I/O) trong service nền, cách này đơn giản hơn minifilter cho đúng use case này vì Downloads là một thư mục cụ thể, không cần chặn ở cấp toàn bộ filesystem.

Điểm quan trọng nhất cần xử lý đúng: các trình duyệt không ghi thẳng vào tên file cuối cùng. Chromium-based (Chrome, Edge) tạo file tạm với đuôi `.crdownload` trong lúc tải, Firefox dùng `.part`, khi tải xong, trình duyệt gọi rename bỏ đuôi tạm để ra tên file thật. Sự kiện cần bắt là `FILE_ACTION_RENAMED_NEW_NAME`, không phải `FILE_ACTION_ADDED`, quét ngay lúc thấy file tạm vừa xuất hiện sẽ hoặc quét một file rỗng/chưa đầy đủ (vô nghĩa), hoặc gặp lỗi vì file đang bị trình duyệt khóa độc quyền.

```c
FILE_NOTIFY_INFORMATION* info = (FILE_NOTIFY_INFORMATION*)buffer;
while (TRUE) {
    switch (info->Action) {
        case FILE_ACTION_RENAMED_NEW_NAME: {
            // Tên mới sau khi trình duyệt bỏ đuôi tạm .crdownload/.part
            EnqueueDownloadForScan(info->FileName, info->FileNameLength);
            break;
        }
        case FILE_ACTION_ADDED: {
            // File mới xuất hiện trực tiếp (vd: curl, wget, app khác không dùng đuôi tạm)
            // Không quét ngay, đưa vào hàng đợi chờ handle ghi đóng hoàn toàn
            QueueForDeferredScan(info->FileName, info->FileNameLength);
            break;
        }
    }
    if (info->NextEntryOffset == 0) break;
    info = (FILE_NOTIFY_INFORMATION*)((PUCHAR)info + info->NextEntryOffset);
}
```

Với trường hợp tải bằng công cụ dòng lệnh hoặc app không dùng đuôi tạm trung gian, sự kiện bắt được là `FILE_ACTION_ADDED` ngay với tên file cuối cùng, nhưng tại thời điểm đó file rất có thể vẫn đang được ghi dở dang. Cả hai nhánh vì vậy đều không quét ngay tại sự kiện mà đưa vào hàng đợi, chỉ thực sự quét khi xác nhận được không còn handle ghi nào giữ file, cách xác nhận này được trình bày ở phần tiếp theo.

## Luồng xử lý khi phát hiện file tải về đáng ngờ

Xác nhận file tải về đã ghi xong bằng cách polling `CreateFile` mở exclusive (không truyền `FILE_SHARE_WRITE`) trên file đó theo chu kỳ ngắn (ví dụ mỗi 200ms, timeout tổng sau 30 giây với file lớn), nếu mở thành công nghĩa là không còn tiến trình nào khác giữ handle ghi, file đã sẵn sàng để quét; nếu liên tục thất bại với `ERROR_SHARING_VIOLATION`, tiếp tục chờ. Nếu đã có sẵn minifilter cho real-time protection (phần 20-21), cách hiệu quả hơn polling là hook thêm `IRP_MJ_CLEANUP` trong cùng driver đó để nhận sự kiện handle cuối cùng vừa đóng, tái sử dụng hạ tầng đã có thay vì polling từ user-mode.

Khi file đã sẵn sàng, đưa qua đúng pipeline scan engine đã mô tả ở phần 13 (hash trước, YARA, rồi heuristic), với một khác biệt so với real-time protection thông thường: file trong Downloads luôn được quét đồng bộ và đầy đủ ngay khi sẵn sàng, không áp dụng việc bỏ qua theo phần mở rộng "ít rủi ro" như ở phần giảm độ trễ real-time, vì file tải về là điểm vào phổ biến nhất của mã độc, một ảnh hay tài liệu tưởng vô hại tải về vẫn có giá trị được quét đầy đủ do có thể chứa exploit nhắm vào phần mềm đọc file đó.

Ba kết quả từ engine dẫn tới ba hành động khác nhau: `Clean`, không làm gì thêm, để nguyên file cho người dùng dùng bình thường; `Malicious`, tự động chuyển file vào quarantine ngay lập tức (cơ chế ở phần tiếp theo) và hiển thị thông báo hệ thống (toast notification) nêu rõ tên file và lý do; `Suspicious`, không tự động di chuyển file, chỉ hiển thị cảnh báo kèm ba lựa chọn Xóa/Cách ly/Bỏ qua để người dùng tự quyết, vì mức độ chắc chắn của heuristic không đủ để tự động hành động trên file mà người dùng vừa chủ động tải về và có thể đang cần dùng ngay.

## Cơ chế Quarantine cách ly file nghi ngờ

Không xóa file bị coi là `Malicious` ngay lập tức, luôn di chuyển vào một khu vực cách ly trước, vì mọi engine phát hiện đều có tỷ lệ false positive khác không, và một khi file gốc bị xóa vĩnh viễn, không còn cách nào khôi phục nếu kết luận sau này hóa ra sai. Khu vực quarantine là một thư mục hệ thống được ACL bảo vệ (chỉ SYSTEM đọc/ghi được, người dùng thường không thể tự mở file bên trong bằng Explorer), và file khi chuyển vào đây cần qua hai bước biến đổi bắt buộc: đổi tên thành một định danh không mang phần mở rộng gốc (ví dụ dùng GUID) để Windows Explorer hay bất kỳ chương trình nào không vô tình thực thi nó nếu người dùng tò mò click vào, và mã hóa nội dung bằng một khóa đơn giản (ví dụ XOR với khóa cố định, không cần mã hóa mạnh vì mục đích chỉ là ngăn chính engine antivirus khác hoặc chương trình thực thi tình cờ đọc/chạy được file, không phải chống phân tích chuyên sâu).

```
QuarantineRecord {
    quarantine_id: GUID,
    original_path: string,       // đường dẫn gốc, cần cho việc khôi phục
    original_filename: string,
    sha256_hash: string,
    detection_reason: string,    // rule/signature nào đã gắn cờ
    quarantined_at: timestamp,
    file_size: uint64
}
```

Metadata này lưu song song trong bảng SQLite riêng (không chung bảng rule phân quyền), đủ để khôi phục chính xác file về đúng vị trí gốc nếu người dùng xác nhận đây là false positive, thao tác khôi phục chỉ nên khả dụng qua giao diện chính của app (yêu cầu xác nhận rõ ràng, không phải một nút bấm vô tình), không qua thao tác file thông thường trong Explorer.

Trường hợp đặc biệt cần xử lý riêng: nếu file bị gắn cờ nằm trong danh sách thư mục hệ thống được bảo vệ (trùng vị trí với các thư mục đã nêu ở phần "Nguyên tắc mặc định tin cậy ứng dụng gốc Windows"), không tự động quarantine ngay cả khi engine kết luận `Malicious`, chuyển sang chế độ cảnh báo yêu cầu xác nhận thủ công trước khi di chuyển, vì rủi ro gỡ nhầm một file hệ thống quan trọng gây mất ổn định hệ điều hành nghiêm trọng hơn nhiều so với việc chậm vài giây phản ứng với một phát hiện có thể đúng.

## Cập nhật cơ sở dữ liệu virus tự động

Chạy một update service riêng, tách khỏi service điều phối chính, kiểm tra phiên bản CSDL mới theo chu kỳ ngắn (ví dụ mỗi 1-4 giờ, không cần liên tục vì mối đe dọa mới không xuất hiện theo giây) qua một endpoint HTTPS trả về metadata dạng JSON gồm số phiên bản mới nhất và checksum, so sánh với phiên bản CSDL đang có cục bộ trước khi quyết định tải về.

Thay vì tải lại toàn bộ file CSDL mỗi lần có bản cập nhật (một CSDL vài trăm MB tải lại toàn bộ mỗi vài giờ vừa tốn băng thông người dùng vừa tốn tải server), thiết kế theo incremental update dạng delta: server lưu sẵn các gói diff giữa mỗi cặp phiên bản liên tiếp (`v100_to_v101.delta`, `v101_to_v102.delta`...), client tải các gói delta còn thiếu theo đúng thứ tự và áp dụng tuần tự lên CSDL cục bộ để lên phiên bản mới nhất, chỉ tải full CSDL khi client bị tụt quá xa (ví dụ hơn 30 phiên bản) để tránh phải tải và áp hàng chục gói delta liên tiếp.

Mỗi gói tải về, dù full hay delta, phải được xác minh chữ ký số trước khi áp dụng, ký bằng chính certificate của công ty, verify bằng `WinVerifyTrust` giống cách kiểm tra ở phần chữ ký số Authenticode, để một máy chủ CDN hoặc kênh phân phối bị xâm nhập không thể đẩy một CSDL giả xuống máy người dùng (kịch bản này từng thực sự xảy ra với vài sản phẩm bảo mật, khiến CSDL bị thao túng để tự nhận diện phần mềm hợp lệ là mã độc hoặc ngược lại). Sau khi verify, ghi CSDL mới vào một file tạm, đổi tên hoán đổi nguyên tử (`MoveFileEx` với `MOVEFILE_REPLACE_EXISTING`) thay thế file cũ, để không bao giờ có khoảng thời gian CSDL ở trạng thái ghi dở dang nếu update service bị crash hoặc mất điện giữa chừng.

## Kiểm thử với file EICAR và bộ mẫu an toàn

Chuỗi test EICAR là một tiêu chuẩn ngành có thật, được thiết kế để mọi engine antivirus nhận diện là "mã độc" mà không chứa bất kỳ đoạn code thực thi nguy hiểm nào, an toàn tuyệt đối để dùng trong test, kể cả trên máy sản xuất. Nội dung đầy đủ, tạo bằng cách ghi chính xác chuỗi ASCII sau vào một file `.com` hoặc `.txt`:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Vì đây là chuỗi công khai được mọi vendor antivirus công nhận, việc quan trọng khi test là kiểm tra pipeline phát hiện chạy đúng ở đúng tầng, không chỉ kiểm tra "có báo động hay không". Kịch bản test tối thiểu gồm ba lần thử tách biệt: (1) đặt file EICAR tĩnh vào một thư mục thường rồi chạy full scan, xác nhận engine trả về `Malicious` qua đúng nhánh CSDL hash (vì EICAR nằm sẵn trong hầu hết CSDL signature công khai) chứ không rơi vào nhánh heuristic; (2) copy file EICAR vào thư mục Downloads, xác nhận luồng giám sát Downloads bắt được sự kiện rename/added và tự động quét, đo thời gian từ lúc file xuất hiện tới lúc cảnh báo hiện ra; (3) cố mở trực tiếp file EICAR bằng một chương trình bất kỳ, xác nhận minifilter chặn thao tác mở trước khi chương trình đọc được nội dung, không phải chặn sau khi đã đọc.

Ngoài EICAR (chỉ test được nhánh phát hiện "có mã độc"), cần thêm một bộ mẫu file sạch đa dạng, toàn bộ file trong `Program Files` của một máy Windows cài mới, một vài phần mềm phổ biến hợp pháp có dùng packer (ví dụ bản cài của một ứng dụng dùng UPX), và các định dạng file nén hợp lệ với tỷ lệ nén cao (ví dụ file cài đặt game nén tốt), để đo tỷ lệ false positive của engine trên tập dữ liệu sạch trước khi coi bất kỳ rule heuristic hay YARA mới nào là sẵn sàng chuyển từ chế độ log-only sang enforce, quy trình được nêu chi tiết ở phần tiếp theo.

## Xử lý false positive với whitelist nhiều lớp

Mọi rule heuristic hoặc YARA mới trước khi được phép tự động chặn (enforce) phải trải qua một giai đoạn log-only: rule vẫn chạy trên mọi file được quét, kết quả khớp được ghi log kèm hash và đường dẫn nhưng không kích hoạt hành động chặn/quarantine nào, chạy tối thiểu vài ngày trên tập file sạch đã mô tả ở phần kiểm thử EICAR. Chỉ khi tỷ lệ match trên tập sạch này bằng không hoặc thấp tới mức chấp nhận được, rule mới được chuyển sang chế độ enforce thật cho người dùng.

Khi false positive vẫn xảy ra sau khi đã enforce (không thể loại trừ hoàn toàn), quy trình khôi phục cho người dùng gồm hai bước tách biệt: khôi phục file từ quarantine về đúng vị trí gốc bằng metadata đã lưu (phần cơ chế quarantine), và thêm ngoại lệ để không bị gắn cờ lại, đây là chỗ cần hai lớp whitelist khác nhau tùy tình huống, không chỉ một.

Với file tĩnh, ít khi thay đổi (ví dụ một tiện ích nội bộ công ty không cập nhật thường xuyên), whitelist theo đúng hash SHA-256 của file đó là đủ và an toàn tuyệt đối, không vô tình whitelist bất kỳ file nào khác kể cả khi trùng tên. Nhưng với phần mềm được build liên tục (ví dụ công cụ CI/CD nội bộ của chính người dùng, mỗi lần build ra hash khác nhau dù mã nguồn không đổi bản chất), whitelist theo hash sẽ vô tác dụng ngay từ lần build tiếp theo, lớp whitelist thứ hai cần bổ sung là theo publisher certificate thumbprint (nếu công cụ đó được ký, kể cả bằng self-signed certificate nội bộ của chính người dùng, không cần certificate thương mại) thay vì theo hash, dùng đúng cột `scope` đã thiết kế sẵn trong bảng rule ở phần lưu trữ rule phân quyền.

Mỗi lần người dùng thêm ngoại lệ thủ công, ghi lại cùng với rule/signature nào đã gây ra false positive đó vào một danh sách nội bộ để review định kỳ khi phát triển thêm rule mới, mục đích không phải xóa rule đó ngay, mà để nhận diện được rule nào có xu hướng gắn cờ nhầm lặp lại trên cùng một loại công cụ hợp lệ, từ đó tinh chỉnh điều kiện của rule thay vì chỉ vá từng trường hợp riêng lẻ.

## Đăng ký với Windows Security Center và tránh xung đột Defender

Đây là điểm dễ hiểu nhầm nhất trong toàn bộ quá trình xây dựng app: không tồn tại một API công khai đơn giản để bất kỳ ứng dụng nào tự "đăng ký" mình là AV provider và được Windows Security Center tin ngay lập tức. Con đường thực tế là tham gia chương trình **Microsoft Virus Initiative (MVI)**, yêu cầu công ty đạt chứng nhận từ một phòng test độc lập được Microsoft công nhận (như AV-Test, AV-Comparatives, hoặc ICSA Labs), chứng minh sản phẩm có bộ phát hiện thật đạt tiêu chuẩn tối thiểu, cùng tuân thủ các yêu cầu kỹ thuật khác của chương trình. Chỉ sau khi được chấp nhận vào MVI, sản phẩm mới được cấp quyền đăng ký hiển thị trong Windows Security Center qua interface dành riêng cho provider đã duyệt.

Nếu bỏ qua bước này và cố tự ý thao tác các registry key hoặc gọi API liên quan đến WSC provider mà không qua MVI, Windows sẽ không công nhận app là AV hợp lệ, hệ quả cụ thể là Windows Defender vẫn coi máy "không có bảo vệ của bên thứ 3" và tiếp tục tự bật real-time protection của chính nó chạy song song, dẫn tới hai minifilter driver cùng tranh chấp lock trên cùng file, gây lỗi khó chẩn đoán hoặc giảm hiệu năng đáng kể, đây chính là kịch bản xung đột hai AV cùng chạy mà bất kỳ ai từng cài hai phần mềm diệt virus cùng lúc đều gặp phải.

Trong giai đoạn phát triển và test, khi chưa qua MVI, giải pháp hợp lệ và thực tế để hai engine không tranh chấp là chủ động loại trừ thư mục cài đặt và tiến trình của app khỏi phạm vi quét của Windows Defender bằng PowerShell chạy quyền Administrator:

```powershell
Add-MpPreference -ExclusionPath "C:\Program Files\YourAntivirus"
Add-MpPreference -ExclusionProcess "YourAntivirusService.exe"
```

Đây chỉ là giải pháp tạm thời cho môi trường dev/test trên máy của chính nhóm phát triển, không phải cấu hình dành cho bản phát hành thật, không nên và không thể yêu cầu người dùng cuối tự chạy lệnh loại trừ Defender cho một app chưa được công nhận chính thức, vì làm vậy đồng nghĩa tắt một lớp bảo vệ thật của Windows mà không có gì thay thế đáng tin cậy tương đương cho tới khi app đã qua MVI.

## Chống tắt ứng dụng bằng Protected Process Light

Một app antivirus mà tiến trình service của nó có thể bị chính người dùng (hoặc malware chạy dưới quyền admin) tắt qua Task Manager thì toàn bộ các cơ chế bảo vệ đã xây ở những phần trước đều vô nghĩa trong tình huống thực sự cần đến chúng, mã độc chỉ cần kill service trước khi thực thi payload. Windows cung cấp cơ chế Protected Process Light (PPL) đúng cho tình huống này: một tiến trình chạy ở mức PPL với signer level phù hợp không thể bị mở handle với quyền `PROCESS_TERMINATE` từ một tiến trình thường, kể cả khi tiến trình đó chạy quyền Administrator, chỉ tiến trình khác cũng ở mức PPL ngang hoặc cao hơn mới thao tác được.

Để chạy ở mức PPL với signer level "Antimalware" (mức dành riêng cho phần mềm bảo mật, cao hơn PPL thông thường của các loại dịch vụ Windows khác), điều kiện bắt buộc là service phải được ký bằng certificate có Enhanced Key Usage cho Antimalware, cùng loại certificate liên quan tới ELAM đã nêu ở phần viết ELAM driver, không phải certificate ký code thông thường. Cấu hình tiến trình khởi động với protection level này thực hiện qua `UpdateProcThreadAttribute` với attribute `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` đặt giá trị `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` khi tạo tiến trình service.

```c
STARTUPINFOEX si = { sizeof(si) };
SIZE_T attrSize;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

DWORD protectionLevel = PROTECTION_LEVEL_ANTIMALWARE_LIGHT;
UpdateProcThreadAttribute(si.lpAttributeList, 0,
    PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
    &protectionLevel, sizeof(protectionLevel), NULL, NULL);

CreateProcess(NULL, serviceCommandLine, NULL, NULL, FALSE,
    EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
```

Cùng với việc bảo vệ tiến trình, các khóa registry và file cấu hình quan trọng của app (đường dẫn CSDL, bảng rule phân quyền) cũng cần ACL chặn ghi từ tiến trình không phải SYSTEM, để kẻ tấn công không đi vòng qua việc tắt service bằng cách sửa trực tiếp file cấu hình hoặc registry trong lúc service đang chạy, bảo vệ tiến trình mà không bảo vệ luôn dữ liệu nó đọc/ghi chỉ giải quyết được một nửa vấn đề.

## Logging và báo cáo cho người dùng

Ghi log ở hai tầng tách biệt phục vụ hai mục đích khác nhau, không gộp chung một luồng. Tầng thứ nhất là audit trail kỹ thuật đầy đủ, mọi quyết định allow/block, mọi kết quả scan (kể cả `Clean`), mọi thay đổi rule, ghi vào file log dạng structured (JSON lines) xoay vòng theo dung lượng, dùng cho việc debug và cho chính người phát triển đối chiếu khi có báo cáo lỗi hoặc false positive, không hiển thị trực tiếp cho người dùng vì quá chi tiết và dùng nhiều thuật ngữ kỹ thuật.

Tầng thứ hai là bản tóm tắt hiển thị trên UI, được lọc và diễn giải lại từ audit trail tầng một: số lượng file đã quét trong lần full scan gần nhất, danh sách các mối đe dọa đã phát hiện và xử lý (kèm tên và hành động đã thực hiện, quarantine hay đã khôi phục), và trạng thái bảo vệ hiện tại (real-time protection đang bật, lần cập nhật CSDL gần nhất). Bản tóm tắt này nên có bộ lọc theo thời gian (hôm nay, 7 ngày, 30 ngày) và cho phép người dùng click vào một sự kiện cụ thể để xem chi tiết hơn (đường dẫn file gốc, hash, rule nào đã gắn cờ) mà không cần mở file log kỹ thuật thô.

Cả hai tầng log cùng cần một nguyên tắc chung: không bao giờ ghi nội dung file (kể cả file bị nghi ngờ) vào log dưới dạng văn bản thuần, chỉ ghi hash và metadata, vừa tránh log phình to bất hợp lý, vừa tránh vô tình lưu trữ nội dung nhạy cảm (tài liệu cá nhân bị quét, ví dụ) ở một nơi có thể không được bảo vệ chặt bằng chính file gốc. File log kỹ thuật tầng một cũng cần nằm trong cùng phạm vi ACL bảo vệ như CSDL và bảng rule đã nêu ở các phần trước, vì log chi tiết về hành vi phát hiện của engine, nếu lộ ra ngoài, cũng là thông tin có giá trị cho việc né tránh chính engine đó.

## Đóng gói, ký số installer và checklist phát hành

Installer (dùng WiX Toolset hoặc Inno Setup, cả hai đều hỗ trợ tốt việc cài driver kernel-mode kèm ứng dụng) phải tự ký bằng cùng EV Code Signing Certificate dùng cho driver, không dùng certificate khác, SmartScreen của Windows đánh giá độ tin cậy của installer một phần dựa trên uy tín tích lũy của certificate đó qua thời gian, dùng nhiều certificate khác nhau cho các phần khác nhau của cùng sản phẩm làm loãng uy tín này và tăng khả năng bị SmartScreen cảnh báo ở những lần cài đặt đầu tiên.

Checklist tối thiểu trước khi đưa bản build đầu tiên cho người dùng thật ngoài nhóm phát triển, theo đúng thứ tự phụ thuộc giữa các bước đã trình bày xuyên suốt bài:

- Driver ELAM và minifilter đã qua attestation signing hoặc WHQL (phần ký số driver), không còn dùng testsigning.
- Toàn bộ rule heuristic/YARA đã qua giai đoạn log-only đủ lâu trên tập file sạch đa dạng (phần xử lý false positive), không còn rule nào mới chưa đo tỷ lệ false positive.
- Cơ chế quarantine đã test khôi phục thành công cả trên file thường và trên trường hợp giả lập gắn cờ nhầm file hệ thống.
- Update service đã test được luồng incremental delta lẫn fallback full download, và verify chữ ký số CSDL tải về hoạt động đúng.
- Tiến trình service đã chạy ở PPL Antimalware nếu đã có certificate phù hợp, hoặc ghi rõ trong tài liệu nội bộ đây là hạn chế đã biết nếu chưa có certificate này.
- Đã quyết định rõ trạng thái đăng ký MVI/Windows Security Center, nếu chưa qua MVI, tài liệu hướng dẫn cài đặt cho người dùng cần nêu rõ khả năng xung đột với Windows Defender và cách xử lý, thay vì im lặng để người dùng tự phát hiện.
- Bộ test EICAR đã chạy qua cả ba luồng (full scan, Downloads, real-time) và cho kết quả đúng ở mỗi luồng.

Bản phát hành đầu tiên không cần đã hoàn thiện mọi mục trên ở mức sản phẩm thương mại, nhưng mỗi mục còn thiếu cần được ghi nhận rõ ràng thành hạn chế đã biết thay vì bị bỏ sót âm thầm, một antivirus tự nhận có real-time protection nhưng chưa test độ trễ, hay tự nhận có deep scan nhưng chưa test trên ổ HDD, gây hiểu lầm nguy hiểm hơn nhiều so với việc công khai nói rõ tính năng nào còn ở giai đoạn thử nghiệm.

## Những lỗi thường gặp khi tự xây antivirus

**Tin vào tên file hoặc đường dẫn như một tiêu chí bảo mật.** Đây là lỗi nền tảng nhất và đã được nhấn mạnh xuyên suốt bài: bất kỳ chuỗi văn bản nào cũng copy được. Team mới bắt đầu thường viết whitelist kiểu `if (filename == "explorer.exe") trust = true`, lỗi này chỉ lộ ra khi có người thử đặt một file cùng tên vào vị trí khác, lúc đó whitelist đã chạy trong tay hàng nghìn người dùng.

**Quét đồng bộ mọi loại file trong real-time protection.** Chặn IRP_MJ_CREATE và gửi mọi file, kể cả ảnh và văn bản, xuống service chờ kết quả trước khi cho mở, tạo ra độ trễ cảm nhận được ngay từ ngày đầu người dùng thử app, đây là lý do phổ biến nhất khiến người dùng gỡ cài đặt một antivirus tự viết chỉ sau vài phút dùng thử, trước khi kịp đánh giá khả năng phát hiện thực sự.

**Bỏ qua việc đo hiệu năng trên phần cứng thật trước khi ship.** Code chạy mượt trên máy dev cấu hình cao với SSD NVMe không nói lên gì về trải nghiệm trên máy người dùng phổ thông với ổ HDD cũ, phần tối ưu hiệu năng khi quét sâu tồn tại chính vì sự khác biệt này, và bỏ qua nó là cách nhanh nhất để một tính năng "deep scan" đúng về mặt logic trở thành lý do máy người dùng bị treo trong thực tế.

**Coi driver signing và MVI là bước hành chính có thể làm sau cùng.** Cả hai đều có thời gian xử lý tính bằng tuần và là điều kiện tiên quyết để driver nạp được hoặc để tránh xung đột với Defender, để tới gần ngày phát hành mới bắt đầu nộp hồ sơ Partner Center hoặc tìm hiểu MVI là nguyên nhân phổ biến khiến lịch phát hành bị trễ hàng tháng dù phần code kỹ thuật đã xong từ lâu.

**Tự động xóa thay vì quarantine khi engine chỉ ở mức `Suspicious`.** Heuristic và YARA luôn có tỷ lệ false positive khác không; xử lý kết quả `Suspicious` giống hệt `Malicious` (xóa ngay, không cho khôi phục) là cách chắc chắn nhất để một ngày nào đó tự xóa nhầm một công cụ hợp lệ của chính người dùng mà không có đường lùi.

## Kết luận

Bạn giờ có kiến trúc và cơ chế cụ thể để bắt đầu triển khai một antivirus Windows thật, từ whitelist app gốc theo chữ ký số, kiểm soát quyền cho app bên thứ 3, quét sâu toàn ổ đĩa, real-time protection bằng minifilter, đến quarantine và cập nhật CSDL. Lưu ý quan trọng nhất nằm ngoài code: driver signing qua Microsoft và việc tham gia Microsoft Virus Initiative đều mất nhiều tuần xử lý, nên bắt đầu song song hai thủ tục này ngay từ đầu thay vì để tới lúc gần phát hành.
