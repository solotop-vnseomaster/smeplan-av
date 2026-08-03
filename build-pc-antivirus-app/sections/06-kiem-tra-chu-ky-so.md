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
