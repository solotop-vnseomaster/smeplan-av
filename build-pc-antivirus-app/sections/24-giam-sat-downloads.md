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
