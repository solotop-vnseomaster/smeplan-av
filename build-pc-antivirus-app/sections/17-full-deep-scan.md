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
