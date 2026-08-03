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
