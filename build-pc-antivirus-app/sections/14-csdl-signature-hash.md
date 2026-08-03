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
