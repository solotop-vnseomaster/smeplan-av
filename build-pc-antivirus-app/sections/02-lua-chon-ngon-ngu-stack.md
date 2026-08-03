## Lựa chọn ngôn ngữ và stack kỹ thuật

Driver kernel-mode (ELAM và minifilter) chỉ có hai lựa chọn thực tế: C hoặc C++ giới hạn (không exception, không STL đầy đủ), viết trên Windows Driver Kit (WDK). Rust đang được Microsoft thử nghiệm cho driver qua dự án `windows-drivers-rs`, nhưng tính đến thời điểm viết bài, hệ sinh thái sample và tài liệu cho driver antivirus vẫn xoay quanh C/C++, chọn Rust ở tầng này nghĩa là tự vá phần lớn tooling, chỉ hợp lý nếu team đã có kinh nghiệm Rust kernel sâu.

Ở tầng scan engine (user-mode nhưng xử lý nặng: hash, YARA, heuristic), C++ vẫn là lựa chọn mặc định vì hai lý do cụ thể: engine này phải load được từ cả service .NET lẫn có thể tái sử dụng logic tương tự (hoặc gọi chung) từ context driver-adjacent, và hiệu năng xử lý hàng triệu file khi full scan nhạy với overhead runtime, GC pause của .NET hay Java giữa lúc quét hàng loạt file nhỏ tạo ra độ trễ không đoán trước được, điều tối kỵ với real-time protection.

Ở tầng UI và service điều phối, C#/.NET (WinUI 3 hoặc WPF cho UI, Windows Service viết bằng .NET cho service nền) hợp lý hơn C++ thuần vì tốc độ phát triển UI nhanh hơn, có sẵn binding tốt với Windows Security Center API và dễ maintain hơn về lâu dài, phần này không nằm trên đường găng về hiệu năng nên đánh đổi này chấp nhận được. Giao tiếp giữa service C# và scan engine C++ qua P/Invoke hoặc COM interop, giữa service và driver qua `DeviceIoControl`/filter port.

Kết hợp ba tầng ngôn ngữ này, không cố gò về một ngôn ngữ duy nhất, là cách các sản phẩm antivirus thương mại thực tế đang tổ chức code, và các phần code minh họa trong bài dùng đúng cách chia này: pseudo-code kernel/scan engine viết theo phong cách C/C++, phần UI/rule storage viết theo phong cách C#.
