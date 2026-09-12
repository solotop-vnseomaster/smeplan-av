# SMEPlan AV

Phần mềm chống mã độc cho Windows, xây dựng trọn vẹn từ engine quét C++ tới trình cài đặt MSI.
Không dùng framework antivirus có sẵn: engine quét, định dạng cơ sở dữ liệu chữ ký và định dạng
gói cập nhật đều tự thiết kế.

| | |
|---|---|
| Mã nguồn | 147 file, ~27.150 dòng — C#, C++, C, JavaScript, PowerShell |
| Kiểm thử | 336 ca (xUnit), 335 đạt |
| API nội bộ | 60 endpoint trên loopback `127.0.0.1:5270` |
| Dịch vụ nền | 15 dịch vụ chạy song song |
| Nền tảng | Windows 10 / 11, x64, .NET 9 |

## Kiến trúc

```
app/
├── service/Service/        Dịch vụ nền (.NET 9, LocalSystem) — điều phối mọi quyết định
├── service/Service.Tests/  Bộ kiểm thử xUnit
├── engine/                 Engine quét C++17, gọi qua P/Invoke
├── drivers/                Mã nguồn C: minifilter, ELAM, WFP callout
├── ui/Shell/               Vỏ WPF + WebView2
├── browser-extension/      Tiện ích Chrome + native messaging host
├── installer/              WiX v5 — MSI và bootstrapper Burn
└── ops/                    Script vận hành và tài liệu hạn chế đã biết
```

**Engine quét** chạy ba tầng nối tiếp: đối chiếu hash SHA-256, luật YARA, rồi chấm điểm heuristic
trên cấu trúc PE (entropy, bảng import, vị trí điểm vào). Cơ sở dữ liệu chữ ký là mảng đã sắp xếp
ánh xạ bộ nhớ, tra cứu bằng tìm kiếm nhị phân, có bloom filter chặn trước phần lớn truy vấn không khớp.

**Dịch vụ nền** giữ toàn bộ logic nghiệp vụ. Giao diện chỉ hiển thị và nhận thao tác.

## Chạy thử

```powershell
# Engine C++ (cần Visual Studio 2022 Build Tools)
powershell -File app/engine/build.ps1 -Config Debug

# Dịch vụ + giao diện web
dotnet run --project app/service/Service/Service.csproj --launch-profile Service

# Kiểm thử
dotnet test app/service/Service.Tests/Service.Tests.csproj
```

Mở `http://127.0.0.1:5270/?token=<token>`, token nằm ở
`%ProgramData%\AntivirusApp\data\api-token.txt`.

## Đóng gói

```powershell
powershell -File app/installer/build-installer.ps1
```

Sinh ra `SmePlanAvSetup.msi` và `SmePlanAvSetup.exe`. Trình cài đặt tự yêu cầu quyền quản trị,
cài dịch vụ chạy `LocalSystem` khởi động cùng Windows.

Script build có cổng đối chiếu: nếu output `dotnet publish` có file mà `Product.wxs` chưa khai báo,
build dừng ngay thay vì tạo ra bản cài hỏng lúc khởi động dịch vụ.

## Kênh cập nhật cơ sở dữ liệu

Gói cập nhật được ký RSA-SHA256 bằng chứng thư của tổ chức và xác minh trước khi áp dụng.
Nguồn gói là thư mục cục bộ `%ProgramData%\AntivirusApp\update-drop` — không cần máy chủ.

```powershell
# Tạo chứng thư ký (chạy quyền quản trị, một lần)
powershell -File app/ops/scripts/setup-update-signing.ps1

# Ký và phát hành một gói cơ sở dữ liệu
powershell -File app/ops/scripts/publish-signature-package.ps1 -CsvPath sigs.csv -VersionBump 51
```

## Hạn chế đã biết

Ghi rõ ở đây vì chính sản phẩm cũng báo cáo chúng trên bảng điều khiển.

- **Driver kernel-mode chưa triển khai.** Mã nguồn C hoàn chỉnh nhưng chưa biên dịch và ký được:
  cần bộ WDK và chứng thư EV có chữ ký attestation của Microsoft. Hệ quả là việc chặn tiến trình
  diễn ra *sau* khi tiến trình đã khởi tạo, không phải trước.
- **Tường lửa phát hiện nhưng chưa chặn.** Luật được lưu, đối chiếu và ghi nhật ký; kết nối khớp
  luật chặn vẫn chạy. Cần driver WFP callout.
- **Cơ sở dữ liệu chữ ký là bộ mẫu.** Hạ tầng cập nhật đã chạy thông đầu–cuối, nhưng dữ liệu hiện
  tại chỉ dùng để kiểm chứng đường ống.
- **Tầng đánh giá tin cậy tiến trình tốn tài nguyên.** Mỗi tiến trình mới bị băm và xác minh chữ ký;
  trên máy sinh nhiều tiến trình ngắn, chi phí này đáng kể. Cần thêm cache theo hash trước khi bật
  thường trực.

Chi tiết đầy đủ: `app/ops/docs/known-limitations.md`.

## Nguyên tắc kỹ thuật

- **Fail-closed.** Engine chưa sẵn sàng hoặc đang hoán đổi cơ sở dữ liệu thì kết quả là `ScanError`,
  không phải `Clean`. Một tệp chưa được kiểm tra không bao giờ được báo là sạch.
- **Trạng thái trung thực.** Một nguồn sự thật duy nhất (`ProtectionStatusService`) tính tình trạng
  từng tầng; giao diện đọc trực tiếp từ đó nên không thể hiển thị màu xanh khi hệ thống suy giảm.
- **Hành động không hoàn tác được cần kết luận dứt khoát.** Chỉ kết thúc tiến trình khi có luật chặn
  tường minh hoặc người dùng chọn chặn — hết thời gian chờ không phải là kết luận.
- **Kiểm thử phải chứng minh được điều nó tuyên bố.** Mỗi ca trong `ReviewFixRegressionTests` đều
  được kiểm chứng là đỏ khi hoàn tác bản vá tương ứng.

## Giấy phép và phụ thuộc

Engine liên kết động tới [libyara](https://github.com/VirusTotal/yara) (BSD-3-Clause, VirusTotal).
Cần bổ sung tệp NOTICE trước khi phân phối ra ngoài.
