# SmePlanAv — Antivirus Windows (triển khai theo `spec-output/v1`)

Phần mềm được viết đầy đủ theo checklist tính năng trong
[`../features.md`](../features.md), trích xuất từ toàn bộ 11 tài liệu spec
trong `spec-output/v1/`. Đọc `../features.md` trước để biết mục nào có
bằng chứng ở đâu; đọc [`ops/docs/known-limitations.md`](ops/docs/known-limitations.md)
để biết rõ hạn chế môi trường (không có WDK/EV certificate/MVI — không thể
giả lập được, không phải lỗi kỹ thuật).

## Kiến trúc 6 khối (đúng theo `modules/02-kien-truc.md`)

| Khối trong spec | Thư mục | Ngôn ngữ | Trạng thái |
|---|---|---|---|
| UI | `ui/Shell` (WPF shell) + `service/Service/wwwroot` (nội dung HTML/CSS/JS) | C#/.NET + HTML/CSS/JS | ✅ Chạy được, đã test qua trình duyệt |
| Service nền (SYSTEM) | `service/Service` | C# (.NET 9, ASP.NET Core) | ✅ Chạy được, 21 automated test pass |
| Scan engine | `engine/` | C++ (biên dịch bằng MSVC) | ✅ Build được, P/Invoke từ service |
| Driver ELAM | `drivers/elam` | C (WDK) | ⚠️ Mã nguồn đầy đủ, chưa biên dịch (cần WDK) |
| Minifilter driver | `drivers/minifilter` | C (WDK) | ⚠️ Mã nguồn đầy đủ, chưa biên dịch (cần WDK) |
| CSDL signature + update | `engine` (định dạng CSDL) + `service/Service/Update` (client) | C++ / C# | ✅ Build + test được (delta/full/verify chữ ký) |

## Build & chạy thử

```powershell
# 1. Build scan engine (C++)
powershell -File app/engine/build.ps1 -Config Debug

# 2. Build + chạy service (ASP.NET Core, loopback 127.0.0.1:5270)
cd app/service/Service
dotnet run

# 3. (Tuỳ chọn) chạy shell WPF native — mở dashboard trong cửa sổ riêng
cd app/ui/Shell
dotnet run

# Hoặc chỉ mở trình duyệt tới http://127.0.0.1:5270 sau khi service đã chạy
```

```powershell
# Chạy toàn bộ automated test (engine + service, 21 test)
cd app/service/Service.Tests
dotnet test
```

## Thử phát hiện EICAR (test chuẩn ngành, không phải malware thật)

```powershell
# Seed một CSDL demo chỉ chứa hash EICAR
powershell -File app/ops/scripts/seed-demo-signatures.ps1

# Tạo file test
Set-Content -Path C:\eicar_test.com -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' -NoNewline

# Mở UI, vào "Quét nhanh một file", nhập C:\eicar_test.com -> phải trả về Malicious qua nhánh HashSignature
```

## Những gì KHÔNG chạy được trong môi trường này (và tại sao)

Xem đầy đủ trong [`ops/docs/known-limitations.md`](ops/docs/known-limitations.md).
Tóm tắt: driver kernel-mode thật (chặn file trước khi mở, ELAM sớm nhất
lúc boot), Protected Process Light Antimalware, đăng ký MVI/Windows
Security Center, và ký EV Code Signing — đều là các phụ thuộc bên ngoài
(WDK, certificate phần cứng, quy trình đối tác Microsoft) mà bản thân tài
liệu spec cũng liệt kê là bắt buộc và tốn "vài ngày đến vài tuần", không
phải thứ có thể mô phỏng bằng code.
