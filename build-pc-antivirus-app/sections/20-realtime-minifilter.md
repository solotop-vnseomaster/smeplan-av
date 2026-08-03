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
