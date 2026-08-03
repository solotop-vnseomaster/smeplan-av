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
