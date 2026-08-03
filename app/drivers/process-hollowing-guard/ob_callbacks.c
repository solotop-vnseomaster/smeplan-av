// ob_callbacks.c
// [HAN CHE MOI TRUONG] Xem ghi chu dau file ob_callbacks.h — day la MA
// NGUON THAM CHIEU, chua bien dich/ky trong phien nay (khong co WDK).
// Trien khai dung mo ta ky thuat trong "tai lieu moi.txt" muc "Bao ve
// tien trinh khoi process hollowing", bam sat vi du C trong tai lieu
// (PreOperationCallback kiem tra PROCESS_VM_WRITE/PROCESS_VM_OPERATION
// tren PsProcessType).
//
// [QUYET DINH TRIEN KHAI] Tai lieu de cap hai ham phu thuoc:
// IsUnrelatedProcess va IsWhitelistedDebuggerOrTool, khong dac ta chi
// tiet trien khai. O day:
//   - IsUnrelatedProcess: "khong lien quan" = KHONG PHAI chinh no
//     (self-write, vd runtime tu JIT code cua chinh minh) VA KHONG PHAI
//     quan he cha-con truc tiep (mot so cong cu hop le ghi vao tien trinh
//     con vua tao truoc khi resume — pattern nay pho bien o launcher/
//     installer hop phap). Quan he cha-con duoc dien tu chinh
//     PS_CREATE_NOTIFY_INFO->ParentProcessId ma driver nay tu dang ky
//     PsSetCreateProcessNotifyRoutineEx RIENG de theo doi (khong dung
//     chung bang voi minifilter.c vi day la driver .sys khac).
//   - IsWhitelistedDebuggerOrTool: khong the tra cuu whitelist chu ky so
//     (SQLite, WinVerifyTrust) TU KERNEL — cung kien truc "day tu
//     user-mode xuong cache kernel don gian" da dung cho wfp_callout.c,
//     service PUSH danh sach PID da qua whitelist (Process Explorer,
//     debugger... da duoc AuthenticodeVerifier xac nhan o tang service)
//     qua IOCTL_SMEPLANAV_OB_PUSH_WHITELIST moi khi ProcessTrustEngine
//     danh gia xong mot tien trinh moi.
#include "ob_callbacks.h"

SMEPLANAV_OB_CONTEXT gObContext = { 0 };

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;
    OB_OPERATION_REGISTRATION operationRegistration = { 0 };
    OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
    UNICODE_STRING altitude;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&gObContext.TableLock);
    KeInitializeSpinLock(&gObContext.PendingNotifyLock);
    InitializeListHead(&gObContext.PendingNotifyIrps);

    // [SUA LOI NGHIEM TRONG] TRUOC DAY dung IoCreateDevice thuong, KHONG gan
    // security descriptor nao ca — mac dinh Windows ap DACL rong (cho phep
    // MOI tien trinh local, ke ca khong dac quyen, mo handle toi
    // \Device\SmePlanAvObGuard). Vi IOCTL_SMEPLANAV_OB_PUSH_WHITELIST cho
    // phep tu whitelist BAT KY PID nao khoi kiem tra cua driver nay, mot
    // tien trinh khong dac quyen (vi du chinh malware dang thuc hien
    // process hollowing) co the tu goi IOCTL nay de vo hieu hoa toan bo
    // driver truoc khi hanh dong. Sua giong het cach wfp_callout.c da lam:
    // IoCreateDeviceSecure + SDDL chi cho SYSTEM (SY) va Administrators (BA).
    RtlInitUnicodeString(&deviceName, L"\\Device\\SmePlanAvObGuard");
    {
        UNICODE_STRING sddl;
        RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        status = IoCreateDeviceSecure(
            DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE,
            &sddl, NULL, &gObContext.DeviceObject);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlInitUnicodeString(&symLinkName, L"\\??\\SmePlanAvObGuard");
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gObContext.DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SmePlanAvObCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SmePlanAvObCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SmePlanAvObDeviceControl;
    DriverObject->DriverUnload = SmePlanAvObDriverUnload;

    // Theo doi quan he cha-con — dung de IsUnrelatedProcess phan biet
    // "launcher ghi vao chinh tien trinh con no vua tao" (thuong hop le)
    // voi "mot tien trinh bat ky ghi vao mot tien trinh khong lien quan"
    // (dau hieu process hollowing manh hon nhieu).
    status = PsSetCreateProcessNotifyRoutineEx(SmePlanAvObProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLinkName);
        IoDeleteDevice(gObContext.DeviceObject);
        return status;
    }

    // ObRegisterCallbacks tren PsProcessType, chan OB_OPERATION_HANDLE_CREATE
    // (va HANDLE_DUPLICATE — mot tien trinh co the lay handle qua
    // DuplicateHandle tu mot tien trinh khac da co san thay vi tu mo moi).
    operationRegistration.ObjectType = PsProcessType;
    operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration.PreOperation = SmePlanAvObPreOperationCallback;
    operationRegistration.PostOperation = NULL; // khong can hau kiem, chi ghi nhan luc xin quyen

    // Altitude cho ObRegisterCallbacks (khong gioi han cung dai voi
    // minifilter, nhung van can Microsoft cap cho ban phat hanh that —
    // gia tri placeholder minh hoa nhu cac driver khac trong repo nay).
    RtlInitUnicodeString(&altitude, L"329100");
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = NULL;
    callbackRegistration.OperationRegistration = &operationRegistration;

    status = ObRegisterCallbacks(&callbackRegistration, &gObContext.RegistrationHandle);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(SmePlanAvObProcessNotify, TRUE);
        IoDeleteSymbolicLink(&symLinkName);
        IoDeleteDevice(gObContext.DeviceObject);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
SmePlanAvObDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, L"\\??\\SmePlanAvObGuard");

    UNREFERENCED_PARAMETER(DriverObject);

    if (gObContext.RegistrationHandle) {
        ObUnRegisterCallbacks(gObContext.RegistrationHandle);
    }
    PsSetCreateProcessNotifyRoutineEx(SmePlanAvObProcessNotify, TRUE);
    IoDeleteSymbolicLink(&symLinkName);
    if (gObContext.DeviceObject) {
        IoDeleteDevice(gObContext.DeviceObject);
    }
}

NTSTATUS
SmePlanAvObCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
SmePlanAvObDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_SMEPLANAV_OB_PUSH_WHITELIST: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(SMEPLANAV_OB_PUSH_WHITELIST_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PSMEPLANAV_OB_PUSH_WHITELIST_REQUEST req =
            (PSMEPLANAV_OB_PUSH_WHITELIST_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        KIRQL oldIrql;
        KeAcquireSpinLock(&gObContext.TableLock, &oldIrql);
        for (ULONG i = 0; i < SMEPLANAV_OB_MAX_TRACKED_PROCESSES; i++) {
            if (gObContext.Table[i].InUse && gObContext.Table[i].ProcessId == req->ProcessId) {
                gObContext.Table[i].Whitelisted = req->Whitelisted;
                break;
            }
        }
        KeReleaseSpinLock(&gObContext.TableLock, oldIrql);
        break;
    }
    case IOCTL_SMEPLANAV_OB_READ_SUSPICIOUS_ACCESS:
        // [HAN CHE MOI TRUONG] Xem ghi chu tuong duong trong
        // wfp_callout.c SmePlanAvFwDeviceControl — quan ly pending-IRP
        // day du (mark pending + cancel routine) bi luoc bot trong ban
        // tham chieu nay.
        status = STATUS_PENDING;
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID
SmePlanAvObProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    KIRQL oldIrql;
    ULONG i;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        // Tien trinh thoat — xoa khoi bang de tranh PID bi tai su dung
        // sau nay bi nham voi ban ghi cu (dung nguyen tac "PID co the bi
        // tai su dung" ma tai lieu da nhan manh).
        KeAcquireSpinLock(&gObContext.TableLock, &oldIrql);
        for (i = 0; i < SMEPLANAV_OB_MAX_TRACKED_PROCESSES; i++) {
            if (gObContext.Table[i].InUse && gObContext.Table[i].ProcessId == ProcessId) {
                gObContext.Table[i].InUse = FALSE;
                break;
            }
        }
        KeReleaseSpinLock(&gObContext.TableLock, oldIrql);
        return;
    }

    KeAcquireSpinLock(&gObContext.TableLock, &oldIrql);
    for (i = 0; i < SMEPLANAV_OB_MAX_TRACKED_PROCESSES; i++) {
        if (!gObContext.Table[i].InUse) {
            gObContext.Table[i].InUse = TRUE;
            gObContext.Table[i].ProcessId = ProcessId;
            gObContext.Table[i].ParentProcessId = CreateInfo->ParentProcessId;
            gObContext.Table[i].Whitelisted = FALSE;
            break;
        }
    }
    // [HAN CHE MOI TRUONG] Bang day (khong tim duoc slot trong):
    // IsUnrelatedProcess se coi tien trinh nay la "khong ro quan he" (an
    // toan hon, fail-closed ve phia GHI NHAN nhieu hon thay vi bo sot).
    KeReleaseSpinLock(&gObContext.TableLock, oldIrql);
}

OB_PREOP_CALLBACK_STATUS
SmePlanAvObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    ACCESS_MASK desiredAccess;
    HANDLE requesterPid;
    HANDLE targetPid;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    desiredAccess = (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        ? Info->Parameters->CreateHandleInformation.DesiredAccess
        : Info->Parameters->DuplicateHandleInformation.DesiredAccess;

    if (!(desiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION))) {
        return OB_PREOP_SUCCESS;
    }

    requesterPid = PsGetCurrentProcessId();
    targetPid = PsGetProcessId((PEPROCESS)Info->Object);

    if (requesterPid == targetPid) {
        // Tien trinh tu ghi vao chinh no (vi du JIT compiler cap phat
        // trang RWX cho chinh minh) — khong phai pattern process hollowing
        // (pattern do LUON la MOT tien trinh khac nham vao tien trinh vua
        // tao con suspended).
        return OB_PREOP_SUCCESS;
    }

    if (SmePlanAvObIsUnrelatedProcess(requesterPid, targetPid) &&
        !SmePlanAvObIsWhitelisted(requesterPid)) {
        // "Khong chan ngay tai day de tranh pha vo cong cu debug hop le,
        // chi ghi nhan va publish vao event bus de correlator danh gia" —
        // LUON tra OB_PREOP_SUCCESS, khong bao gio sua DesiredAccess de
        // tu choi handle.
        SmePlanAvObLogSuspiciousAccess(requesterPid, targetPid, (ULONG)desiredAccess);
    }

    return OB_PREOP_SUCCESS;
}

BOOLEAN
SmePlanAvObIsUnrelatedProcess(_In_ HANDLE RequesterPid, _In_ HANDLE TargetPid)
{
    KIRQL oldIrql;
    ULONG i;
    HANDLE targetParent = NULL;
    BOOLEAN foundTarget = FALSE;

    KeAcquireSpinLock(&gObContext.TableLock, &oldIrql);
    for (i = 0; i < SMEPLANAV_OB_MAX_TRACKED_PROCESSES; i++) {
        if (gObContext.Table[i].InUse && gObContext.Table[i].ProcessId == TargetPid) {
            targetParent = gObContext.Table[i].ParentProcessId;
            foundTarget = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gObContext.TableLock, oldIrql);

    if (!foundTarget) {
        // Khong co du lieu ve tien trinh dich (vi du driver vua nap sau
        // khi tien trinh do da ton tai) — coi la "khong ro quan he",
        // nghieng ve phia GHI NHAN (an toan hon bo sot that su).
        return TRUE;
    }

    // "Lien quan" = requester CHINH LA cha truc tiep cua target — pattern
    // launcher/installer hop le ghi vao tien trinh con vua tao truoc khi
    // resume no.
    return targetParent != RequesterPid;
}

BOOLEAN
SmePlanAvObIsWhitelisted(_In_ HANDLE Pid)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN whitelisted = FALSE;

    KeAcquireSpinLock(&gObContext.TableLock, &oldIrql);
    for (i = 0; i < SMEPLANAV_OB_MAX_TRACKED_PROCESSES; i++) {
        if (gObContext.Table[i].InUse && gObContext.Table[i].ProcessId == Pid) {
            whitelisted = gObContext.Table[i].Whitelisted;
            break;
        }
    }
    KeReleaseSpinLock(&gObContext.TableLock, oldIrql);
    return whitelisted;
}

VOID
SmePlanAvObLogSuspiciousAccess(_In_ HANDLE RequesterPid, _In_ HANDLE TargetPid, _In_ ULONG DesiredAccess)
{
    // [HAN CHE MOI TRUONG] Ban day du: tao SMEPLANAV_OB_SUSPICIOUS_ACCESS_EVENT,
    // hoan tat mot IRP dang cho trong PendingNotifyIrps (neu co) de service
    // nhan duoc gan nhu ngay lap tuc qua IOCTL_SMEPLANAV_OB_READ_SUSPICIOUS_ACCESS
    // dang pending — bo qua chi tiet quan ly hang doi IRP trong ban tham
    // chieu nay (xem ghi chu tai SmePlanAvObDeviceControl).
    UNREFERENCED_PARAMETER(RequesterPid);
    UNREFERENCED_PARAMETER(TargetPid);
    UNREFERENCED_PARAMETER(DesiredAccess);
}
