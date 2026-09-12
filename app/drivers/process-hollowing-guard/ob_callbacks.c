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
    // [SUA LOI NGHIEM TRONG] Tham so DeviceCharacteristics (tham so thu 5)
    // TRUOC DAY la 0 — THIEU FILE_DEVICE_SECURE_OPEN. Khong co co nay, SDDL
    // o tren CHI duoc ap dung khi mo CHINH device, con moi lan mo mot
    // "duong dan phu" duoi device (vi du \.\SmePlanAvObGuardat_ky) deu BO QUA
    // security descriptor cua device — mot tien trinh quyen thuong chi can
    // them mot dau gach cheo la qua duoc toan bo kiem tra quyen va goi
    // duoc IOCTL. Comment ben tren tuyen bo lo hong nay da duoc va bang
    // IoCreateDeviceSecure + SDDL; tuyen bo do KHONG dung neu thieu co nay.
        status = IoCreateDeviceSecure(
            DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
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
    // Vong dem su kien truy cap dang ngo — xem SmePlanAvObLogSuspiciousAccess.
    KeInitializeSpinLock(&gObContext.EventLock);

    status = PsSetCreateProcessNotifyRoutineEx(SmePlanAvObProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLinkName);
        IoDeleteDevice(gObContext.DeviceObject);
        return status;
    }
    gObContext.ProcessNotifyRegistered = TRUE;

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
        // Duong nay chi chay khi notify routine DA dang ky thanh cong o tren,
        // nen go la dung; xoa co de DriverUnload khong go lan thu hai.
        PsSetCreateProcessNotifyRoutineEx(SmePlanAvObProcessNotify, TRUE);
        gObContext.ProcessNotifyRegistered = FALSE;
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
        gObContext.RegistrationHandle = NULL;
    }

    //
    // [SUA LOI NGHIEM TRONG] TRUOC DAY loi goi nay chay VO DIEU KIEN va gia
    // tri tra ve bi bo qua hoan toan. Hai van de doc lap:
    //
    // 1. Neu DriverEntry that bai TRUOC khi dang ky notify routine, day la
    //    mot lan GO cai chua bao gio duoc DANG KY.
    // 2. Neu loi go that bai (tra ve khac STATUS_SUCCESS — vi du
    //    STATUS_PROCEDURE_NOT_FOUND), driver van unload va anh cua no bi go
    //    khoi bo nho TRONG KHI entry cua no van con trong bang callback cua
    //    kernel. Tien trinh KE TIEP duoc tao tren may se goi vao vung nho da
    //    khong con — bugcheck, va nguyen nhan that su rat kho lan ra vi no
    //    xay ra sau khi driver da bien mat.
    //
    // Sua: chi go khi da thuc su dang ky, va neu go that bai thi TU CHOI
    // hoan tat unload (giu nguyen trang thai da dang ky) — mot driver khong
    // go duoc con tot hon mot he thong se bugcheck.
    //
    if (gObContext.ProcessNotifyRegistered) {
        NTSTATUS unregisterStatus =
            PsSetCreateProcessNotifyRoutineEx(SmePlanAvObProcessNotify, TRUE);
        if (!NT_SUCCESS(unregisterStatus)) {
            DbgPrint("SmePlanAvObGuard: KHONG go duoc process-notify routine (0x%08X) - "
                     "huy unload de tranh bugcheck o tien trinh ke tiep\n", unregisterStatus);
            return;
        }
        gObContext.ProcessNotifyRegistered = FALSE;
    }

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
    ULONG_PTR information = 0;

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
    case IOCTL_SMEPLANAV_OB_READ_SUSPICIOUS_ACCESS: {
        //
        // [SUA LOI CAO — LOI GIAO THUC IRP] TRUOC DAY nhanh nay dat
        // status = STATUS_PENDING roi roi thang xuong IoCompleteRequest o
        // cuoi ham VA return STATUS_PENDING. Do la vi pham giao thuc IRP
        // nghiem trong: STATUS_PENDING noi voi I/O Manager rang IRP CHUA
        // hoan tat va driver con giu no — trong khi driver vua hoan tat no
        // xong. I/O Manager se tiep tuc thao tac tren mot IRP da duoc giai
        // phong (use-after-free trong kernel). Ngoai ra IoMarkIrpPending
        // KHONG he duoc goi, dieu bat buoc truoc khi tra STATUS_PENDING.
        //
        // Sua: bo hoan toan mo hinh pending-IRP (von chua bao gio duoc
        // trien khai) va chuyen sang DRAIN dong bo tu vong dem su kien —
        // service poll dinh ky, moi lan lay het nhung gi dang co. Hoan tat
        // ngay lap tuc, dung giao thuc, va quan trong hon: canh bao THUC SU
        // den duoc user-mode (xem SmePlanAvObLogSuspiciousAccess).
        //
        ULONG capacity = stack->Parameters.DeviceIoControl.OutputBufferLength
                       / sizeof(SMEPLANAV_OB_SUSPICIOUS_ACCESS_EVENT);
        PSMEPLANAV_OB_SUSPICIOUS_ACCESS_EVENT out =
            (PSMEPLANAV_OB_SUSPICIOUS_ACCESS_EVENT)Irp->AssociatedIrp.SystemBuffer;
        KIRQL oldIrql;
        ULONG copied = 0;

        if (capacity == 0 || out == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KeAcquireSpinLock(&gObContext.EventLock, &oldIrql);
        while (copied < capacity && gObContext.EventCount > 0) {
            // Su kien cu nhat = EventHead lui lai EventCount vi tri.
            ULONG tail = (gObContext.EventHead + SMEPLANAV_OB_MAX_EVENTS - gObContext.EventCount)
                       % SMEPLANAV_OB_MAX_EVENTS;
            out[copied] = gObContext.Events[tail];
            gObContext.EventCount--;
            copied++;
        }
        KeReleaseSpinLock(&gObContext.EventLock, oldIrql);

        information = copied * sizeof(SMEPLANAV_OB_SUSPICIOUS_ACCESS_EVENT);
        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
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

// Khai bao truoc (dinh nghia phia duoi, ngay sau SmePlanAvObPreOperationCallback) —
// dung o hot path ben duoi truoc khi C compiler thay dinh nghia day du neu
// khong khai bao truoc o day.
static BOOLEAN SmePlanAvObIsUnrelatedAndNotWhitelisted(_In_ HANDLE RequesterPid, _In_ HANDLE TargetPid);

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

    // [SUA LOI HIEU NANG] Truoc day goi rieng SmePlanAvObIsUnrelatedProcess roi
    // SmePlanAvObIsWhitelisted — MOI ham tu KHOA spinlock TableLock (nang IRQL
    // len DISPATCH_LEVEL) va QUET TOAN BO bang SMEPLANAV_OB_MAX_TRACKED_PROCESSES
    // (8192) phan tu TUYEN TINH rieng biet, tren duong dan nong
    // (SmePlanAvObPreOperationCallback chay cho MOI OpenProcess/DuplicateHandle xin
    // PROCESS_VM_WRITE/PROCESS_VM_OPERATION — khong hiem, cac debugger/AV/EDR
    // khac cung hay xin quyen nay). Tuc la TOI DA 2 lan khoa + 2 lan quet
    // 8192 phan tu cho MOI lan goi. Sua: gop thanh MOT ham tinh CA HAI gia
    // tri (quan he cha-con cua target VA trang thai whitelist cua requester)
    // trong MOT lan khoa spinlock + MOT lan quet bang (thoat som ngay khi
    // ca hai da tim thay, khong can doi het 8192 phan tu) — giam mot nua so
    // lan khoa spinlock va thuong giam so buoc quet thuc te. SmePlanAvObIsUnrelatedProcess/
    // SmePlanAvObIsWhitelisted van giu nguyen (dung o noi khac neu can), chi
    // doi diem goi DUY NHAT nay — noi duy nhat ca hai gia tri can tinh CUNG
    // luc — sang ham gop SmePlanAvObIsUnrelatedAndNotWhitelisted ben duoi.
    if (SmePlanAvObIsUnrelatedAndNotWhitelisted(requesterPid, targetPid)) {
        // "Khong chan ngay tai day de tranh pha vo cong cu debug hop le,
        // chi ghi nhan va publish vao event bus de correlator danh gia" —
        // LUON tra OB_PREOP_SUCCESS, khong bao gio sua DesiredAccess de
        // tu choi handle.
        SmePlanAvObLogSuspiciousAccess(requesterPid, targetPid, (ULONG)desiredAccess);
    }

    return OB_PREOP_SUCCESS;
}

// [SUA LOI HIEU NANG] Gop logic cua SmePlanAvObIsUnrelatedProcess +
// SmePlanAvObIsWhitelisted vao MOT lan khoa TableLock + MOT lan quet bang —
// xem ghi chu chi tiet o diem goi DUY NHAT trong SmePlanAvObPreOperationCallback.
// Ket qua tra ve giu NGUYEN ngu nghia "requester KHONG lien quan toi target
// VA requester CHUA duoc whitelist" (dieu kien de ghi nhan truy cap dang
// ngo vuc) — chi khac cach hien thuc noi bo.
static BOOLEAN
SmePlanAvObIsUnrelatedAndNotWhitelisted(_In_ HANDLE RequesterPid, _In_ HANDLE TargetPid)
{
    KIRQL oldIrql;
    ULONG i;
    HANDLE targetParent = NULL;
    BOOLEAN foundTarget = FALSE;
    BOOLEAN whitelisted = FALSE;
    BOOLEAN foundRequester = FALSE;
    BOOLEAN isUnrelated;

    KeAcquireSpinLock(&gObContext.TableLock, &oldIrql);
    for (i = 0; i < SMEPLANAV_OB_MAX_TRACKED_PROCESSES && !(foundTarget && foundRequester); i++) {
        if (!foundTarget && gObContext.Table[i].InUse && gObContext.Table[i].ProcessId == TargetPid) {
            targetParent = gObContext.Table[i].ParentProcessId;
            foundTarget = TRUE;
        }
        if (!foundRequester && gObContext.Table[i].InUse && gObContext.Table[i].ProcessId == RequesterPid) {
            whitelisted = gObContext.Table[i].Whitelisted;
            foundRequester = TRUE;
        }
    }
    KeReleaseSpinLock(&gObContext.TableLock, oldIrql);

    // Giong het SmePlanAvObIsUnrelatedProcess: khong tim thay du lieu ve target ->
    // coi la "khong ro quan he", nghieng ve phia GHI NHAN (an toan hon bo sot).
    isUnrelated = !foundTarget || (targetParent != RequesterPid);

    // foundRequester == FALSE -> whitelisted van la FALSE (gia tri khoi tao),
    // giong het hanh vi mac dinh cua SmePlanAvObIsWhitelisted khi khong tim thay PID.
    return isUnrelated && !whitelisted;
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
    //
    // [SUA LOI CAO] TRUOC DAY toan bo than ham nay la ba dong
    // UNREFERENCED_PARAMETER — mot ham RONG. SmePlanAvObPreOperationCallback
    // van chay du, van ket luan dung "tien trinh khong lien quan dang xin
    // quyen ghi vao tien trinh khac", roi goi ham nay va KET QUA BIEN MAT.
    // Khong luu, khong day len user-mode, khong ghi log. Tang phat hien
    // process-hollowing vi vay khong bao gio tao ra duoc mot canh bao nao,
    // du no hoat dong dung ve mat logic.
    //
    // Sua: ghi su kien vao vong dem tinh trong context (xem ob_callbacks.h)
    // de service doc ra qua IOCTL_SMEPLANAV_OB_READ_SUSPICIOUS_ACCESS.
    // Ham nay co the duoc goi o IRQL cao (duong callback cua Object
    // Manager) nen: spinlock, bo nho tinh, KHONG cap phat, khong I/O.
    //
    KIRQL oldIrql;
    ULONG slot;

    KeAcquireSpinLock(&gObContext.EventLock, &oldIrql);

    slot = gObContext.EventHead;
    gObContext.Events[slot].RequesterProcessId = RequesterPid;
    gObContext.Events[slot].TargetProcessId = TargetPid;
    gObContext.Events[slot].DesiredAccessMask = DesiredAccess;
    KeQuerySystemTime(&gObContext.Events[slot].TargetCreateTime);

    gObContext.EventHead = (gObContext.EventHead + 1) % SMEPLANAV_OB_MAX_EVENTS;
    if (gObContext.EventCount < SMEPLANAV_OB_MAX_EVENTS) {
        gObContext.EventCount++;
    } else {
        // Vong dem day: su kien cu nhat vua bi ghi de. Dem lai de service
        // biet minh da BO LOT bao nhieu canh bao — im lang o day se lap lai
        // dung loi "phat hien roi lam mat" ma ban sua nay ton tai de va.
        gObContext.EventDropped++;
    }

    KeReleaseSpinLock(&gObContext.EventLock, oldIrql);
}
