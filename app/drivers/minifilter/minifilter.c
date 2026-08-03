// minifilter.c
// [HAN CHE MOI TRUONG] Xem ghi chu dau file minifilter.h — day la ma nguon
// THAM CHIEU, chua bien dich/ky trong phien nay (khong co WDK). Trien khai
// dung mo ta ky thuat trong modules/02-kien-truc.md, business-rules/05 va
// flows/11-luong-xu-ly.md.
//
// Nguyen tac cot loi (modules/02-kien-truc.md muc 4): kernel-mode duoc giu
// CANG MONG CANG TOT — chi chan va hoi, KHONG tu quyet dinh logic phuc tap
// (heuristic/YARA/tra CSDL hash nam o user-mode, trong scan engine).
#include "minifilter.h"

// [CANH BAO DONG BO THU CONG] Danh sach nay la BAN SAO DOC LAP cua cung
// danh sach duoi "co kha nang thuc thi" trong app/engine/src/pipeline.cpp
// (kExts, dung boi IsExecutableCandidateInternal cho real-time watcher
// user-mode). Kernel driver nay VE MAT KY THUAT KHONG THE goi vao ham C++
// user-mode do (khac dia chi/che do thuc thi), nen KHONG co co che "dung
// chung logic" thuc su nao ca — day la hai tang bao ve DOC LAP tinh cho
// cung mot khai niem. Sua danh sach duoi o MOT trong hai noi ma quen noi
// con lai se khien hai tang bao ve LECH NHAU ma khong co canh bao bien
// dich nao — PHAI sua CA HAI noi khi thay doi danh sach nay.
const PCWSTR gExecutableExtensions[] = {
    L".exe", L".dll", L".ps1", L".bat", L".scr", L".cmd", L".vbs", L".js"
};
const ULONG gExecutableExtensionsCount = ARRAYSIZE(gExecutableExtensions);

MINIFILTER_CONTEXT gContext = { 0 };

// FLT_OPERATION_REGISTRATION: IRP_MJ_CREATE la diem chan "mo file" truoc
// khi Windows cho phep thao tac hoan tat (modules/02-kien-truc.md muc 1).
// IRP_MJ_WRITE + IRP_MJ_SET_INFORMATION them cho EXT-RW-01 ("tai lieu
// moi.txt" muc "Phat hien hanh vi ransomware..."): chan GHI/DOI TEN file
// trong thu muc bao ve truoc khi no xay ra that su — xem SmePlanAvMfPreWriteCallback/
// SmePlanAvMfPreSetInformationCallback.
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, SmePlanAvMfPreCreateCallback, SmePlanAvMfPostCreateCallback },
    { IRP_MJ_WRITE, 0, SmePlanAvMfPreWriteCallback, NULL },
    { IRP_MJ_SET_INFORMATION, 0, SmePlanAvMfPreSetInformationCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

// [SUA LOI HIEU NANG] Dang ky FLT_STREAM_CONTEXT de cache ket qua
// SmePlanAvMfIsUnderProtectedFolder MOT LAN duy nhat luc mo file (SmePlanAvMfPostCreateCallback)
// thay vi tinh lai cho MOI IRP_MJ_WRITE — xem MINIFILTER_STREAM_CONTEXT
// trong minifilter.h.
CONST FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_STREAM_CONTEXT, 0, NULL, sizeof(MINIFILTER_STREAM_CONTEXT), MINIFILTER_STREAM_CONTEXT_TAG },
    { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                          // FilterFlags
    ContextRegistration,        // FLT_STREAM_CONTEXT cache SmePlanAvMfIsUnderProtectedFolder (toi uu hieu nang)
    Callbacks,
    SmePlanAvMfUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objAttrs;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Tao communication port de service nen (user-mode, SYSTEM) ket noi vao
    // (FltCreateCommunicationPort) — modules/02-kien-truc.md muc 4: "khong
    // the va khong nen chay logic phuc tap trong kernel".
    RtlInitUnicodeString(&portName, L"\\SmePlanAvMiniFilterPort");

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gContext.FilterHandle);
        return status;
    }

    InitializeObjectAttributes(
        &objAttrs, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, securityDescriptor);

    KeInitializeSpinLock(&gContext.ProtectedFoldersLock);

    // SmePlanAvMfMessageNotifyCallback (tham so thu 7, truoc day NULL) — nhan thong
    // diep PUSH tu service (khong phai reply cho FltSendMessage cua chinh
    // driver, ma la kenh nguoc: service chu dong gui xuong qua
    // FilterSendMessage o user-mode) — dung de nhan danh sach thu muc bao
    // ve ransomware, xem SmePlanAvMfMessageNotifyCallback.
    status = FltCreateCommunicationPort(
        gContext.FilterHandle, &gContext.ServerPort, &objAttrs,
        NULL, SmePlanAvMfPortConnectNotify, SmePlanAvMfPortDisconnectNotify, SmePlanAvMfMessageNotifyCallback, 1);

    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gContext.FilterHandle);
        return status;
    }

    // PsSetCreateProcessNotifyRoutineEx: chan tien trinh moi DONG BO ngay
    // tai thoi diem tao, TRUOC khi tien trinh thuc thi dong lenh dau tien
    // (modules/02-kien-truc.md muc 1; flows/11 "Luong thuc thi ung dung moi").
    status = PsSetCreateProcessNotifyRoutineEx(SmePlanAvMfProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gContext.ServerPort);
        FltUnregisterFilter(gContext.FilterHandle);
        return status;
    }

    status = FltStartFiltering(gContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(SmePlanAvMfProcessNotifyCallbackEx, TRUE);
        FltCloseCommunicationPort(gContext.ServerPort);
        FltUnregisterFilter(gContext.FilterHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SmePlanAvMfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    PsSetCreateProcessNotifyRoutineEx(SmePlanAvMfProcessNotifyCallbackEx, TRUE);

    if (gContext.ServerPort) {
        FltCloseCommunicationPort(gContext.ServerPort);
    }
    FltUnregisterFilter(gContext.FilterHandle);
    return STATUS_SUCCESS;
}

NTSTATUS
SmePlanAvMfPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    // Chi chap nhan MOT client duy nhat (service nen chay quyen SYSTEM) —
    // tu choi ket noi thu hai de tranh tien trinh gia mao gia lam service.
    if (gContext.ClientPort != NULL) {
        return STATUS_CONNECTION_REFUSED;
    }
    gContext.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID
SmePlanAvMfPortDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gContext.FilterHandle, &gContext.ClientPort);
    gContext.ClientPort = NULL;
}

BOOLEAN
SmePlanAvMfIsExecutableCandidate(_In_ PCUNICODE_STRING FileName)
{
    // errors/10-so-tay-loi.md ERR-RT-01: "chi chan dong bo nhom file co
    // kha nang thuc thi truc tiep (.exe/.dll/.ps1/.bat/.scr, magic bytes
    // MZ); file du lieu thong thuong cho mo ngay va quet bat dong bo" —
    // kiem tra phan mo rong o day (kiem tra magic bytes MZ can doc byte
    // dau file, thuc hien o buoc doc them trong ban day du).
    ULONG i;
    for (i = 0; i < gExecutableExtensionsCount; i++) {
        UNICODE_STRING ext;
        RtlInitUnicodeString(&ext, gExecutableExtensions[i]);
        if (FileName->Length >= ext.Length) {
            UNICODE_STRING tail;
            tail.Buffer = (PWCH)((PUCHAR)FileName->Buffer + FileName->Length - ext.Length);
            tail.Length = ext.Length;
            tail.MaximumLength = ext.Length;
            if (RtlEqualUnicodeString(&tail, &ext, TRUE)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

FLT_PREOP_CALLBACK_STATUS
SmePlanAvMfPreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    LARGE_INTEGER perfStart, perfEnd, perfFreq;
    DRIVER_TO_SERVICE_MSG query;
    SERVICE_TO_DRIVER_REPLY reply;

    UNREFERENCED_PARAMETER(CompletionContext);

    // NFR-OBS-01: do do tre bang QueryPerformanceCounter (kernel: KeQueryPerformanceCounter)
    // o dau va cuoi callback, don vi microsecond.
    perfStart = KeQueryPerformanceCounter(&perfFreq);

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    // ERR-RT-01: chi chan DONG BO nhom file thuc thi; file khac cho mo ngay.
    //
    // [SUA LOI HIEU NANG] Tra ve FLT_PREOP_SUCCESS_WITH_CALLBACK (thay vi
    // NO_CALLBACK nhu truoc) o day va o nhanh "cho phep" cuoi ham — day la
    // hai nhanh "file duoc mo thanh cong" DUY NHAT can SmePlanAvMfPostCreateCallback
    // chay de cache SmePlanAvMfIsUnderProtectedFolder cho MOI file (khong chi file
    // thuc thi). WITH_CALLBACK la dieu kien BAT BUOC de Filter Manager goi
    // SmePlanAvMfPostCreateCallback — NO_CALLBACK se lam SmePlanAvMfPostCreateCallback KHONG BAO
    // GIO duoc goi, khien ca co che cache o SmePlanAvMfQueryProtectedFolderWrite vo
    // hieu (luon fallback).
    if (!SmePlanAvMfIsExecutableCandidate(&nameInfo->Extension)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // [HAN CHE MOI TRUONG] Trong ban day du: tra cache ket qua da quet
    // truoc (khoa: duong dan + mtime + kich thuoc, xem NFR-PERF-01) truoc
    // khi hoi service — bo qua trong ban tham chieu nay de giu vi du gon.

    // [SUA LOI NGHIEM TRONG] Truoc day chi RtlZeroMemory rieng query.FilePath
    // — cac truong khac (Type, ProcessId) duoc gan tung truong nhung KHONG
    // xoa PHAN DEM (padding) ma trinh bien dich chen giua cac truong (vi
    // du giua Type 4-byte va ProcessId can align 8-byte tren x64) de dam
    // bao alignment. query la bien local tren stack, phan dem do giu
    // nguyen RAC RUOI con lai tu ngan xep (co the la du lieu cua ham goi
    // truoc, ke ca dia chi con tro/gia tri nhay cam khac). Toan bo struct
    // (sizeof(DRIVER_TO_SERVICE_MSG)) duoc FltSendMessage sao chep NGUYEN
    // VEN sang service — nghia la nhung byte rac do bi RO RI qua ranh gioi
    // kernel/user-mode. Sua: xoa TOAN BO struct truoc khi gan tung truong.
    RtlZeroMemory(&query, sizeof(query));
    query.Type = MsgType_FileOpenQuery;
    query.ProcessId = PsGetCurrentProcessId();
    RtlCopyMemory(
        query.FilePath, nameInfo->Name.Buffer,
        min(nameInfo->Name.Length, sizeof(query.FilePath) - sizeof(WCHAR)));

    FltReleaseFileNameInformation(nameInfo);

    status = SmePlanAvMfQueryServiceDecision(&query, &reply);

    perfEnd = KeQueryPerformanceCounter(NULL);
    // (Ghi delta (perfEnd - perfStart) * 1000000 / perfFreq vao buffer log
    // noi bo trong ban day du — NFR-OBS-01.)
    UNREFERENCED_PARAMETER(perfEnd);

    if (!NT_SUCCESS(status)) {
        // NFR-AVAIL-03: service khong phan hoi kip -> deny-and-log mac dinh
        // (an toan hon allow mu).
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (!reply.Allow) {
        // errors/10: STATUS_ACCESS_DENIED tra ve trong SmePlanAvMfPreCreateCallback
        // khi service quyet dinh BLOCK.
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    // WITH_CALLBACK (xem ghi chu o nhanh non-executable phia tren) —
    // SmePlanAvMfPostCreateCallback se cache SmePlanAvMfIsUnderProtectedFolder cho file nay.
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
SmePlanAvMfPostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PMINIFILTER_STREAM_CONTEXT streamContext = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);

    // [HAN CHE MOI TRUONG — co hoi toi uu CHUA lam trong ban nay] CompletionContext
    // nhan tu SmePlanAvMfPreCreateCallback (tham so thu 3) hien KHONG duoc dung
    // (UNREFERENCED_PARAMETER ben duoi): FltGetFileNameInformation goi lai
    // o day la lan THU HAI cho CUNG mot IRP_MJ_CREATE (lan dau da goi trong
    // SmePlanAvMfPreCreateCallback). Ve nguyen tac co the giu lai mot tham chieu
    // FLT_FILE_NAME_INFORMATION tu Pre va truyen qua CompletionContext de
    // tranh goi FltGetFileNameInformation lan hai — nhung lam dung can quan
    // ly vong doi tham chieu (FltReferenceFileNameInformation/Release) cho
    // CA HAI nhanh cua SmePlanAvMfPreCreateCallback (executable va non-executable,
    // ca hai deu tra WITH_CALLBACK) va xu ly dung khi Post bi goi voi
    // Data->IoStatus.Status loi (file khong mo duoc du Pre da tra allow) —
    // du rui ro de KHONG sua "mu" trong phien khong co trinh bien dich nay;
    // ghi chu lai de nguoi sau can nhac.
    UNREFERENCED_PARAMETER(CompletionContext);

    // Chi cache cho create THANH CONG tren MOT FILE OBJECT that (bo qua
    // loi, va thu muc — thu muc khong bao gio la muc tieu cua IRP_MJ_WRITE
    // nen khong can cache, giam so context cap phat khong can thiet).
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_DIRECTORY_FILE)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        // Khong lay duoc ten -> khong cache duoc. SmePlanAvMfQueryProtectedFolderWrite
        // se tu fallback tinh lai moi lan ghi cho stream nay (dung ve mat
        // logic, chi mat phan toi uu hieu nang cho rieng file nay).
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    FltParseFileNameInformation(nameInfo);

    status = FltAllocateContext(
        FltObjects->Filter, FLT_STREAM_CONTEXT, sizeof(MINIFILTER_STREAM_CONTEXT),
        NonPagedPoolNx, (PFLT_CONTEXT*)&streamContext);
    if (NT_SUCCESS(status)) {
        streamContext->SmePlanAvMfIsUnderProtectedFolder = SmePlanAvMfIsUnderProtectedFolder(
            &nameInfo->Name, &streamContext->CachedProtectedFoldersGeneration);

        // FLT_SET_CONTEXT_KEEP_IF_EXISTS: neu mot thread khac da gan context
        // cho CUNG stream nay truoc (race hiem gap), giu ban da co, khong
        // ghi de — ca hai deu tinh ra cung ket qua nen khong anh huong dung
        // dan, chi tranh cap phat/giai phong thua.
        FltSetStreamContext(
            FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            streamContext, NULL);
        FltReleaseContext(streamContext);
    }
    // Loi FltAllocateContext (vi du thieu bo nho) khong nghiem trong —
    // SmePlanAvMfQueryProtectedFolderWrite se khong tim thay context va tu fallback.

    FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

VOID
SmePlanAvMfProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    DRIVER_TO_SERVICE_MSG query;
    SERVICE_TO_DRIVER_REPLY reply;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        // Tien trinh dang thoat, khong phai dang tao — khong can hoi.
        return;
    }

    if (CreateInfo->ImageFileName == NULL) {
        return;
    }

    // [SUA LOI NGHIEM TRONG] Xoa TOAN BO struct (khong chi FilePath) truoc
    // khi gan tung truong — xem ghi chu chi tiet o SmePlanAvMfPreCreateCallback,
    // cung mot loi ro ri byte dem (padding) chua khoi tao qua FltSendMessage.
    RtlZeroMemory(&query, sizeof(query));
    query.Type = MsgType_ProcessCreateQuery;
    query.ProcessId = ProcessId;
    RtlCopyMemory(
        query.FilePath, CreateInfo->ImageFileName->Buffer,
        min(CreateInfo->ImageFileName->Length, sizeof(query.FilePath) - sizeof(WCHAR)));

    status = SmePlanAvMfQueryServiceDecision(&query, &reply);

    if (!NT_SUCCESS(status) || !reply.Allow) {
        // business-rules/05 "Quyet dinh cap quyen cho tien trinh moi":
        // deny-and-log mac dinh khi khong co quyet dinh ro rang, tru khi
        // da dat TrustedByDefault ngay o tang driver (chua trien khai
        // trong ban tham chieu nay — whitelist 3 lop yeu cau goi
        // WinVerifyTrust, mot API user-mode, nen buoc "tu cho qua" o tang
        // driver trong ban day du can mot co che kiem tra rieng, gon hon,
        // hoac uy quyen hoan toan cho service voi chi phi do tre chap nhan
        // duoc — quyet dinh kien truc nay can ghi trong tai lieu noi bo
        // truoc khi trien khai that).
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

NTSTATUS
SmePlanAvMfQueryServiceDecision(
    _In_ PDRIVER_TO_SERVICE_MSG Query,
    _Out_ PSERVICE_TO_DRIVER_REPLY Reply)
{
    NTSTATUS status;
    ULONG replyLength = sizeof(SERVICE_TO_DRIVER_REPLY);
    LARGE_INTEGER timeout;

    if (gContext.ClientPort == NULL) {
        // Service chua ket noi (vi du dang khoi dong lai) -> deny-and-log.
        return STATUS_PORT_DISCONNECTED;
    }

    // BIZ-04/NFR-PERF-02: gioi han thoi gian cho phan hoi — <50ms cho tra
    // rule co san; FltSendMessage o day dung timeout ngan de khong giu IRP
    // qua lau (hop thoai hoi nguoi dung, neu can, duoc service tu quan ly
    // vong doi rieng, khong chan truc tiep goi FltSendMessage nay qua 30s).
    timeout.QuadPart = -50 * 1000 * 10; // 50ms tinh theo don vi 100ns, am = relative

    status = FltSendMessage(
        gContext.FilterHandle, &gContext.ClientPort,
        Query, sizeof(DRIVER_TO_SERVICE_MSG),
        Reply, &replyLength, &timeout);

    return status;
}

// EXT-RW-01: nhan thong diep PUSH tu service qua FilterSendMessage
// (user-mode) — khac huong voi SmePlanAvMfQueryServiceDecision o tren (driver hoi,
// service tra loi); day la service CHU DONG gui xuong, driver chi cap
// nhat trang thai noi bo, khong tra loi nghiep vu gi.
NTSTATUS
SmePlanAvMfMessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength)
{
    PPUSH_SET_PROTECTED_FOLDERS_MSG msg;
    KIRQL oldIrql;
    ULONG count;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferSize < sizeof(PUSH_SET_PROTECTED_FOLDERS_MSG)) {
        return STATUS_INVALID_PARAMETER;
    }

    msg = (PPUSH_SET_PROTECTED_FOLDERS_MSG)InputBuffer;
    if (msg->Type != PushMsgType_SetProtectedFolders) {
        return STATUS_INVALID_PARAMETER;
    }

    count = min(msg->FolderCount, MINIFILTER_MAX_PROTECTED_FOLDERS);

    // [SUA LOI NGHIEM TRONG] msg->Folders la mang WCHAR co dinh
    // (MINIFILTER_MAX_FOLDER_PATH_CHARS moi phan tu) NHAN THANG tu service
    // qua FilterSendMessage — cung LOAI rui ro da sua o wfp_callout.c
    // SmePlanAvFwDeviceControl (IOCTL_SMEPLANAV_FW_PUSH_RULE): neu mot
    // phan tu KHONG co NUL trong pham vi MINIFILTER_MAX_FOLDER_PATH_CHARS
    // (vi du service co loi marshalling, hoac du lieu bi hong), ham
    // RtlInitUnicodeString goi trong SmePlanAvMfIsUnderProtectedFolder se QUET
    // KHONG GIOI HAN tim NUL (khac RtlStringCchCopyNW da dung o cho khac,
    // RtlInitUnicodeString khong nhan tham so gioi han) — voi phan tu CUOI
    // CUNG trong mang ProtectedFolders, quet nay se DOC VUOT QUA het mang
    // vao vung nho kernel ke tiep (ProtectedFoldersLock roi xa hon), co the
    // gay BSOD. Sua: kiem tra NUL-terminator TRONG BIEN mang cho TUNG phan
    // tu se duoc copy, ngay tai choke point nhan thong diep nay, truoc khi
    // dua vao gContext — tu choi toan bo push neu bat ky phan tu nao thieu
    // NUL hop le.
    {
        ULONG folderIdx, nulCheckIdx;
        BOOLEAN allHaveNul = TRUE;
        for (folderIdx = 0; folderIdx < count && allHaveNul; folderIdx++) {
            BOOLEAN hasNul = FALSE;
            for (nulCheckIdx = 0; nulCheckIdx < MINIFILTER_MAX_FOLDER_PATH_CHARS; nulCheckIdx++) {
                if (msg->Folders[folderIdx][nulCheckIdx] == L'\0') {
                    hasNul = TRUE;
                    break;
                }
            }
            if (!hasNul) {
                allHaveNul = FALSE;
            }
        }
        if (!allHaveNul) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeAcquireSpinLock(&gContext.ProtectedFoldersLock, &oldIrql);
    gContext.ProtectedFolderCount = count;
    RtlCopyMemory(gContext.ProtectedFolders, msg->Folders, count * sizeof(msg->Folders[0]));
    // [SUA LOI NGHIEM TRONG] Tang generation MOI LAN danh sach doi de cac
    // MINIFILTER_STREAM_CONTEXT da cache tu TRUOC lan cap nhat nay tu nhan
    // ra minh STALE (xem MINIFILTER_CONTEXT.ProtectedFoldersGeneration va
    // SmePlanAvMfQueryProtectedFolderWrite) — sua loi "cache khong bao gio duoc
    // lam moi lai sau khi danh sach bao ve thay doi" (file mo TRUOC khi
    // admin them thu muc cua no vao danh sach se khong bao gio duoc bao ve
    // cho toi khi dong/mo lai file, neu khong co co che nay).
    InterlockedIncrement(&gContext.ProtectedFoldersGeneration);
    KeReleaseSpinLock(&gContext.ProtectedFoldersLock, oldIrql);

    return STATUS_SUCCESS;
}

BOOLEAN
SmePlanAvMfIsUnderProtectedFolder(_In_ PCUNICODE_STRING FileName, _Out_opt_ PLONG OutGeneration)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN match = FALSE;

    KeAcquireSpinLock(&gContext.ProtectedFoldersLock, &oldIrql);

    // [SUA LOI NGHIEM TRONG] Doc ProtectedFoldersGeneration CUNG mot lan
    // khoa spinlock voi viec quet danh sach ben duoi, de gia tri tra ve la
    // ban chup DONG BO voi ket qua match — neu doc generation RIENG (ngoai
    // khoa), co the xay ra race: danh sach doi giua luc tinh match va luc
    // doc generation, khien caller (SmePlanAvMfPostCreateCallback) cache mot cap
    // (match, generation) khong khop nhau.
    if (OutGeneration != NULL) {
        *OutGeneration = gContext.ProtectedFoldersGeneration;
    }

    for (i = 0; i < gContext.ProtectedFolderCount; i++) {
        UNICODE_STRING folder;
        USHORT folderLen;

        RtlInitUnicodeString(&folder, gContext.ProtectedFolders[i]);
        folderLen = folder.Length;

        // [SUA LOI NGHIEM TRONG] Truoc day khong kiem tra folderLen == 0:
        // mot phan tu ProtectedFolders[i] rong (vi du slot con lai tu cau
        // hinh loi, hoac chuoi rong duoc push nham) co Length == 0 sau
        // RtlInitUnicodeString. Voi folderLen == 0: dieu kien "FileName->Length
        // < folderLen" khong bao gio dung (khong the < 0), va RtlEqualUnicodeString
        // giua hai chuoi RONG luon tra ve TRUE, nen nhanh kiem tra ranh gioi
        // ben duoi roi vao "FileName->Buffer[0] == L'\\'" — DUNG cho HAU
        // HET moi file (ten file kernel-mode luon bat dau bang '\'), tuc la
        // MOT phan tu rong se khien SmePlanAvMfIsUnderProtectedFolder tra ve TRUE cho
        // GAN NHU MOI file tren he thong, bien tinh nang toi uu "chi hoi
        // service khi thuc su nam trong thu muc bao ve" thanh vo nghia
        // (moi thao tac ghi tren toan he thong deu bi xem la "trong thu
        // muc bao ve" va phai cho hoi service dong bo, co nguy co treo I/O
        // toan he thong neu mot cau hinh loi day xuong mot entry rong). Sua:
        // bo qua (continue) cac phan tu rong ngay tu dau, khong coi la khop.
        if (folderLen == 0) {
            continue;
        }

        // Bo QUA MOT dau '\' cuoi cung neu co (service co the gui duong
        // dan da co san hoac chua co dau phan cach cuoi) — chuan hoa ve
        // cung mot dang truoc khi so sanh boundary ben duoi.
        if (folderLen >= sizeof(WCHAR) &&
            folder.Buffer[(folderLen / sizeof(WCHAR)) - 1] == L'\\') {
            folderLen = (USHORT)(folderLen - sizeof(WCHAR));
        }

        if (folderLen == 0) continue; // toan bo entry chi la "\" sau khi bo dau phan cach -> bo qua, khong khop moi thu

        if (FileName->Length < folderLen) continue;

        {
            UNICODE_STRING prefix;
            prefix.Buffer = FileName->Buffer;
            prefix.Length = folderLen;
            prefix.MaximumLength = folderLen;

            folder.Length = folderLen;
            folder.MaximumLength = folderLen;

            if (!RtlEqualUnicodeString(&prefix, &folder, TRUE)) continue; // TRUE = khong phan biet hoa/thuong

            // [SUA LOI NGHIEM TRONG] So khop prefix DON THUAN nhu tren,
            // KHONG kiem tra ranh gioi dau phan cach thu muc ngay sau no,
            // se khop nham "C:\Documents2\evil.exe" voi thu muc bao ve
            // "C:\Documents" (hoac nguoc lai, mot thu muc con gia mao ten
            // nhu "C:\DocumentsBackup" cung se bi coi la nam trong thu muc
            // bao ve) — cho phep ransomware GHI/DOI TEN file trong thu muc
            // KHONG duoc bao ve ma van bi chan nham, hoac te hon la BYPASS
            // bao ve neu logic dao nguoc. Loi CUNG LOAI da duoc sua o
            // Common/PathUtil.cs (IsPathUnderDirectory) phia service C#
            // nhung CHUA duoc ap dung cho driver nay. Sua: chi coi la khop
            // khi FileName TRUNG KHOP HOAN TOAN voi folder, HOAC ky tu
            // NGAY SAU prefix (o vi tri folderLen/sizeof(WCHAR)) la dau '\'.
            if (FileName->Length == folderLen) {
                match = TRUE;
                break;
            }
            if (FileName->Buffer[folderLen / sizeof(WCHAR)] == L'\\') {
                match = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&gContext.ProtectedFoldersLock, oldIrql);
    return match;
}

// [SUA LOI NGHIEM TRONG] Doc ProtectedFoldersGeneration hien tai KHONG can
// giu spinlock toan bo (chi de kiem tra cache stream context con moi hay
// khong tren hot path IRP_MJ_WRITE — xem SmePlanAvMfQueryProtectedFolderWrite):
// dung InterlockedCompareExchange(...,0,0) de doc nguyen tu (co rao chan
// bo nho), tranh chi phi khoa spinlock day du (dieu se xoa bot loi ich cua
// co che cache stream context ma toi uu hieu nang o day dang bao ve).
static LONG
SmePlanAvMfGetProtectedFoldersGeneration(VOID)
{
    return InterlockedCompareExchange(&gContext.ProtectedFoldersGeneration, 0, 0);
}

// [QUYET DINH TRIEN KHAI CHUNG cho SmePlanAvMfPreWriteCallback + SmePlanAvMfPreSetInformationCallback]
// Ca hai deu dung MOT ham dung chung SmePlanAvMfQueryProtectedFolderWrite (khai bao
// tinh, khong dua vao .h vi chi dung noi bo file nay) de tranh trung lap
// logic "lay ten file -> kiem tra prefix -> hoi service neu khop".
static FLT_PREOP_CALLBACK_STATUS
SmePlanAvMfQueryProtectedFolderWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PMINIFILTER_STREAM_CONTEXT streamContext = NULL;
    NTSTATUS status;
    DRIVER_TO_SERVICE_MSG query;
    SERVICE_TO_DRIVER_REPLY reply;

    // [SUA LOI HIEU NANG] TRUOC DAY ham nay goi FltGetFileNameInformation
    // (FLT_FILE_NAME_NORMALIZED — phai resolve reparse point/ten day du,
    // DAT) cho MOI IRP_MJ_WRITE/SET_INFORMATION TREN TOAN HE THONG TRUOC
    // KHI moi loc theo prefix (SmePlanAvMfIsUnderProtectedFolder). Vi IRP_MJ_WRITE xay
    // ra cho MOI thao tac ghi file cua MOI ung dung dang chay, chi phi nay
    // nhan len rat lon tren hot path I/O he thong. Sua: uu tien doc
    // MINIFILTER_STREAM_CONTEXT da duoc SmePlanAvMfPostCreateCallback tinh SAN MOT LAN
    // luc mo file — neu co cache va no bao KHONG nam trong thu muc bao ve
    // (truong hop pho bien nhat, tuyet dai da so ghi file tren he thong),
    // tra ve NGAY, KHONG can goi FltGetFileNameInformation chut nao. Chi
    // khi cache bao CO trong thu muc bao ve (hiem), hoac KHONG co cache
    // (fallback — vi du file da mo tu truoc khi filter attach), moi can
    // resolve ten day du nhu truoc.
    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&streamContext);
    if (NT_SUCCESS(status) && streamContext != NULL) {
        BOOLEAN cachedUnderProtected = streamContext->SmePlanAvMfIsUnderProtectedFolder;
        LONG cachedGeneration = streamContext->CachedProtectedFoldersGeneration;
        FltReleaseContext(streamContext);

        // [SUA LOI NGHIEM TRONG] Truoc day: cache "khong nam trong thu muc
        // bao ve" duoc tin TUYET DOI cho toi khi file dong, du danh sach
        // thu muc bao ve co the da duoc ADMIN CAP NHAT (them thu muc moi)
        // SAU thoi diem file nay duoc mo — bo NGO su khac biet do, khien
        // mot file dang mo tu TRUOC luc them thu muc bao ve khong bao gio
        // duoc kiem tra lai cho toi khi dong/mo lai handle (co the la VO
        // THOI HAN neu ung dung giu handle mo lien tuc, vi du mot editor).
        // Sua: so sanh CachedProtectedFoldersGeneration voi generation HIEN
        // TAI — chi tin cache khi danh sach CHUA doi ke tu luc cache; neu
        // da doi (hoac cache bao CO trong thu muc bao ve), tinh/hoi lai.
        if (!cachedUnderProtected && cachedGeneration == SmePlanAvMfGetProtectedFoldersGeneration()) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK; // duong nhanh: cache con moi, khong can resolve ten file
        }

        if (cachedUnderProtected) {
            // Cache (du co the stale ve mat generation) da tung bao CO
            // trong thu muc bao ve — giu nguyen hanh vi cu: luon hoi service,
            // uu tien an toan hon la bo sot (neu thu muc da bi go bao ve,
            // service se la noi quyet dinh allow, khong phai driver).
            status = FltGetFileNameInformation(
                Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
            if (!NT_SUCCESS(status)) {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            FltParseFileNameInformation(nameInfo);
        } else {
            // cachedUnderProtected == FALSE nhung generation stale — danh
            // sach thu muc bao ve co the da doi, khong the tin cache nua,
            // phai tinh lai tu dau (giong nhanh fallback ben duoi).
            status = FltGetFileNameInformation(
                Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
            if (!NT_SUCCESS(status)) {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            FltParseFileNameInformation(nameInfo);

            if (!SmePlanAvMfIsUnderProtectedFolder(&nameInfo->Name, NULL)) {
                FltReleaseFileNameInformation(nameInfo);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
        }
    } else {
        // Fallback: khong co cache (vi du file mo truoc khi filter attach,
        // hoac SmePlanAvMfPostCreateCallback truoc do khong cap phat duoc context) —
        // tu tinh lai nhu hanh vi cu, khong anh huong tinh dung dan.
        status = FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (!NT_SUCCESS(status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        FltParseFileNameInformation(nameInfo);

        if (!SmePlanAvMfIsUnderProtectedFolder(&nameInfo->Name, NULL)) {
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    // [SUA LOI NGHIEM TRONG] Xoa TOAN BO struct truoc khi gan tung truong —
    // xem ghi chu chi tiet o SmePlanAvMfPreCreateCallback (ro ri byte dem chua
    // khoi tao qua FltSendMessage).
    RtlZeroMemory(&query, sizeof(query));
    query.Type = MsgType_ProtectedWriteQuery;
    query.ProcessId = PsGetCurrentProcessId();
    RtlCopyMemory(
        query.FilePath, nameInfo->Name.Buffer,
        min(nameInfo->Name.Length, sizeof(query.FilePath) - sizeof(WCHAR)));
    FltReleaseFileNameInformation(nameInfo);

    status = SmePlanAvMfQueryServiceDecision(&query, &reply);

    if (!NT_SUCCESS(status)) {
        // [QUYET DINH TRIEN KHAI] Khac voi SmePlanAvMfPreCreateCallback (deny-and-log
        // khi timeout) — o day service co the dang BAN THAN dang xu ly
        // (vi du dang snapshot mot file lon khac) va khong kip tra loi
        // trong 50ms; tu choi CUNG mot GHI hop le vao file nguoi dung dang
        // lam viec binh thuong (vi du Word tu luu) se gay gian doan ro
        // rang hon rui ro bo lot MOT lan ghi don le cua ransomware (van
        // con hai tin hieu con lai — entropy + doi hang loat duoi — de
        // EventBus/RansomwareGuardService phat hien va rollback qua
        // version store ngay sau do). Ghi ro day la danh doi UX so voi
        // SmePlanAvMfPreCreateCallback, khong phai mau thuan logic.
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!reply.Allow) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
SmePlanAvMfPreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    return SmePlanAvMfQueryProtectedFolderWrite(Data, FltObjects);
}

FLT_PREOP_CALLBACK_STATUS
SmePlanAvMfPreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    UNREFERENCED_PARAMETER(CompletionContext);

    // Chi quan tam doi ten (FileRenameInformation/FileRenameInformationEx)
    // va xoa (FileDispositionInformation) — day la hai thao tac
    // IRP_MJ_SET_INFORMATION lien quan truc tiep toi "doi hang loat sang
    // cung mot duoi la" ma tai lieu mo ta, cac loai FileInformationClass
    // khac (vi du doi thuoc tinh) khong lien quan toi hanh vi ransomware.
    if (infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx &&
        infoClass != FileDispositionInformation) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return SmePlanAvMfQueryProtectedFolderWrite(Data, FltObjects);
}
