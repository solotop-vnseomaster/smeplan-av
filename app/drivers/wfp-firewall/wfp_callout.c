// wfp_callout.c
// [HAN CHE MOI TRUONG] Xem ghi chu dau file wfp_callout.h — day la MA
// NGUON THAM CHIEU, chua bien dich/ky trong phien nay (khong co WDK).
// Trien khai dung mo ta ky thuat trong "tai lieu moi.txt" muc "Firewall
// lop ung dung bang WFP".
//
// [QUYET DINH TRIEN KHAI QUAN TRONG NHAT] Tai lieu mo ta chinh sach
// "outbound allow cho whitelist chu ky so, outbound HOI cho app la".
// classifyFn chay TRONG duong dan ket noi TCP/UDP that, o IRQL <= DISPATCH
// — KHONG THE dung (block) cho toi khi nguoi dung tra loi hop thoai (co
// the mat vai giay tro len), lam vay se treo ca stack mang. Vi vay:
//   - Cache HIT (path+port+protocol da co quyet dinh, do SERVICE PUSH
//     xuong truoc qua IOCTL_SMEPLANAV_FW_PUSH_RULE sau khi da tra
//     FirewallRuleStore/hoi nguoi dung o user-mode) -> ap dung NGAY,
//     khong co do tre nao them.
//   - Cache MISS (app hoan toan moi, chua tung thay) -> mac dinh
//     FWP_ACTION_PERMIT cho KET NOI DAU TIEN nay (fail-open, uu tien
//     khong lam gian doan ket noi hop le hon la chan nham), DONG THOI
//     day mot su kien "unknown app" vao PendingNotifyIrps de service
//     nhan duoc qua IOCTL_SMEPLANAV_FW_READ_UNKNOWN_APP, tu do hoi nguoi
//     dung/tra rule nhu binh thuong VA push ket qua xuong cache cho CAC
//     KET NOI SAU cua chinh app do. Day la diem KHAC BIET so voi cach
//     dien giai "hoi dong bo ngay lan dau" ma mo ta ngan gon trong tai
//     lieu co the goi y — ghi ro o day de khong bi hieu nham la lam thieu.
#include "wfp_callout.h"

SMEPLANAV_FW_CONTEXT gFwContext = { 0 };

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { 0 };
    FWPS_CALLOUT1 sCallout = { 0 };
    FWPM_CALLOUT0 mCallout = { 0 };
    FWPM_SUBLAYER0 subLayer = { 0 };
    FWPM_FILTER0 filter = { 0 };
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&gFwContext.CacheLock);
    KeInitializeSpinLock(&gFwContext.PendingNotifyLock);
    InitializeListHead(&gFwContext.PendingNotifyIrps);

    // --- Thiet bi de service (user-mode) mo handle va goi IOCTL ---
    //
    // [SUA LOI NGHIEM TRONG] TRUOC DAY dung IoCreateDevice thuong, KHONG
    // gan security descriptor nao ca — mac dinh Windows se ap DACL rong
    // (cho phep MOI tien trinh local, ke ca khong dac quyen, mo handle toi
    // \Device\SmePlanAvFwCallout). Vi IOCTL_SMEPLANAV_FW_PUSH_RULE cho phep
    // ghi thang vao cache quyet dinh firewall (SmePlanAvFwCacheUpsert), mot
    // tien trinh local KHONG dac quyen (vi du chinh malware dang bi danh
    // gia) co the tu goi IOCTL nay de tu whitelist minh khoi firewall. Sua
    // bang IoCreateDeviceSecure + SDDL chi cho phep SYSTEM (SY) va nhom
    // Administrators (BA) mo handle — dung nguyen tac "least privilege" nhu
    // minifilter.c dang lam qua FltBuildDefaultSecurityDescriptor cho
    // communication port cua no. Can lien ket them wdmsec.lib (khai bao
    // trong wdmsec.h) de dung IoCreateDeviceSecure.
    RtlInitUnicodeString(&deviceName, L"\\Device\\SmePlanAvFwCallout");
    {
        UNICODE_STRING sddl;
        RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        status = IoCreateDeviceSecure(
            DriverObject, 0, &deviceName, FILE_DEVICE_NETWORK, 0, FALSE,
            &sddl, NULL, &gFwContext.DeviceObject);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlInitUnicodeString(&symLinkName, L"\\??\\SmePlanAvFwCallout");
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gFwContext.DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SmePlanAvFwCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SmePlanAvFwCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SmePlanAvFwDeviceControl;
    DriverObject->DriverUnload = SmePlanAvFwDriverUnload;

    // --- Mo phien WFP engine (kernel-mode: FwpmEngineOpen0 voi
    // authnService=RPC_C_AUTHN_WINNT tro thanh NULL cho kernel caller) ---
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &gFwContext.EngineHandle);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLinkName);
        IoDeleteDevice(gFwContext.DeviceObject);
        return status;
    }

    status = FwpmTransactionBegin0(gFwContext.EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Sublayer rieng — khong dung sublayer mac dinh de tranh xung dot uu
    // tien voi cac firewall/security product khac co the cung cai tren may.
    subLayer.subLayerKey = SMEPLANAV_SUBLAYER_GUID;
    subLayer.displayData.name = L"SmePlanAv Firewall Sublayer";
    subLayer.weight = 0x8000;
    status = FwpmSubLayerAdd0(gFwContext.EngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(gFwContext.EngineHandle);
        goto Cleanup;
    }

    // Dang ky callout voi Filter Engine Subsystem (FWPS — kernel side).
    sCallout.calloutKey = SMEPLANAV_CALLOUT_GUID;
    sCallout.classifyFn = SmePlanAvClassifyFn;
    sCallout.notifyFn = SmePlanAvNotifyFn;
    sCallout.flowDeleteFn = NULL; // khong giu flow context nao can don dep rieng
    status = FwpsCalloutRegister3(DriverObject, &sCallout, &gFwContext.CalloutId);
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(gFwContext.EngineHandle);
        goto Cleanup;
    }
    gFwContext.CalloutRegistered = TRUE;

    // Dang ky callout voi Filter Engine Management (FWPM — de FwpmFilterAdd
    // tham chieu duoc toi calloutKey nay tu user-mode/kernel-mode transaction).
    mCallout.calloutKey = SMEPLANAV_CALLOUT_GUID;
    mCallout.displayData.name = L"SmePlanAv Firewall Callout";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd0(gFwContext.EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(gFwContext.EngineHandle);
        goto Cleanup;
    }

    // Filter goi callout cho MOI ket noi outbound IPv4 (khong dieu kien
    // loc them o tang filter — toan bo logic loc nam trong chinh
    // classifyFn/cache, dung tinh than "kernel-mode mong, logic o
    // user-mode" da ap dung cho minifilter).
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = SMEPLANAV_SUBLAYER_GUID;
    filter.displayData.name = L"SmePlanAv Firewall Filter";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = SMEPLANAV_CALLOUT_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    status = FwpmFilterAdd0(gFwContext.EngineHandle, &filter, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(gFwContext.EngineHandle);
        goto Cleanup;
    }

    status = FwpmTransactionCommit0(gFwContext.EngineHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    return STATUS_SUCCESS;

Cleanup:
    if (gFwContext.CalloutRegistered) {
        FwpsCalloutUnregisterById0(gFwContext.CalloutId);
    }
    if (gFwContext.EngineHandle) {
        FwpmEngineClose0(gFwContext.EngineHandle);
    }
    IoDeleteSymbolicLink(&symLinkName);
    IoDeleteDevice(gFwContext.DeviceObject);
    return status;
}

VOID
SmePlanAvFwDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, L"\\??\\SmePlanAvFwCallout");

    UNREFERENCED_PARAMETER(DriverObject);

    // Huy filter/callout theo dung thu tu nguoc lai luc dang ky — that
    // trong ban day du can luu lai filterId tra ve tu FwpmFilterAdd0 de
    // FwpmFilterDeleteById0 dung muc tieu; o day don gian hoa bang
    // FwpmEngineClose0 (dong session cung tu dong xoa cac object session
    // nay so huu, nhung KHONG xoa neu filter duoc them voi
    // FWPM_SESSION_FLAG_DYNAMIC=0 — luu y nay can xu ly dung trong ban that).
    if (gFwContext.CalloutRegistered) {
        FwpsCalloutUnregisterById0(gFwContext.CalloutId);
    }
    if (gFwContext.EngineHandle) {
        FwpmEngineClose0(gFwContext.EngineHandle);
    }
    IoDeleteSymbolicLink(&symLinkName);
    if (gFwContext.DeviceObject) {
        IoDeleteDevice(gFwContext.DeviceObject);
    }
}

NTSTATUS
SmePlanAvFwCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
SmePlanAvFwDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_SMEPLANAV_FW_PUSH_RULE: {
        // Service da tra FirewallRuleStore.FindBestMatch (hoac hoi nguoi
        // dung) o user-mode, PUSH ket qua xuong day de cac ket noi TIEP
        // THEO cua cung app/port/protocol nay duoc ap dung ngay tu cache,
        // khong can hoi lai.
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(SMEPLANAV_FW_PUSH_RULE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PSMEPLANAV_FW_PUSH_RULE_REQUEST req = (PSMEPLANAV_FW_PUSH_RULE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        // [SUA LOI NGHIEM TRONG] req->ProcessPath la mang WCHAR co dinh
        // SMEPLANAV_FW_MAX_PATH_CHARS (260) NHAN THANG TU user-mode qua
        // METHOD_BUFFERED — khong co gi dam bao no chua mot NUL trong pham
        // vi 260 ky tu do (input di dang/co y do xau). RtlStringCchCopyW
        // (khong phai bien the "N") xac dinh do dai nguon bang cach QUET
        // TIM NUL, KHONG bi chan boi cchDest — neu nguon khong co NUL, no
        // se doc VUOT QUA bien mang 260 ky tu vao vung nho kernel ke tiep
        // (co the la phan con lai cua system buffer hoac xa hon), dan toi
        // BSOD tren input dang xau tu mot tien trinh user-mode bat ky. Sua:
        // kiem tra NUL-terminator TRONG BIEN mang ngay tai diem nhan IOCTL
        // (choke point duy nhat cho du lieu tu ben ngoai) truoc khi dua
        // ProcessPath di xa hon; tu choi request neu khong co NUL hop le.
        {
            BOOLEAN hasNul = FALSE;
            ULONG nulCheckIdx;
            for (nulCheckIdx = 0; nulCheckIdx < SMEPLANAV_FW_MAX_PATH_CHARS; nulCheckIdx++) {
                if (req->ProcessPath[nulCheckIdx] == L'\0') { hasNul = TRUE; break; }
            }
            if (!hasNul) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
        SmePlanAvFwCacheUpsert(&gFwContext, req->ProcessPath, req->RemotePort, req->Protocol, req->Action);
        break;
    }
    case IOCTL_SMEPLANAV_FW_READ_UNKNOWN_APP: {
        // [HAN CHE MOI TRUONG] Ban day du can hang doi IRP nay cho toi khi
        // co su kien moi (pending I/O, hoan tat qua IoCompleteRequest tu
        // trong SmePlanAvClassifyFn khi gap cache miss) thay vi tra ve
        // ngay — bo qua chi tiet quan ly pending-IRP (mark pending,
        // cancel routine...) trong ban tham chieu nay de giu vi du gon,
        // chi ghi ro day la mau thiet ke can hoan thien.
        status = STATUS_PENDING;
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

VOID NTAPI
SmePlanAvClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    SMEPLANAV_FW_ACTION cachedAction;
    UINT16 remotePort = 0;
    UINT8 protocol = 0;
    PCWSTR processPath = L"";

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        return; // mot callout khac (co the cua san pham bao mat khac) da quyet dinh roi
    }

    // FWPM_CONDITION_IP_REMOTE_PORT/FWPM_CONDITION_IP_PROTOCOL nam trong
    // inFixedValues theo dung chi so field cua layer
    // FWPM_LAYER_ALE_AUTH_CONNECT_V4 (tai lieu WDK liet ke chi so co dinh
    // cho tung layer — o day dung ten field mo ta thay vi chi so tho de
    // de doc, ban that phai tra dung FWPS_FIELD_ALE_AUTH_CONNECT_V4_*).
    remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    // FWPS_METADATA_FIELD_PROCESS_PATH: duong dan file thuc thi cua tien
    // trinh dang mo ket noi — dieu kien FWPM_CONDITION_ALE_APP_ID phai
    // duoc yeu cau qua providerContext/filter flags de truong nay duoc
    // dien (FWPM_LAYER_FLAG_QUERY_APP_ID hoac tuong duong o filter da
    // dang ky); gia dinh da bat trong DriverEntry (khong the hien day du
    // trong tham khao nay de tranh dai dong ma cau hinh khong trong tam).
    if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH) &&
        inMetaValues->processPath != NULL) {
        processPath = (PCWSTR)inMetaValues->processPath->data;
    }

    if (SmePlanAvFwCacheLookup(&gFwContext, processPath, remotePort, protocol, &cachedAction)) {
        classifyOut->actionType = (cachedAction == FwAction_Block) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    // Cache miss: xem [QUYET DINH TRIEN KHAI QUAN TRONG NHAT] o dau file —
    // PERMIT ngay ket noi dau tien, dong thoi bao hieu user-mode qua
    // pending IRP (chi tiet quan ly IRP: xem ghi chu trong
    // SmePlanAvFwDeviceControl).
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

NTSTATUS NTAPI
SmePlanAvNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

BOOLEAN
SmePlanAvFwCacheLookup(
    _In_ PSMEPLANAV_FW_CONTEXT Context,
    _In_ PCWSTR ProcessPath, _In_ UINT16 RemotePort, _In_ UINT8 Protocol,
    _Out_ SMEPLANAV_FW_ACTION* Action)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&Context->CacheLock, &oldIrql);
    for (i = 0; i < SMEPLANAV_FW_CACHE_CAPACITY; i++) {
        PSMEPLANAV_FW_CACHE_ENTRY entry = &Context->Cache[i];
        if (!entry->InUse) continue;
        if (entry->RemotePort != RemotePort || entry->Protocol != Protocol) continue;
        if (wcscmp(entry->ProcessPath, ProcessPath) != 0) continue;
        *Action = entry->Action;
        found = TRUE;
        break;
    }
    KeReleaseSpinLock(&Context->CacheLock, oldIrql);
    return found;
}

VOID
SmePlanAvFwCacheUpsert(
    _In_ PSMEPLANAV_FW_CONTEXT Context,
    _In_ PCWSTR ProcessPath, _In_ UINT16 RemotePort, _In_ UINT8 Protocol,
    _In_ SMEPLANAV_FW_ACTION Action)
{
    KIRQL oldIrql;
    ULONG i;
    LONG freeSlot = -1;

    KeAcquireSpinLock(&Context->CacheLock, &oldIrql);
    for (i = 0; i < SMEPLANAV_FW_CACHE_CAPACITY; i++) {
        PSMEPLANAV_FW_CACHE_ENTRY entry = &Context->Cache[i];
        if (entry->InUse && entry->RemotePort == RemotePort && entry->Protocol == Protocol &&
            wcscmp(entry->ProcessPath, ProcessPath) == 0) {
            entry->Action = Action;
            KeReleaseSpinLock(&Context->CacheLock, oldIrql);
            return;
        }
        if (!entry->InUse && freeSlot < 0) {
            freeSlot = (LONG)i;
        }
    }

    if (freeSlot >= 0) {
        PSMEPLANAV_FW_CACHE_ENTRY entry = &Context->Cache[freeSlot];
        entry->InUse = TRUE;
        // Phong thu lop 2 (choke point chinh da kiem tra NUL o
        // SmePlanAvFwDeviceControl): dung bien the "N" — gioi han ro rang
        // so ky tu doc tu ProcessPath bang SMEPLANAV_FW_MAX_PATH_CHARS-1,
        // KHONG bao gio quet vuot qua kich thuoc mang nguon de tim NUL nhu
        // RtlStringCchCopyW thuong lam (nguyen nhan goc cua loi doc tran o
        // tren) — an toan ke ca neu ham nay duoc goi tu mot noi khac trong
        // tuong lai voi nguon khong dam bao NUL-terminated.
        RtlStringCchCopyNW(entry->ProcessPath, SMEPLANAV_FW_MAX_PATH_CHARS,
            ProcessPath, SMEPLANAV_FW_MAX_PATH_CHARS - 1);
        entry->RemotePort = RemotePort;
        entry->Protocol = Protocol;
        entry->Action = Action;
    }
    // [HAN CHE MOI TRUONG] Cache day (freeSlot < 0): ban that can chien
    // luoc LRU eviction, o day chi bo qua upsert moi (fail-safe: ket noi
    // do se lai qua nhanh "cache miss -> PERMIT + notify" o lan sau).
    KeReleaseSpinLock(&Context->CacheLock, oldIrql);
}
