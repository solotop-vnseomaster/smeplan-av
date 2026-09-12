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

//
// [SUA LOI NGHIEM TRONG] Go TOAN BO cac object da dang ky, theo dung thu tu
// nguoc lai luc them, va CHI nhung cai that su da them thanh cong.
//
// TRUOC DAY ca nhanh Cleanup cua DriverEntry lan DriverUnload chi goi
// FwpsCalloutUnregisterById0 + FwpmEngineClose0, kem mot comment noi rang
// dong session "cung tu dong xoa cac object session nay so huu, NHUNG KHONG
// xoa neu filter duoc them voi FWPM_SESSION_FLAG_DYNAMIC=0" — dung la truong
// hop dang xay ra. Comment do mo ta chinh xac mot lo hong ma khong ai sua:
// filter van ton tai va van tro toi callout vua bi go dang ky.
//
// Thu tu bat buoc: filter (nguoi dung callout) -> callout FWPM -> sublayer ->
// go dang ky callout FWPS. Go callout FWPS truoc khi xoa filter dang tham
// chieu no chinh la kich ban bugcheck.
//
static VOID
SmePlanAvFwTeardownWfpObjects(VOID)
{
    if (gFwContext.EngineHandle == NULL) {
        return;
    }

    if (gFwContext.FilterAdded) {
        FwpmFilterDeleteById0(gFwContext.EngineHandle, gFwContext.FilterId);
        gFwContext.FilterAdded = FALSE;
    }
    if (gFwContext.MgmtCalloutAdded) {
        FwpmCalloutDeleteByKey0(gFwContext.EngineHandle, &SMEPLANAV_CALLOUT_GUID);
        gFwContext.MgmtCalloutAdded = FALSE;
    }
    if (gFwContext.SubLayerAdded) {
        FwpmSubLayerDeleteByKey0(gFwContext.EngineHandle, &SMEPLANAV_SUBLAYER_GUID);
        gFwContext.SubLayerAdded = FALSE;
    }

    if (gFwContext.CalloutRegistered) {
        FwpsCalloutUnregisterById0(gFwContext.CalloutId);
        gFwContext.CalloutRegistered = FALSE;
    }

    FwpmEngineClose0(gFwContext.EngineHandle);
    gFwContext.EngineHandle = NULL;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { 0 };
    // [SUA LOI NGHIEM TRONG] TRUOC DAY khai bao la FWPS_CALLOUT1 nhung duoc
    // truyen cho FwpsCalloutRegister3, ham nay nhan `const FWPS_CALLOUT3*`.
    // Hai struct KHONG dong nhat (chu ky cua classifyFn/notifyFn khac nhau
    // giua cac phien ban callout), nen WDK that se tu choi bien dich —
    // driver nay chua tung duoc dich thu.
    FWPS_CALLOUT3 sCallout = { 0 };
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
    // [SUA LOI NGHIEM TRONG] Tham so DeviceCharacteristics (tham so thu 5)
    // TRUOC DAY la 0 — THIEU FILE_DEVICE_SECURE_OPEN. Khong co co nay, SDDL
    // o tren CHI duoc ap dung khi mo CHINH device, con moi lan mo mot
    // "duong dan phu" duoi device (vi du \.\SmePlanAvFwCalloutat_ky) deu BO QUA
    // security descriptor cua device — mot tien trinh quyen thuong chi can
    // them mot dau gach cheo la qua duoc toan bo kiem tra quyen va goi
    // duoc IOCTL. Comment ben tren tuyen bo lo hong nay da duoc va bang
    // IoCreateDeviceSecure + SDDL; tuyen bo do KHONG dung neu thieu co nay.
        status = IoCreateDeviceSecure(
            DriverObject, 0, &deviceName, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE,
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
    // [SUA LOI NGHIEM TRONG] TRUOC DAY session duoc mo voi flags = 0. Cac
    // object FWPM them trong mot session KHONG dynamic la object BEN VUNG:
    // chung song tiep sau khi FwpmEngineClose0 va sau ca khi driver unload.
    // Ket hop voi DriverUnload (khong xoa filter nao) hau qua la:
    //   - mot filter mo coi tro toi callout DA duoc go dang ky -> ket noi
    //     outbound ke tiep lam bugcheck;
    //   - sau reboot, filter/callout/sublayer cu VAN CON va chiem dung cac
    //     GUID ma DriverEntry can -> FwpmSubLayerAdd0/FwpmCalloutAdd0 that
    //     bai voi FWP_E_ALREADY_EXISTS -> driver khong bao gio nap lai duoc,
    //     va duong sua (go driver) bi chan boi chinh nguyen nhan do.
    // FWPM_SESSION_FLAG_DYNAMIC lam moi object do session nay them bi xoa
    // TU DONG khi session dong (ke ca khi tien trinh/driver chet bat thuong)
    // — dung ngu nghia can cho mot driver co the unload.
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
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
    gFwContext.SubLayerAdded = TRUE;

    // Dang ky callout voi Filter Engine Subsystem (FWPS — kernel side).
    sCallout.calloutKey = SMEPLANAV_CALLOUT_GUID;
    sCallout.classifyFn = SmePlanAvClassifyFn;
    sCallout.notifyFn = SmePlanAvNotifyFn;
    sCallout.flowDeleteFn = NULL; // khong giu flow context nao can don dep rieng
    // [SUA LOI NGHIEM TRONG] Tham so dau cua FwpsCalloutRegister3 la
    // `void* deviceObject` — DEVICE object ma callout gan vao, KHONG phai
    // driver object. TRUOC DAY truyen DriverObject vao day: sai kieu doi
    // tuong hoan toan, WFP se dereference no nhu mot DEVICE_OBJECT.
    status = FwpsCalloutRegister3(gFwContext.DeviceObject, &sCallout, &gFwContext.CalloutId);
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
    gFwContext.MgmtCalloutAdded = TRUE;

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
    // [SUA LOI NGHIEM TRONG] TRUOC DAY tham so cuoi la NULL, tuc filterId do
    // FwpmFilterAdd0 sinh ra bi VUT BO — khong con cach nao xoa dung filter
    // nay luc unload. Giu lai id.
    status = FwpmFilterAdd0(gFwContext.EngineHandle, &filter, NULL, &gFwContext.FilterId);
    if (!NT_SUCCESS(status)) {
        FwpmTransactionAbort0(gFwContext.EngineHandle);
        goto Cleanup;
    }
    gFwContext.FilterAdded = TRUE;

    status = FwpmTransactionCommit0(gFwContext.EngineHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    return STATUS_SUCCESS;

Cleanup:
    SmePlanAvFwTeardownWfpObjects();
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

    // Huy filter/callout/sublayer theo dung thu tu nguoc lai luc dang ky —
    // xem SmePlanAvFwTeardownWfpObjects.
    SmePlanAvFwTeardownWfpObjects();
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
        //
        // [SUA LOI CAO — LOI GIAO THUC IRP] TRUOC DAY nhanh nay tra ve
        // STATUS_PENDING NHUNG van roi xuong IoCompleteRequest o cuoi ham.
        // STATUS_PENDING la mot LOI HUA voi I/O Manager rang driver con
        // giu IRP va se hoan tat no sau; hoan tat no NGAY khien I/O Manager
        // thao tac tiep tren mot IRP da giai phong (use-after-free trong
        // kernel, tu mot IOCTL binh thuong). IoMarkIrpPending — bat buoc
        // truoc khi tra STATUS_PENDING — cung khong he duoc goi.
        //
        // Hang doi IRP pending o day chua bao gio duoc trien khai. Nen thay
        // vi giu mot loi giao thuc de "giu cho" cho mot thiet ke chua co,
        // hay that bai TO va DUNG CACH: bao ro chuc nang chua co, hoan tat
        // IRP dung giao thuc. Service se thay STATUS_NOT_IMPLEMENTED va
        // biet chinh xac tinh trang, thay vi lam sap may.
        //
        status = STATUS_NOT_IMPLEMENTED;
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
        if (cachedAction == FwAction_Block) {
            // Chi khi CHINH TA quyet dinh CHAN moi xoa quyen ghi action cua
            // cac callout phia sau — day la mot quyet dinh chan dut khoat,
            // khong filter nao duoc phep noi long no.
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        } else {
            // [SUA LOI NGHIEM TRONG] TRUOC DAY nhanh PERMIT cung xoa
            // FWPS_RIGHT_ACTION_WRITE. Xoa co do o mot quyet dinh CHO PHEP
            // nghia la VETO moi filter dung sau trong chuoi — bao gom
            // Windows Defender Firewall va moi rule tuong lua nguoi dung tu
            // dat. Nghia la cai dat san pham nay lam may KEM AN TOAN HON so
            // voi khong cai. Cho phep thi phai de cac filter khac tiep tuc
            // co tieng noi.
            classifyOut->actionType = FWP_ACTION_PERMIT;
        }
        return;
    }

    // Cache miss: xem [QUYET DINH TRIEN KHAI QUAN TRONG NHAT] o dau file —
    // PERMIT ngay ket noi dau tien, dong thoi bao hieu user-mode qua
    // pending IRP (chi tiet quan ly IRP: xem ghi chu trong
    // SmePlanAvFwDeviceControl).
    // [SUA LOI NGHIEM TRONG] Xem nhanh cache-hit o tren: cache-miss la luc
    // ta KHONG co y kien gi ca, nen cang tuyet doi khong duoc veto cac
    // filter phia sau. Giu nguyen classifyOut->rights de Windows Defender
    // Firewall va cac rule khac van duoc danh gia binh thuong.
    classifyOut->actionType = FWP_ACTION_PERMIT;
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
        // [SUA LOI NGHIEM TRONG] wcscmp phan biet hoa/thuong nhung duong
        // dan file tren Windows la KHONG phan biet hoa/thuong — mot app bi
        // Block van PERMIT duoc (fail-open mac dinh khi cache-miss) chi
        // bang cach doi hoa/thuong trong path khi chay lai. Dung _wcsicmp
        // (nhu minifilter.c da lam dung o noi khac trong cung repo).
        if (_wcsicmp(entry->ProcessPath, ProcessPath) != 0) continue;
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
            _wcsicmp(entry->ProcessPath, ProcessPath) == 0) {
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
