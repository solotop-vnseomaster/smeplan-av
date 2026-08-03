// wfp_callout.h
// [HAN CHE MOI TRUONG] File nay la MA NGUON THAM CHIEU cho WFP callout
// driver mo ta trong "tai lieu moi.txt" muc "Firewall lop ung dung bang
// WFP" (EXT-FW-01/04). KHONG bien dich duoc trong phien lam viec nay —
// cung ly do da ghi trong app/drivers/README.md (khong co WDK). Can them
// header rieng cho WFP (`fwpsk.h`, `fwpmk.h`) ngoai fltKernel.h da dung
// cho minifilter — day la MOT driver .sys RIENG, khong dung chung binary
// voi minifilter (WFP callout va Filter Manager la hai co che kernel
// khac nhau, dang ky qua hai API hoan toan doc lap).
#pragma once

#include <fwpsk.h>
#include <fwpmk.h>
#include <ntddk.h>
#include <wdmsec.h> // IoCreateDeviceSecure — can them wdmsec.lib vao linker input khi build that

// GUID rieng cho callout va sublayer nay — gia tri PLACEHOLDER, driver
// that phai tu sinh GUID rieng (vi du bang guidgen.exe) va giu co dinh
// giua cac phien ban de FwpmFilterAdd khong tao trung lap khi driver
// nap lai.
DEFINE_GUID(SMEPLANAV_CALLOUT_GUID,
    0x1a2b3c4d, 0x5e6f, 0x4a7b, 0x8c, 0x9d, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5);
DEFINE_GUID(SMEPLANAV_SUBLAYER_GUID,
    0x2b3c4d5e, 0x6f7a, 0x4b8c, 0x9d, 0xae, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06);

// "tai lieu moi.txt": "Cache quyet dinh (path, port, protocol) trong
// kernel callout" — mang co dinh don gian (khong dung cau truc phuc tap
// trong kernel de tranh loi cap phat bo nho tai IRQL cao); PUSH tu
// service qua IOCTL, KHONG bao gio tu goi ra ngoai kernel de tra cuu (do
// se lam cham duong dan ket noi TCP/UDP that).
#define SMEPLANAV_FW_CACHE_CAPACITY 4096
#define SMEPLANAV_FW_MAX_PATH_CHARS 260

typedef enum _SMEPLANAV_FW_ACTION {
    FwAction_Allow = 1,
    FwAction_Block = 2,
} SMEPLANAV_FW_ACTION;

typedef struct _SMEPLANAV_FW_CACHE_ENTRY {
    BOOLEAN InUse;
    WCHAR ProcessPath[SMEPLANAV_FW_MAX_PATH_CHARS];
    UINT16 RemotePort;
    UINT8 Protocol;            // IPPROTO_TCP / IPPROTO_UDP
    SMEPLANAV_FW_ACTION Action;
} SMEPLANAV_FW_CACHE_ENTRY, *PSMEPLANAV_FW_CACHE_ENTRY;

typedef struct _SMEPLANAV_FW_CONTEXT {
    HANDLE EngineHandle;               // FwpmEngineOpen0
    UINT32 CalloutId;                  // FwpsCalloutRegister0 tra ve
    BOOLEAN CalloutRegistered;
    PDEVICE_OBJECT DeviceObject;       // \\.\SmePlanAvFwCallout de service ket noi qua IOCTL

    KSPIN_LOCK CacheLock;
    SMEPLANAV_FW_CACHE_ENTRY Cache[SMEPLANAV_FW_CACHE_CAPACITY];

    // Hang doi IRP cho "unknown app can quyet dinh" — xem ghi chu
    // [QUYET DINH TRIEN KHAI] o dau wfp_callout.c ve ly do khong the hoi
    // dong bo trong classifyFn.
    LIST_ENTRY PendingNotifyIrps;
    KSPIN_LOCK PendingNotifyLock;
} SMEPLANAV_FW_CONTEXT, *PSMEPLANAV_FW_CONTEXT;

// --- IOCTL giua service (user-mode) va driver nay ---
#define IOCTL_SMEPLANAV_FW_PUSH_RULE \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SMEPLANAV_FW_READ_UNKNOWN_APP \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef struct _SMEPLANAV_FW_PUSH_RULE_REQUEST {
    WCHAR ProcessPath[SMEPLANAV_FW_MAX_PATH_CHARS];
    UINT16 RemotePort;
    UINT8 Protocol;
    SMEPLANAV_FW_ACTION Action;
} SMEPLANAV_FW_PUSH_RULE_REQUEST, *PSMEPLANAV_FW_PUSH_RULE_REQUEST;

typedef struct _SMEPLANAV_FW_UNKNOWN_APP_EVENT {
    WCHAR ProcessPath[SMEPLANAV_FW_MAX_PATH_CHARS];
    UINT32 RemoteAddressV4;    // network byte order
    UINT16 RemotePort;
    UINT8 Protocol;
} SMEPLANAV_FW_UNKNOWN_APP_EVENT, *PSMEPLANAV_FW_UNKNOWN_APP_EVENT;

// --- Khai bao ham chinh ---
DRIVER_INITIALIZE DriverEntry;
VOID SmePlanAvFwDriverUnload(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS SmePlanAvFwCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS SmePlanAvFwDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

VOID NTAPI SmePlanAvClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

NTSTATUS NTAPI SmePlanAvNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter);

// Tra ve TRUE neu tim thay trong cache (Action duoc dien); FALSE neu
// chua co ban ghi nao khop (cache miss).
BOOLEAN SmePlanAvFwCacheLookup(
    _In_ PSMEPLANAV_FW_CONTEXT Context,
    _In_ PCWSTR ProcessPath, _In_ UINT16 RemotePort, _In_ UINT8 Protocol,
    _Out_ SMEPLANAV_FW_ACTION* Action);

VOID SmePlanAvFwCacheUpsert(
    _In_ PSMEPLANAV_FW_CONTEXT Context,
    _In_ PCWSTR ProcessPath, _In_ UINT16 RemotePort, _In_ UINT8 Protocol,
    _In_ SMEPLANAV_FW_ACTION Action);
