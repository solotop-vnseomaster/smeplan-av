// minifilter.h
// [HAN CHE MOI TRUONG] File nay la MA NGUON THAM CHIEU cho driver
// minifilter kernel-mode mo ta trong modules/02-kien-truc.md va
// security/09-bao-mat.md. KHONG bien dich duoc trong phien lam viec nay vi
// moi truong khong co Windows Driver Kit (thieu header fltKernel.h,
// ntddk.h...) — xem features.md ARCH-06 va ops/README-known-limitations.md.
// Can Visual Studio + WDK (khop phien ban Windows SDK) de bien dich, va
// certificate ky driver qua Microsoft (attestation/WHQL) de nap tren may
// bat Secure Boot — dung nhu ops/08-trien-khai.md da mo ta.
#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

// Dai altitude danh cho antivirus (320000-329999) — xin tu Microsoft de
// tranh xung dot giua cac san pham bao mat cung hook filesystem
// (modules/02-kien-truc.md muc 2). Gia tri cu the phai duoc Microsoft cap,
// day chi la placeholder minh hoa.
#define MINIFILTER_ALTITUDE L"328000"
#define MINIFILTER_NAME L"SmePlanAvMiniFilter"

// Nhom phan mo rong duoc coi la "co kha nang thuc thi truc tiep" — CHI nhom
// nay bi chan DONG BO tai SmePlanAvMfPreCreateCallback (errors/10 ERR-RT-01: chan het
// moi loai file gay giat lag ngay tu lan dung thu dau).
extern const PCWSTR gExecutableExtensions[];
extern const ULONG gExecutableExtensionsCount;

// "tai lieu moi.txt" muc "Phat hien hanh vi ransomware...": danh sach thu
// muc bao ve (Documents/Pictures/Desktop...) duoc SERVICE PUSH xuong qua
// SmePlanAvMfMessageNotifyCallback tren CUNG communication port da co (khac huong
// voi FltSendMessage — day la kenh service-chu-dong-gui-xuong-driver, xem
// FilterConnectCommunicationPort + FilterSendMessage phia user-mode).
// Mang co dinh, kiem tra prefix don gian TRUOC khi quyet dinh co hoi
// service hay khong — bat buoc phai re, vi IRP_MJ_WRITE xay ra cho MOI
// file dang ghi tren he thong, khong chi file trong thu muc bao ve.
#define MINIFILTER_MAX_PROTECTED_FOLDERS 16
#define MINIFILTER_MAX_FOLDER_PATH_CHARS 260

typedef struct _MINIFILTER_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort; // ket noi tu service nen (mot client duy nhat duoc chap nhan)

    ULONG ProtectedFolderCount;
    WCHAR ProtectedFolders[MINIFILTER_MAX_PROTECTED_FOLDERS][MINIFILTER_MAX_FOLDER_PATH_CHARS];
    KSPIN_LOCK ProtectedFoldersLock;
    // [SUA LOI NGHIEM TRONG] Dem so lan danh sach thu muc bao ve duoc PUSH
    // cap nhat (tang trong SmePlanAvMfMessageNotifyCallback). MINIFILTER_STREAM_CONTEXT
    // luu lai gia tri nay tai thoi diem cache — neu gia tri hien tai khac
    // gia tri da cache, ket qua SmePlanAvMfIsUnderProtectedFolder cached KHONG con
    // dang tin (danh sach da doi SAU khi file mo) va phai tinh lai — xem
    // SmePlanAvMfQueryProtectedFolderWrite. Khong dung nay truoc day: mot file mo
    // TRUOC khi admin them thu muc cua no vao danh sach bao ve se giu cache
    // "khong bao ve" SUOT VONG DOI handle, khong bao gio duoc kiem tra lai
    // cho toi khi dong/mo lai file — lam mat tac dung bao ve ngay lap tuc
    // ma tinh nang push-cap-nhat du dinh mang lai.
    volatile LONG ProtectedFoldersGeneration;
} MINIFILTER_CONTEXT, *PMINIFILTER_CONTEXT;

// [SUA LOI HIEU NANG — can xac nhan khi build that voi WDK] Context gan
// vao MOI stream (file object) khi mo (SmePlanAvMfPostCreateCallback), luu san ket
// qua SmePlanAvMfIsUnderProtectedFolder tinh MOT LAN duy nhat tai thoi diem MO file.
// SmePlanAvMfQueryProtectedFolderWrite (goi cho MOI IRP_MJ_WRITE/SET_INFORMATION —
// hot path tren toan he thong) uu tien doc cache nay THAY VI goi lai
// FltGetFileNameInformation(FLT_FILE_NAME_NORMALIZED) — von phai resolve
// reparse point/ten day du — TREN MOI THAO TAC GHI. Mot file thuong duoc
// ghi NHIEU LAN tren cung mot handle dang mo, nen chi phi chuyen tu O(so
// lan ghi) xuong O(so lan mo file), giam dang ke tren hot path he thong.
// Fallback (tu tinh lai nhu truoc) neu context chua duoc gan (vi du filter
// attach sau khi file da mo tu truoc, hoac FltAllocateContext/
// FltSetStreamContext o SmePlanAvMfPostCreateCallback that bai vi thieu bo nho) —
// KHONG lam yeu di kiem tra bao mat, chi anh huong toc do trong truong hop
// hiem gap do.
typedef struct _MINIFILTER_STREAM_CONTEXT {
    BOOLEAN SmePlanAvMfIsUnderProtectedFolder;
    // [SUA LOI NGHIEM TRONG] Ban chup ProtectedFoldersGeneration (xem
    // MINIFILTER_CONTEXT) tai thoi diem tinh SmePlanAvMfIsUnderProtectedFolder o tren —
    // dung de phat hien cache STALE khi danh sach thu muc bao ve duoc cap
    // nhat SAU khi file nay da mo (xem SmePlanAvMfQueryProtectedFolderWrite).
    LONG CachedProtectedFoldersGeneration;
} MINIFILTER_STREAM_CONTEXT, *PMINIFILTER_STREAM_CONTEXT;

#define MINIFILTER_STREAM_CONTEXT_TAG 'CsAS' // "SAsC" (SmePlanAv Stream Context)

// [SUA LOI NGHIEM TRONG] Tag cho bo nho non-paged dung de CHUP ban sao
// kernel cua thong diep push tu user-mode truoc khi validate/copy — xem
// SmePlanAvMfMessageNotifyCallback trong minifilter.c.
#define MINIFILTER_POOL_TAG 'gsAS' // "SAsg" (SmePlanAv message)

extern CONST FLT_CONTEXT_REGISTRATION ContextRegistration[];

// --- Thong diep giua driver <-> service qua FltCreateCommunicationPort ---
// Khop luong xu ly trong flows/11-luong-xu-ly.md muc "Luong thuc thi ung
// dung moi": driver gui duong dan + PID xuong service, service tra ve
// quyet dinh allow/block. MsgType_ProtectedWriteQuery them cho
// EXT-RW-01 ("tai lieu moi.txt" muc "Phat hien hanh vi ransomware dang
// ma hoa hang loat file"): hoi TRUOC khi cho phep ghi/doi ten file trong
// thu muc bao ve, cho service co co hoi snapshot ban sach TRUOC khi ghi
// xay ra (khac voi FileSystemWatcher user-mode dang dung lam fallback
// trong RansomwareGuardService.cs, von chi quan sat DUOC SAU khi ghi da
// xong — day chinh la loi ich cot loi cua hook kernel PRE-write ma tai
// lieu nhan manh).
typedef enum _MSG_TYPE {
    MsgType_ProcessCreateQuery = 1,
    MsgType_FileOpenQuery = 2,
    MsgType_ProtectedWriteQuery = 3,
} MSG_TYPE;

// Thong diep service PUSH xuong (khong phai query/reply) — nhan qua
// SmePlanAvMfMessageNotifyCallback, KHONG qua FltSendMessage (huong nguoc lai).
typedef enum _PUSH_MSG_TYPE {
    PushMsgType_SetProtectedFolders = 1,
} PUSH_MSG_TYPE;

typedef struct _PUSH_SET_PROTECTED_FOLDERS_MSG {
    PUSH_MSG_TYPE Type;
    ULONG FolderCount;
    WCHAR Folders[MINIFILTER_MAX_PROTECTED_FOLDERS][MINIFILTER_MAX_FOLDER_PATH_CHARS];
} PUSH_SET_PROTECTED_FOLDERS_MSG, *PPUSH_SET_PROTECTED_FOLDERS_MSG;

typedef struct _DRIVER_TO_SERVICE_MSG {
    MSG_TYPE Type;
    HANDLE ProcessId;
    // [SUA LOI NGHIEM TRONG] Truoc day hardcode lai "260" thay vi dung
    // MINIFILTER_MAX_FOLDER_PATH_CHARS da dinh nghia ngay tren (dong 38,
    // CUNG file nay) — hai hang so dung de chua duong dan Windows nhung
    // duoc go tay doc lap, de lech nhau neu chi sua mot noi. Dung chung
    // mot hang so trong pham vi file nay (finding: hang so 260 lap lai o
    // nhieu noi — xem them SMEPLANAV_FW_MAX_PATH_CHARS trong
    // wfp_callout.h, mot driver .sys KHAC nen KHONG the dung chung header
    // voi file nay, chi ghi chu de nguoi sau biet co ban tuong duong).
    WCHAR FilePath[MINIFILTER_MAX_FOLDER_PATH_CHARS];
} DRIVER_TO_SERVICE_MSG, *PDRIVER_TO_SERVICE_MSG;

typedef struct _SERVICE_TO_DRIVER_REPLY {
    BOOLEAN Allow;
} SERVICE_TO_DRIVER_REPLY, *PSERVICE_TO_DRIVER_REPLY;

// --- Khai bao ham chinh ---
DRIVER_INITIALIZE DriverEntry;
NTSTATUS SmePlanAvMfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS SmePlanAvMfPreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

// Gan MINIFILTER_STREAM_CONTEXT vao stream vua mo thanh cong — xem ghi chu
// o MINIFILTER_STREAM_CONTEXT phia tren.
FLT_POSTOP_CALLBACK_STATUS SmePlanAvMfPostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

VOID SmePlanAvMfProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

NTSTATUS SmePlanAvMfPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie);

VOID SmePlanAvMfPortDisconnectNotify(_In_opt_ PVOID ConnectionCookie);

NTSTATUS SmePlanAvMfMessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength);

BOOLEAN SmePlanAvMfIsExecutableCandidate(_In_ PCUNICODE_STRING FileName);
NTSTATUS SmePlanAvMfQueryServiceDecision(
    _In_ PDRIVER_TO_SERVICE_MSG Query,
    _Out_ PSERVICE_TO_DRIVER_REPLY Reply);

// EXT-RW-01: tra ve TRUE neu FileName nam trong mot thu muc bao ve
// (so sanh prefix don gian, khong phan biet hoa/thuong). OutGeneration
// (co the NULL neu khong can): nhan gia tri ProtectedFoldersGeneration tai
// thoi diem quet (doc cung mot lan khoa spinlock voi danh sach thu muc),
// dung de phat hien cache stale sau nay — xem MINIFILTER_STREAM_CONTEXT.
BOOLEAN SmePlanAvMfIsUnderProtectedFolder(_In_ PCUNICODE_STRING FileName, _Out_opt_ PLONG OutGeneration);

FLT_PREOP_CALLBACK_STATUS SmePlanAvMfPreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS SmePlanAvMfPreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

// [SUA LOI NGHIEM TRONG — HONG MAY] Xem minifilter.c: whitelist tien trinh
// he thong toi quan trong, can thiet de driver BOOT_START nay khong khoa
// chet may khi service user-mode chua ket noi hoac khong tra loi kip.
BOOLEAN SmePlanAvMfContainsSubstring(_In_ PCUNICODE_STRING Haystack, _In_ PCUNICODE_STRING Needle);

BOOLEAN SmePlanAvMfIsCriticalSystemProcess(_In_ PCUNICODE_STRING ImageFileName);
