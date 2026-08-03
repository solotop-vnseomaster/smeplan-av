// ob_callbacks.h
// [HAN CHE MOI TRUONG] File nay la MA NGUON THAM CHIEU cho driver
// ObRegisterCallbacks mo ta trong "tai lieu moi.txt" muc "Bao ve tien
// trinh khoi process hollowing" (EXT-EXP-02). KHONG bien dich duoc trong
// phien lam viec nay — cung ly do da ghi trong app/drivers/README.md
// (khong co WDK). Driver rieng, KHONG dung chung binary voi minifilter
// hay wfp_callout (ba co che kernel doc lap: Filter Manager, WFP, va
// Object Manager callbacks).
#pragma once

#include <ntddk.h>
#include <wdmsec.h>

#define SMEPLANAV_OB_MAX_TRACKED_PROCESSES 8192

typedef struct _SMEPLANAV_OB_PROCESS_INFO {
    BOOLEAN InUse;
    HANDLE ProcessId;
    HANDLE ParentProcessId; // dien tu PS_CREATE_NOTIFY_INFO->ParentProcessId luc tao
    BOOLEAN Whitelisted;    // PUSH tu service sau khi da qua whitelist chu ky so (dung chung)
} SMEPLANAV_OB_PROCESS_INFO, *PSMEPLANAV_OB_PROCESS_INFO;

typedef struct _SMEPLANAV_OB_CONTEXT {
    PVOID RegistrationHandle; // tra ve tu ObRegisterCallbacks
    PDEVICE_OBJECT DeviceObject;

    KSPIN_LOCK TableLock;
    SMEPLANAV_OB_PROCESS_INFO Table[SMEPLANAV_OB_MAX_TRACKED_PROCESSES];

    LIST_ENTRY PendingNotifyIrps; // "chi ghi nhan va publish vao event bus" — xem ob_callbacks.c
    KSPIN_LOCK PendingNotifyLock;
} SMEPLANAV_OB_CONTEXT, *PSMEPLANAV_OB_CONTEXT;

// --- IOCTL giua service (user-mode) va driver nay ---
#define IOCTL_SMEPLANAV_OB_PUSH_WHITELIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SMEPLANAV_OB_READ_SUSPICIOUS_ACCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef struct _SMEPLANAV_OB_PUSH_WHITELIST_REQUEST {
    HANDLE ProcessId;
    BOOLEAN Whitelisted;
} SMEPLANAV_OB_PUSH_WHITELIST_REQUEST, *PSMEPLANAV_OB_PUSH_WHITELIST_REQUEST;

// entity_key tuong thich EventBus.CorrelationEvent ben user-mode
// (Extensions/EventBus.cs) — dung cap (PID, thoi diem tao) theo dung
// nguyen tac "PID co the bi tai su dung" da neu trong tai lieu moi.txt.
typedef struct _SMEPLANAV_OB_SUSPICIOUS_ACCESS_EVENT {
    HANDLE RequesterProcessId;
    HANDLE TargetProcessId;
    LARGE_INTEGER TargetCreateTime;
    ULONG DesiredAccessMask;
} SMEPLANAV_OB_SUSPICIOUS_ACCESS_EVENT, *PSMEPLANAV_OB_SUSPICIOUS_ACCESS_EVENT;

// --- Khai bao ham chinh ---
DRIVER_INITIALIZE DriverEntry;
VOID SmePlanAvObDriverUnload(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS SmePlanAvObCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS SmePlanAvObDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

VOID SmePlanAvObProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

OB_PREOP_CALLBACK_STATUS SmePlanAvObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info);

BOOLEAN SmePlanAvObIsUnrelatedProcess(_In_ HANDLE RequesterPid, _In_ HANDLE TargetPid);
BOOLEAN SmePlanAvObIsWhitelisted(_In_ HANDLE Pid);
VOID SmePlanAvObLogSuspiciousAccess(_In_ HANDLE RequesterPid, _In_ HANDLE TargetPid, _In_ ULONG DesiredAccess);
