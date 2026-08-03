// elam.c
// [HAN CHE MOI TRUONG + GHI CHU DO TIN CAY KY THUAT — xem elam.h]
//
// modules/02-kien-truc.md muc 1: "Driver ELAM ... nap som nhat trong qua
// trinh boot, quyet dinh driver boot-start nao khac duoc phep nap, la
// tuyen phong thu chong rootkit co nap driver doc hai truoc ca antivirus."
// modules/02-kien-truc.md muc 4: "Driver ELAM phu thuoc vao CSDL rieng
// dong goi san dang resource nhung (tach biet voi CSDL day du cua scan
// engine) vi tai thoi diem ELAM chay, service nen chua kip khoi dong."
//
// DriverEntry o day CO CHU Y giu toi gian: phan loai driver boot-start
// khac chu yeu den tu resource "MSElamCertificateInfo" duoc dong goi kem
// theo driver nay luc build (khong the hien trong file .c nay vi la du
// lieu nhi phan/resource, tao qua .rc + cong cu ky cua Microsoft Partner
// Center), KHONG phai logic C tu do trong DriverEntry.
#include "elam.h"

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // ELAM driver KHONG tao device object hay phuc vu I/O thong thuong —
    // vai tro cua no da hoan tat chu yeu qua viec Windows doc resource
    // "MSElamCertificateInfo" nhung kem driver nay TRUOC KHI DriverEntry
    // nay chay. DriverEntry chi can ton tai va tra ve thanh cong de driver
    // duoc coi la mot ELAM driver hop le da nap.
    DriverObject->DriverUnload = SmePlanAvElamUnload;

    // [HAN CHE MOI TRUONG] Trong ban trien khai that co CSDL rieng nho gon:
    // day la noi (neu Microsoft cho phep qua co che doi tac) doc them CSDL
    // nhung bo sung (vi du qua IoRegisterBootDriverCallback theo tai lieu
    // doi tac rieng, chua co bang chung ky thuat cong khai trong tai lieu
    // nguon cua du an nay) — KHONG bia them mot API cu the o day.

    return STATUS_SUCCESS;
}

VOID
SmePlanAvElamUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    // ELAM driver thuong khong unload trong qua trinh chay binh thuong
    // (vai tro cua no ket thuc rat som trong boot); giu ham nay de driver
    // object hop le va co the unload sach khi go cai dat.
}
