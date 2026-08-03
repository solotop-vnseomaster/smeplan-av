// elam.h
// [HAN CHE MOI TRUONG + GHI CHU DO TIN CAY KY THUAT]
// Day la ma nguon THAM CHIEU cho driver Early Launch Antimalware (ELAM) mo
// ta trong modules/01-tong-quan.md, modules/02-kien-truc.md va
// security/09-bao-mat.md. KHONG bien dich duoc trong phien nay (khong co
// WDK) — xem ops/README-known-limitations.md.
//
// Co che ELAM la mot be mat API rat hep, chi mo cho doi tac qua chuong
// trinh Microsoft (khong co tai lieu cong khai day du nhu minifilter).
// Phan CHAC CHAN dung theo cac sample chinh thuc cua Microsoft
// (Windows-driver-samples/general/elam): driver duoc khai bao boot-start,
// nap som nhat qua certificate co Enhanced Key Usage rieng cho ELAM, va
// mang theo MOT RESOURCE dac biet kieu "MSElamCertificateInfo" chua danh
// sach publisher/hash duoc phan loai san (day la co che phan loai CHINH,
// mang tinh khai bao, khong phai mot ham callback nhan tham so tu do).
// Bon gia tri phan loai Good/Bad/BadCritical/Unknown (dung theo dung mo ta
// trong modules/01-tong-quan.md) tuong ung voi
// WdBootDriverVerificationStatus trong sample chinh thuc.
//
// Neu can logic phan loai tuy bien sau hon phan resource khai bao (vi du
// tra CSDL rieng luc runtime), day la vung chua co bang chung ky thuat cu
// the trong tai lieu nguon cua du an nay — PHAI doi chieu truc tiep voi
// sample ELAM chinh thuc cua Microsoft
// (https://github.com/microsoft/Windows-driver-samples/tree/main/general/elam)
// truoc khi trien khai that, thay vi tin vao suy doan trong file nay.
#pragma once

#include <ntddk.h>
#include <wdmsec.h>

// Bon phan loai — dung ten nhu modules/01-tong-quan.md mo ta.
typedef enum _ELAM_CLASSIFICATION {
    ElamClassification_Good = 0,
    ElamClassification_Unknown = 1,
    ElamClassification_Bad = 2,
    ElamClassification_BadCritical = 3,
} ELAM_CLASSIFICATION;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SmePlanAvElamUnload;
