using System.Security.AccessControl;
using System.Security.Principal;

namespace Antivirus.Service.Data;

// SEC-06: "ACL: chi SYSTEM/Administrator ghi duoc thu muc du lieu (rule DB),
// chi SYSTEM doc/ghi quarantine" (security/09-bao-mat.md muc 2, 3).
// Neu tien trinh thuong ghi duoc truc tiep vao rule DB, toan bo co che phan
// quyen sup do vi malware chi can tu them rule "Cho phep luon" cho chinh no.
public static class AclProtection
{
    // [SUA LOI] Ban truoc CHI cap FullControl cho SID SYSTEM/Administrators
    // (nhom), khong bao gio cap cho danh tinh THUC SU dang chay tien trinh.
    // Tren may san xuat that, service chay duoi LocalSystem nen khong sao —
    // nhung trong moi truong dev/test KHONG elevate (`dotnet run` thong
    // thuong), token cua tien trinh KHONG bat "Administrators" trong danh
    // sach nhom du tai khoan dang nhap co quyen admin (UAC loc bo group do
    // o token mac dinh) — ket qua la CHINH TIEN TRINH VUA TAO RA THU MUC bi
    // tu khoa ra khoi du lieu cua no ngay sau khi goi ham nay (moi lan doc/
    // ghi tiep theo trong CUNG mot lan chay se nem UnauthorizedAccessException).
    // Sua: LUON cap them cho danh tinh dang chay tien trinh hien tai
    // (WindowsIdentity.GetCurrent().User), ben canh SYSTEM/Administrators —
    // trong production danh tinh do la SYSTEM (da co san), trong dev/test
    // do la user hien tai, dam bao tien trinh luon truy cap duoc file/thu
    // muc chinh no vua tao ra du chay elevate hay khong.
    public static void ProtectDataDirectory(string path)
    {
        var dirInfo = new DirectoryInfo(path);
        var security = dirInfo.GetAccessControl();
        security.SetAccessRuleProtection(true, false); // ngat ke thua, khong giu rule cu

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var currentUser = WindowsIdentity.GetCurrent().User;

        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            admins, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        if (currentUser is not null && currentUser != system)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }

        dirInfo.SetAccessControl(security);
    }

    public static void ProtectQuarantineDirectory(string path)
    {
        var dirInfo = new DirectoryInfo(path);
        var security = dirInfo.GetAccessControl();
        security.SetAccessRuleProtection(true, false);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var currentUser = WindowsIdentity.GetCurrent().User;
        // Chi SYSTEM (+ danh tinh dang chay tien trinh hien tai — xem ghi
        // chu tren ProtectDataDirectory) doc/ghi quarantine, KHONG cap cho
        // Administrators noi chung (khac voi thu muc rule DB) — dung theo
        // bang phan quyen security/09 muc 2: "SYSTEM (qua ACL thu muc
        // quarantine) - Duy nhat co quyen doc/ghi khu vuc quarantine".
        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        if (currentUser is not null && currentUser != system)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }

        dirInfo.SetAccessControl(security);
    }
}
