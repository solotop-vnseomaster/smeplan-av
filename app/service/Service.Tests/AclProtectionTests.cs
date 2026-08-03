using System.Security.AccessControl;
using System.Security.Principal;
using Antivirus.Service.Data;
using Xunit;

namespace Antivirus.Service.Tests;

// [SUA LOI NGHIEM TRONG - AclProtection.cs] Ban truoc CHI cap FullControl
// cho SID SYSTEM/Administrators (nhom), khong bao gio cap cho danh tinh
// THUC SU dang chay tien trinh — tren may dev/test KHONG elevate, token
// tien trinh KHONG bat "Administrators" trong danh sach nhom (UAC loc bo),
// nen CHINH TIEN TRINH VUA TAO RA THU MUC bi tu khoa ra khoi du lieu cua
// no ngay sau khi goi ham nay. Class nay truoc day khong co test truc
// tiep nao — QuarantineManager.cs con ghi ro "test dung applyAcl=false vi
// se tu khoa chinh minh" (comment cu, viet TRUOC khi AclProtection duoc
// sua). Test o day xac nhan TRUC TIEP: sau khi goi ProtectDataDirectory/
// ProtectQuarantineDirectory, tien trinh hien tai (khong elevate) VAN con
// ghi duoc vao thu muc — tuc la bug tu-khoa-chinh-minh KHONG con tai dien.
public class AclProtectionTests : IDisposable
{
    private readonly string _tempDir;

    public AclProtectionTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("avtest_acl_").FullName;
    }

    [Fact]
    public void ProtectDataDirectory_CurrentProcessCanStillWriteAfterward()
    {
        AclProtection.ProtectDataDirectory(_tempDir);

        // Day la kiem tra QUAN TRONG NHAT: neu bug "tu khoa chinh minh" tai
        // dien, dong nay se nem UnauthorizedAccessException.
        var testFile = Path.Combine(_tempDir, "probe.txt");
        File.WriteAllText(testFile, "ok");
        Assert.Equal("ok", File.ReadAllText(testFile));
    }

    [Fact]
    public void ProtectDataDirectory_GrantsCurrentUserFullControl()
    {
        AclProtection.ProtectDataDirectory(_tempDir);

        var security = new DirectoryInfo(_tempDir).GetAccessControl();
        var currentUser = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(currentUser);

        bool hasFullControl = HasFullControlAllowRule(security, currentUser!);
        Assert.True(hasFullControl, "Danh tinh dang chay tien trinh hien tai phai co FullControl sau ProtectDataDirectory");
    }

    [Fact]
    public void ProtectDataDirectory_GrantsSystemAndAdministrators()
    {
        AclProtection.ProtectDataDirectory(_tempDir);

        var security = new DirectoryInfo(_tempDir).GetAccessControl();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        Assert.True(HasFullControlAllowRule(security, system), "SYSTEM phai co FullControl");
        Assert.True(HasFullControlAllowRule(security, admins), "Administrators phai co FullControl");
    }

    [Fact]
    public void ProtectDataDirectory_DisablesInheritance()
    {
        AclProtection.ProtectDataDirectory(_tempDir);

        var security = new DirectoryInfo(_tempDir).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected,
            "Phai ngat ke thua ACL tu thu muc cha (SetAccessRuleProtection(true, false)) — neu khong, rule long leo hon co the ri qua ke thua");
    }

    [Fact]
    public void ProtectQuarantineDirectory_CurrentProcessCanStillWriteAfterward()
    {
        AclProtection.ProtectQuarantineDirectory(_tempDir);

        var testFile = Path.Combine(_tempDir, "probe.txt");
        File.WriteAllText(testFile, "ok");
        Assert.Equal("ok", File.ReadAllText(testFile));
    }

    // Khac voi ProtectDataDirectory: quarantine CHI danh cho SYSTEM + danh
    // tinh hien tai, KHONG cap cho Administrators noi chung (business-rules
    // security/09 muc 2: "SYSTEM - Duy nhat co quyen doc/ghi khu vuc quarantine").
    [Fact]
    public void ProtectQuarantineDirectory_DoesNotGrantAdministratorsGroup()
    {
        AclProtection.ProtectQuarantineDirectory(_tempDir);

        var security = new DirectoryInfo(_tempDir).GetAccessControl();
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var currentUser = WindowsIdentity.GetCurrent().User;

        // Neu danh tinh hien tai TINH CO la mot phan cua Administrators SID
        // (vi du chinh no la group SID, khong xay ra trong test binh
        // thuong), bo qua kiem tra nay de tranh false positive.
        if (currentUser == admins) return;

        Assert.False(HasFullControlAllowRule(security, admins),
            "Administrators (nhom) khong duoc cap quyen rieng tren thu muc quarantine");
    }

    private static bool HasFullControlAllowRule(DirectorySecurity security, SecurityIdentifier identity)
    {
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IdentityReference.Equals(identity) &&
                rule.AccessControlType == AccessControlType.Allow &&
                (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl)
            {
                return true;
            }
        }
        return false;
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }
}
