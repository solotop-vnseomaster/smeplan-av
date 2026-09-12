using Antivirus.Service.Common;
using Xunit;

namespace Antivirus.Service.Tests;

// [SUA LOI LON - PathUtil.cs] Ham nay la CAN CU cho HAI quyet dinh bao mat
// khac nhau: ProcessTrustEngine (mot trong 3 tieu chi trusted-by-default —
// SEC-01) va QuarantineManager (kiem tra thu muc he thong duoc WRP bao ve
// truoc khi tu dong quarantine hay cho xac nhan thu cong). Truoc day dung
// StartsWith(root) tran, KHONG kiem tra ky tu ngay sau prefix co phai dau
// phan cach thu muc hay khong — "C:\Program Files" (khong dau \ cuoi) se
// khop nham voi "C:\Program FilesXYZ\evil.exe". Day chinh la loai bug ma
// review flag rieng cho driver minifilter.c (da vay o noi khac) nhung
// CHUA TUNG co test truc tiep cho ban C# nay du no la ham dung chung cho
// 2 quyet dinh bao mat — neu no hong, ca 2 quyet dinh hong theo, im lang.
public class PathUtilTests
{
    [Fact]
    public void ExactMatch_ReturnsTrue()
    {
        Assert.True(PathUtil.IsPathUnderDirectory(@"C:\Documents", @"C:\Documents"));
    }

    [Fact]
    public void TrueSubdirectory_ReturnsTrue()
    {
        Assert.True(PathUtil.IsPathUnderDirectory(@"C:\Documents\file.txt", @"C:\Documents"));
    }

    [Fact]
    public void DeeplyNestedSubdirectory_ReturnsTrue()
    {
        Assert.True(PathUtil.IsPathUnderDirectory(@"C:\Documents\Sub\Deep\file.txt", @"C:\Documents"));
    }

    // [KIEM THU HOI QUY] Kich ban chinh xac cua bug da sua: thu muc CO TEN
    // BAT DAU GIONG root nhung KHONG PHAI la con thuc su cua no.
    [Fact]
    public void SiblingDirectoryWithSharedPrefix_ReturnsFalse()
    {
        Assert.False(PathUtil.IsPathUnderDirectory(@"C:\Documents2\evil.exe", @"C:\Documents"));
        Assert.False(PathUtil.IsPathUnderDirectory(@"C:\DocumentsBackup\file.txt", @"C:\Documents"));
        Assert.False(PathUtil.IsPathUnderDirectory(@"C:\Program FilesXYZ\evil.exe", @"C:\Program Files"));
    }

    [Fact]
    public void UnrelatedPath_ReturnsFalse()
    {
        Assert.False(PathUtil.IsPathUnderDirectory(@"C:\Windows\System32\cmd.exe", @"C:\Documents"));
    }

    [Fact]
    public void DifferentDrive_ReturnsFalse()
    {
        Assert.False(PathUtil.IsPathUnderDirectory(@"D:\Documents\file.txt", @"C:\Documents"));
    }

    [Fact]
    public void CaseInsensitive_ReturnsTrue()
    {
        Assert.True(PathUtil.IsPathUnderDirectory(@"c:\documents\FILE.TXT", @"C:\Documents"));
    }

    // Root truyen vao co dau '\' cuoi hay khong khong duoc anh huong ket qua.
    [Fact]
    public void RootWithTrailingSeparator_NormalizesCorrectly()
    {
        Assert.True(PathUtil.IsPathUnderDirectory(@"C:\Documents\Sub", @"C:\Documents\"));
        Assert.True(PathUtil.IsPathUnderDirectory(@"C:\Documents", @"C:\Documents\"));
    }

    [Fact]
    public void ParentPathIsNotUnderChildPath()
    {
        Assert.False(PathUtil.IsPathUnderDirectory(@"C:\Documents", @"C:\Documents\Sub"));
    }

    // ---------- IsLocalDrivePath (SEC-01: chan NTLM-relay qua UNC) ----------
    // [test-coverage] Day CHINH la ham chong NTLM-relay flag o Program.cs
    // /api/scan/file, /api/scan/full/start, /api/trust/evaluate — truoc day
    // KHONG co test truc tiep nao, chi co test cho IsPathUnderDirectory.

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsLocalDrivePath_NullOrWhitespace_ReturnsFalse(string? path)
    {
        Assert.False(PathUtil.IsLocalDrivePath(path));
    }

    [Theory]
    [InlineData(@"\\attacker-host\share\evil.exe")]
    [InlineData("//attacker-host/share/evil.exe")]
    [InlineData(@"\\127.0.0.1\C$\evil.exe")]
    public void IsLocalDrivePath_UncPath_ReturnsFalse(string path)
    {
        Assert.False(PathUtil.IsLocalDrivePath(path));
    }

    [Fact]
    public void IsLocalDrivePath_RelativePath_ReturnsFalse()
    {
        Assert.False(PathUtil.IsLocalDrivePath(@"relative\path\file.exe"));
    }

    [Fact]
    public void IsLocalDrivePath_ValidExistingLocalPath_ReturnsTrue()
    {
        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!;
        Assert.True(PathUtil.IsLocalDrivePath(systemDrive));
    }

    // [KIEM THU HOI QUY] Duong dan cuc bo HOP LE nhung file/thu muc CHUA
    // TON TAI van phai duoc chap nhan — day chinh la truong hop /api/scan/file
    // can (kiem tra dinh dang TRUOC khi cham vao he thong file, ke ca khi
    // file "khong ton tai"), khac voi truong hop UNC luon bi tu choi bat ke
    // ton tai hay khong.
    [Fact]
    public void IsLocalDrivePath_ValidButNonExistentLocalPath_ReturnsTrue()
    {
        var path = Path.Combine(Path.GetTempPath(), "avtest_khong_ton_tai_" + Guid.NewGuid().ToString("N"), "x.exe");
        Assert.True(PathUtil.IsLocalDrivePath(path));
    }

    // ---------- Reparse point (junction/symlink) resolution ----------
    // [SUA LOI NGHIEM TRONG][test-coverage] Junction/symlink CUC BO (khong
    // can quyen admin de tao bang "mklink /J") co the khien mot duong dan
    // nhin-lexical-hop-le thuc su tro ra noi khac. Test bang junction that
    // tren dia (khong mock) de xac nhan ResolveRealPath/IsPathUnderDirectory/
    // IsLocalDrivePath THAT SU theo duoc reparse point, khong chi kiem tra
    // chuoi ky tu.

    private static bool TryCreateJunction(string linkPath, string targetPath)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c mklink /J \"{linkPath}\" \"{targetPath}\"")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            proc.WaitForExit(10_000);
            return proc.ExitCode == 0 && Directory.Exists(linkPath);
        }
        catch
        {
            return false;
        }
    }

    [Fact]
    public void ResolveRealPath_LocalJunction_FollowsToRealTarget()
    {
        var tempDir = Directory.CreateTempSubdirectory("avtest_pathutil_junc_").FullName;
        var targetDir = Path.Combine(tempDir, "real-target");
        var linkDir = Path.Combine(tempDir, "junction-link");
        Directory.CreateDirectory(targetDir);
        File.WriteAllText(Path.Combine(targetDir, "file.txt"), "noi dung that");

        if (!TryCreateJunction(linkDir, targetDir))
        {
            Assert.Fail(
                    "Khong tao duoc junction de dung thu nghiem. TRUOC DAY nhanh nay "
                    + "\"return;\" — test bao mat khi do KET THUC XANH voi 0 assertion, "
                    + "tuc la mot bao ve da bi go van khong bi phat hien. Neu moi truong "
                    + "that su khong ho tro junction thi phai lam cho dieu do HIEN RA, "
                    + "khong duoc gia vo la da kiem tra.");
        }

        try
        {
            var real = PathUtil.ResolveRealPath(Path.Combine(linkDir, "file.txt"));

            var expectedReal = Path.GetFullPath(Path.Combine(targetDir, "file.txt"));
            Assert.Equal(expectedReal, real, ignoreCase: true);
        }
        finally
        {
            try { Directory.Delete(linkDir); } catch { }
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // [KIEM THU HOI QUY - chinh xac kich ban bug da sua] Mot junction dat
    // BEN TRONG mot thu muc "tin tuong" nhung tro RA NGOAI thu muc do phai
    // bi TU CHOI boi IsPathUnderDirectory — day la co che ProcessTrustEngine
    // dung de quyet dinh "trusted-by-default" va QuarantineManager dung de
    // quyet dinh auto-quarantine vs cho xac nhan thu cong.
    [Fact]
    public void IsPathUnderDirectory_JunctionEscapingTrustedRoot_ReturnsFalse()
    {
        var tempDir = Directory.CreateTempSubdirectory("avtest_pathutil_escape_").FullName;
        var trustedRoot = Path.Combine(tempDir, "trusted-dir");
        var untrustedOutside = Path.Combine(tempDir, "untrusted-outside");
        var junctionInsideTrusted = Path.Combine(trustedRoot, "innocent-looking-subfolder");
        Directory.CreateDirectory(trustedRoot);
        Directory.CreateDirectory(untrustedOutside);
        File.WriteAllText(Path.Combine(untrustedOutside, "evil.exe"), "khong phai binary that, chi la test");

        if (!TryCreateJunction(junctionInsideTrusted, untrustedOutside))
        {
            Assert.Fail(
                    "Khong tao duoc junction de dung thu nghiem. TRUOC DAY nhanh nay "
                    + "\"return;\" — test bao mat khi do KET THUC XANH voi 0 assertion, "
                    + "tuc la mot bao ve da bi go van khong bi phat hien. Neu moi truong "
                    + "that su khong ho tro junction thi phai lam cho dieu do HIEN RA, "
                    + "khong duoc gia vo la da kiem tra.");
        }

        try
        {
            var evilPathViaJunction = Path.Combine(junctionInsideTrusted, "evil.exe");

            // Truoc khi sua: se la TRUE (lexical thuan tuy nhin "duoi"
            // trustedRoot). Sau khi sua: PHAI la FALSE vi file that su nam
            // ngoai trustedRoot.
            Assert.False(PathUtil.IsPathUnderDirectory(evilPathViaJunction, trustedRoot));

            // Doi chieu: file THAT SU nam ngoai (truy cap truc tiep, khong
            // qua junction) van dung nhu ky vong la KHONG nam duoi trustedRoot.
            Assert.False(PathUtil.IsPathUnderDirectory(Path.Combine(untrustedOutside, "evil.exe"), trustedRoot));
        }
        finally
        {
            try { Directory.Delete(junctionInsideTrusted); } catch { }
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // [test-coverage][SUA LOI NGHIEM TRONG] Nhanh vuot MaxReparseHops (32)
    // truoc day CHUA TUNG co test: ResolveRealPath se "break" khoi vong lap
    // va tra ve duong dan MOI resolve toi hop thu 32 (cac thanh phan con lai
    // BI BO HAN, ke ca neu hop thu 33+ thuc su tro ra UNC) — nhin van co ve
    // la mot duong dan cuc bo hop le, khien IsLocalDrivePath co the bi qua
    // mat boi mot chuoi junction du dai (khong can quyen admin de tao). Test
    // nay dung mot CHUOI JUNCTION LONG NHAU (34 hop, vuot nguong 32) de xac
    // nhan hanh vi SAU KHI SUA la fail-closed (tu choi), khong phai tra ve
    // duong dan cat cut trong co ve hop le.
    [Fact]
    public void IsLocalDrivePath_ExceedsMaxReparseHops_FailsClosed()
    {
        var tempDir = Directory.CreateTempSubdirectory("avtest_pathutil_hoplimit_").FullName;
        const int hops = 34; // > MaxReparseHops (32) trong PathUtil.cs
        var linkPaths = new List<string>();
        string cur = tempDir;
        string lastReal = tempDir;

        try
        {
            for (int i = 1; i <= hops; i++)
            {
                var realDir = Path.Combine(tempDir, $"real{i}");
                Directory.CreateDirectory(realDir);
                var linkPath = Path.Combine(cur, $"j{i}");

                if (!TryCreateJunction(linkPath, realDir))
                {
                    Assert.Fail(
                    "Khong tao duoc junction de dung thu nghiem. TRUOC DAY nhanh nay "
                    + "\"return;\" — test bao mat khi do KET THUC XANH voi 0 assertion, "
                    + "tuc la mot bao ve da bi go van khong bi phat hien. Neu moi truong "
                    + "that su khong ho tro junction thi phai lam cho dieu do HIEN RA, "
                    + "khong duoc gia vo la da kiem tra.");
                }

                linkPaths.Add(linkPath);
                cur = linkPath;
                lastReal = realDir;
            }

            File.WriteAllText(Path.Combine(lastReal, "file.txt"), "noi dung demo, khong doc hai");
            var pathViaChain = Path.Combine(cur, "file.txt");

            // Truoc khi sua: co the tra ve TRUE (chuoi bi cat cut truoc khi
            // cham toi hop vuot nguong, nhin van "hop le"). Sau khi sua: PHAI
            // la FALSE — vuot nguong resolve la fail-closed, khong con tin
            // tuong duong dan nay la cuc bo hop le nua.
            Assert.False(PathUtil.IsLocalDrivePath(pathViaChain));
        }
        finally
        {
            for (int i = linkPaths.Count - 1; i >= 0; i--)
            {
                try { Directory.Delete(linkPaths[i]); } catch { }
            }
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // [SUA TEST KHONG BAO GIO CHAY] TRUOC DAY o day co
    // IsLocalDrivePath_JunctionToUncTarget_ReturnsFalse dung `mklink /J` de
    // tao junction tro toi \\127.0.0.1\C$\Windows, va `return;` khi that
    // bai. Nhung JUNCTION VE NGUYEN TAC khong tro ra UNC duoc (no chi nhan
    // duong dan volume cuc bo) — nen lenh do LUON that bai, nhanh `return`
    // LUON chay, va test nay chua tung kiem tra dieu gi trong suot doi no.
    // No chi ton tai de bao cao mot mau xanh.
    //
    // Thay bang hai test that:

    // (a) Luon chay: duong dan UNC tho phai bi tu choi. Day la lop phong
    //     thu dau tien chong NTLM-relay va no kiem tra duoc vo dieu kien.
    [Theory]
    [InlineData(@"\\127.0.0.1\C$\Windows\System32")]
    [InlineData(@"\\attacker\share\payload.exe")]
    [InlineData("//127.0.0.1/C$/Windows")]
    public void IsLocalDrivePath_RawUncPath_ReturnsFalse(string uncPath)
    {
        Assert.False(PathUtil.IsLocalDrivePath(uncPath));
    }

    // (b) Kich ban day du (duong dan "nhin nhu cuc bo" NHUNG resolve ra UNC)
    //     bat buoc phai dung SYMLINK thu muc (`mklink /D`), va tao symlink
    //     doi hoi SeCreateSymbolicLinkPrivilege (chay elevate hoac bat
    //     Developer Mode). Danh dau Skip TUONG MINH: bao cao test se hien
    //     "Skipped" kem ly do — mot khoang trong PHAI NHIN THAY DUOC, khac
    //     han voi mot mau xanh gia nhu truoc.
    //
    //     De chay that: mo shell quyen Administrator, go thuoc tinh Skip roi
    //       dotnet test --filter FullyQualifiedName~SymlinkToUncTarget
    [Fact(Skip = "Can SeCreateSymbolicLinkPrivilege (chay elevate hoac bat Developer Mode). KHONG duoc doi thanh nhanh 'return' im lang — xem ghi chu tren.")]
    public void IsLocalDrivePath_SymlinkToUncTarget_ReturnsFalse()
    {
        var tempDir = Directory.CreateTempSubdirectory("avtest_pathutil_unc_link_").FullName;
        var linkDir = Path.Combine(tempDir, "symlink-to-unc");

        Directory.CreateSymbolicLink(linkDir, @"\\127.0.0.1\C$\Windows");
        try
        {
            var pathViaLink = Path.Combine(linkDir, "System32");
            Assert.False(PathUtil.IsLocalDrivePath(pathViaLink));
        }
        finally
        {
            try { Directory.Delete(linkDir); } catch { }
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }
}
