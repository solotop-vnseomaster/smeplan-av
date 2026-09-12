using Antivirus.Service.Archive;
using Antivirus.Service.Common;
using Antivirus.Service.Data;
using Xunit;

namespace Antivirus.Service.Tests;

// Test hoi quy cho cac lo hong nghiem trong duoc xac dinh trong review.txt.
// Moi test o day khoa lai MOT hanh vi bao mat cu the: neu ban va bi revert,
// test tuong ung PHAI do — do la muc dich ton tai cua chung.
public class ReviewRegressionTests
{
    // --- A7: IsZipArchive gate theo DUOI FILE truoc magic byte ---
    // Doi ten payload.zip -> payload.dat truoc day lam toan bo module quet
    // archive khong chay. Nhan dang phai theo NOI DUNG, khong theo ten.
    [Fact]
    public void IsZipArchive_DetectsZipRegardlessOfExtension()
    {
        var path = Path.Combine(Path.GetTempPath(), $"avtest_{Guid.NewGuid():N}.dat");
        try
        {
            // "PK\x03\x04" = local file header cua zip.
            File.WriteAllBytes(path, new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00 });
            Assert.True(ArchiveScanner.IsZipArchive(path),
                "File zip doi duoi thanh .dat PHAI van duoc nhan dien la archive");
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public void IsZipArchive_RejectsNonZipEvenWithZipExtension()
    {
        var path = Path.Combine(Path.GetTempPath(), $"avtest_{Guid.NewGuid():N}.zip");
        try
        {
            File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x90, 0x00 }); // "MZ" = PE, khong phai zip
            Assert.False(ArchiveScanner.IsZipArchive(path));
        }
        finally { try { File.Delete(path); } catch { } }
    }

    // --- C1/C2: duong dan khoi phuc phai bi tu choi khi co reparse point
    // hoac khi khong phai duong dan o dia cuc bo ---
    [Theory]
    [InlineData(@"\\attacker-host\share\payload.exe")]  // UNC: NTLM relay
    [InlineData("//attacker-host/share/payload.exe")]
    [InlineData(@"relative\path.exe")]                   // khong rooted
    [InlineData("")]
    [InlineData(null)]
    public void IsSafeRestoreTarget_RejectsNonLocalPaths(string? path)
    {
        Assert.False(PathUtil.IsSafeRestoreTarget(path));
    }

    [Fact]
    public void IsSafeRestoreTarget_AcceptsPlainLocalPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"avtest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var target = Path.Combine(dir, "restored.txt");
            Assert.True(PathUtil.IsSafeRestoreTarget(target),
                "Duong dan cuc bo binh thuong, khong reparse point, phai duoc chap nhan");
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // --- Nhom High #1: MOI thu muc du lieu phai nam trong danh sach duoc
    // ACL bao ve. Truoc day signatures/, yara-rules/, logs/, state/,
    // version-store/ khong bao gio duoc bao ve. ---
    [Fact]
    public void AllProtectedDirectories_CoversEverySensitiveDataDirectory()
    {
        var protectedDirs = DataPaths.AllProtectedDirectories;

        foreach (var required in new[]
        {
            DataPaths.DataDir,
            DataPaths.SignatureDir,
            DataPaths.YaraRulesDir,
            DataPaths.LogDir,
            DataPaths.StateDir,
            DataPaths.VersionStoreDir,
            DataPaths.UpdateDropDir,
            DataPaths.PhishingUpdateDropDir,
        })
        {
            Assert.Contains(required, protectedDirs);
        }
    }
}
