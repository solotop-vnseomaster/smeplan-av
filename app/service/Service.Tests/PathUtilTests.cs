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
}
