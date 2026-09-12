using Antivirus.Service.FullScan;
using Antivirus.Service.Models;
using Xunit;

namespace Antivirus.Service.Tests;

// [TINH NANG THEO YEU CAU NGUOI DUNG] Cache full scan giua cac lan quet —
// DIEM AN TOAN BAT BUOC: phai gan voi signature_db_version, neu khong mot
// file tung "Clean" duoi CSDL cu se bi bo qua vinh vien du CSDL moi da
// nhan dien no la ma doc.
public class ScanCacheStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly ScanCacheStore _store;

    public ScanCacheStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_scancache_{Guid.NewGuid():N}.db");
        _store = new ScanCacheStore(_dbPath);
    }

    private static ScanResultDto CleanResult() => new()
    {
        Verdict = ScanVerdict.Clean, Stage = DetectionStage.None, Sha256Hex = "abc", Reason = "sach",
    };

    [Fact]
    public void UnchangedFile_SameSignatureVersion_ReturnsCachedResult()
    {
        _store.Upsert("C:\\a.txt", lastWriteTicks: 1000, fileSize: 50, signatureDbVersion: 5, CleanResult());

        var hit = _store.TryGetCached("C:\\a.txt", lastWriteTicks: 1000, fileSize: 50, currentSignatureDbVersion: 5, actualSha256Hex: "abc");

        Assert.NotNull(hit);
        Assert.Equal(ScanVerdict.Clean, hit!.Verdict);
    }

    [Fact]
    public void ChangedMtime_CacheMiss()
    {
        _store.Upsert("C:\\a.txt", lastWriteTicks: 1000, fileSize: 50, signatureDbVersion: 5, CleanResult());

        var hit = _store.TryGetCached("C:\\a.txt", lastWriteTicks: 2000, fileSize: 50, currentSignatureDbVersion: 5, actualSha256Hex: "abc");

        Assert.Null(hit);
    }

    [Fact]
    public void ChangedFileSize_CacheMiss()
    {
        _store.Upsert("C:\\a.txt", lastWriteTicks: 1000, fileSize: 50, signatureDbVersion: 5, CleanResult());

        var hit = _store.TryGetCached("C:\\a.txt", lastWriteTicks: 1000, fileSize: 99, currentSignatureDbVersion: 5, actualSha256Hex: "abc");

        Assert.Null(hit);
    }

    // [DIEM AN TOAN BAT BUOC] File khong doi nhung CSDL da cap nhat sang
    // version khac -> PHAI la cache miss, quet lai that (co the CSDL moi
    // da nhan dien duoc ma doc ma CSDL cu chua co).
    [Fact]
    public void SignatureDbVersionChanged_CacheMiss_EvenIfFileUnchanged()
    {
        _store.Upsert("C:\\a.txt", lastWriteTicks: 1000, fileSize: 50, signatureDbVersion: 5, CleanResult());

        var hit = _store.TryGetCached("C:\\a.txt", lastWriteTicks: 1000, fileSize: 50, currentSignatureDbVersion: 6, actualSha256Hex: "abc");

        Assert.Null(hit);
    }

    [Fact]
    public void ClearAll_RemovesEveryEntry()
    {
        _store.Upsert("C:\\a.txt", 1000, 50, 5, CleanResult());
        _store.Upsert("C:\\b.txt", 2000, 60, 5, CleanResult());
        Assert.Equal(2, _store.Count());

        _store.ClearAll();

        Assert.Equal(0, _store.Count());
        Assert.Null(_store.TryGetCached("C:\\a.txt", 1000, 50, 5, "abc"));
    }

    // [TEST HOI QUY — LO HONG D3] Khoa cache truoc day chi gom (path, mtime,
    // size, sigVersion). Ghi de file da cache Clean bang payload cung kich
    // thuoc roi SetLastWriteTimeUtc ve mtime cu (quyen nguoi dung thuong la
    // du) khien file do bi BO QUA VINH VIEN. Cache gio phai doi chieu hash
    // noi dung that.
    [Fact]
    public void SameMetadata_DifferentContentHash_MustBeCacheMiss()
    {
        _store.Upsert("C:\a.txt", lastWriteTicks: 1000, fileSize: 50, signatureDbVersion: 5, CleanResult());

        var hit = _store.TryGetCached("C:\a.txt", lastWriteTicks: 1000, fileSize: 50,
            currentSignatureDbVersion: 5, actualSha256Hex: "deadbeef");

        Assert.Null(hit);
    }

    // Khong tinh duoc hash (file bi khoa) cung KHONG duoc tin cache.
    [Fact]
    public void NullContentHash_MustBeCacheMiss()
    {
        _store.Upsert("C:\a.txt", lastWriteTicks: 1000, fileSize: 50, signatureDbVersion: 5, CleanResult());

        var hit = _store.TryGetCached("C:\a.txt", lastWriteTicks: 1000, fileSize: 50,
            currentSignatureDbVersion: 5, actualSha256Hex: null);

        Assert.Null(hit);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
