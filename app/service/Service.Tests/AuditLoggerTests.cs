using Antivirus.Service.Audit;
using Xunit;

namespace Antivirus.Service.Tests;

// [TINH NANG THEO YEU CAU NGUOI DUNG] "co co che nao xoa log tu dong va
// thu cong khong" — PruneToMaxLines/ClearAll dung chung cho ca hai co che.
public class AuditLoggerTests : IDisposable
{
    private readonly string _logDir;
    private readonly string _logPath;
    private readonly AuditLogger _logger;

    public AuditLoggerTests()
    {
        // [SUA LOI TEST] TRUOC DAY file nhat ky nam TRUC TIEP trong %TEMP%
        // dung chung, va Dispose chi xoa dung file do. Nhung ClearAll (va gio
        // ca PruneToMaxLines) tao them file luu tru audit-*.jsonl BEN CANH
        // no — nhung file do khong bao gio duoc don, tich luy qua moi lan
        // chay test, va lam moi khang dinh dang "co dung mot ban luu tru
        // duoc tao ra" tro nen khong the kiem duoc. Cho moi instance test
        // mot thu muc rieng va don sach ca thu muc khi xong.
        _logDir = Path.Combine(Path.GetTempPath(), $"avtest_audit_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_logDir);
        _logPath = Path.Combine(_logDir, "audit.jsonl");
        _logger = new AuditLogger(_logPath);
    }

    [Fact]
    public void PruneToMaxLines_FileUnderLimit_DoesNothing()
    {
        for (int i = 0; i < 10; i++) _logger.Log("system", $"su kien {i}");

        int removed = _logger.PruneToMaxLines(100);

        Assert.Equal(0, removed);
        Assert.Equal(10, File.ReadAllLines(_logPath).Length);
    }

    [Fact]
    public void PruneToMaxLines_FileOverLimit_KeepsOnlyMostRecentLines()
    {
        for (int i = 0; i < 20; i++) _logger.Log("system", $"su kien {i}");

        int removed = _logger.PruneToMaxLines(5);

        Assert.Equal(15, removed);

        // [HOP DONG DA DOI] PruneToMaxLines gio LUU TRU cac dong bi cat thay
        // vi huy chung (dung co che da ap cho ClearAll), va ghi mot dong audit
        // ghi nhan viec do vao chinh nhat ky. Nen file con lai la 5 dong giu
        // + 1 dong ghi nhan = 6. Y dinh goc cua test — "dong moi nhat khong bi
        // mat" — van duoc kiem, chi la khong con o vi tri cuoi cung.
        var remaining = File.ReadAllLines(_logPath);
        Assert.Equal(6, remaining.Length);
        Assert.Contains(remaining, l => l.Contains("su kien 19"));
        Assert.Contains("LUU TRU", remaining[^1]);

        // Va day la phan quan trong: 15 dong bi cat phai CON TREN DIA, khong
        // bi huy. Khong co dieu nay thi prune tu dong tro thanh mot duong xoa
        // bang chung chay ngam dinh ky.
        var dir = Path.GetDirectoryName(_logPath)!;
        var archives = Directory.GetFiles(dir, "audit-pruned-*.jsonl");
        Assert.Single(archives);
        var archived = File.ReadAllLines(archives[0]);
        Assert.Equal(15, archived.Length);
        Assert.Contains("su kien 0", archived[0]);
        Assert.Contains("su kien 14", archived[^1]);
    }

    [Fact]
    // [CAP NHAT THEO BAN SUA BAO MAT] ClearAll KHONG con huy du lieu.
    // DELETE /api/audit truoc day cho phep bat ky ai co token xoa sach moi
    // bang chung ve nhung gi da xay ra tren may — mot nhat ky kiem toan xoa
    // duoc bang chinh giao dien no dang giam sat thi khong con gia tri lam
    // bang chung. Hop dong moi: LUU TRU sang file rieng roi bat dau file
    // trong. Test nay khoa lai hop dong do.
    public void ClearAll_ArchivesOldEventsAndStartsFreshLog()
    {
        for (int i = 0; i < 5; i++) _logger.Log("system", $"su kien {i}");

        var archivePath = _logger.ClearAll();

        // 1. Du lieu cu KHONG bi huy — no nam trong ban luu tru.
        Assert.NotNull(archivePath);
        Assert.True(File.Exists(archivePath));
        var archived = File.ReadAllText(archivePath!);
        for (int i = 0; i < 5; i++) Assert.Contains($"su kien {i}", archived);

        // 2. Nhat ky dang hoat dong khong con cac su kien cu.
        var live = File.ReadAllText(_logPath);
        for (int i = 0; i < 5; i++) Assert.DoesNotContain($"su kien {i}", live);

        // 3. Co mot ban ghi chi ro du lieu cu da di dau — nguoi dieu tra
        //    sau nay phai lan ra duoc ban luu tru tu chinh nhat ky.
        Assert.Contains("LUU TRU", live);

        try { File.Delete(archivePath!); } catch { }
    }

    [Fact]
    public void ClearAll_OnEmptyLog_CreatesNoArchive()
    {
        var archivePath = _logger.ClearAll();

        Assert.Null(archivePath);
    }

    [Fact]
    public void GetLogFileSizeBytes_ReflectsActualFileSize()
    {
        _logger.Log("system", "mot dong log");

        long size = _logger.GetLogFileSizeBytes();

        Assert.True(size > 0);
        Assert.Equal(new FileInfo(_logPath).Length, size);
    }

    public void Dispose()
    {
        // Xoa CA thu muc: nhat ky chinh + moi ban luu tru (audit-*.jsonl,
        // audit-pruned-*.jsonl) ma ClearAll/PruneToMaxLines da tao ra.
        try { Directory.Delete(_logDir, recursive: true); } catch { }
    }
}
