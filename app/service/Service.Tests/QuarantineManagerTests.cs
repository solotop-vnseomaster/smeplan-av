using System.Linq;
using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Models;
using Antivirus.Service.Quarantine;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// business-rules/05 muc "File trong Quarantine" (TEST-06/TEST-09).
public class QuarantineManagerTests : IDisposable
{
    private readonly string _dbPath;
    private readonly string _originalFilePath;
    private readonly QuarantineStore _store;
    private readonly QuarantineManager _manager;
    private readonly string _quarantineDir;

    public QuarantineManagerTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_qtn_{Guid.NewGuid():N}.db");
        _store = new QuarantineStore(_dbPath);
        var audit = new AuditLogger(Path.Combine(Path.GetTempPath(), $"avtest_audit_{Guid.NewGuid():N}.jsonl"));
        _quarantineDir = Directory.CreateTempSubdirectory("avtest_qtndir_").FullName;
        // applyAcl:false vi tien trinh test chay quyen nguoi dung thuong —
        // neu bat ACL SYSTEM-only, chinh test se tu khoa minh ra khoi thu
        // muc vua tao (xem ghi chu trong QuarantineManager constructor).
        _manager = new QuarantineManager(_store, audit, NullLogger<QuarantineManager>.Instance,
            _quarantineDir, applyAcl: false);

        _originalFilePath = Path.Combine(Path.GetTempPath(), $"avtest_file_{Guid.NewGuid():N}.txt");
        File.WriteAllText(_originalFilePath, "noi dung file nghi ngo can cach ly");
    }

    [Fact]
    public void NormalFile_QuarantinedThenRestored_ContentMatchesOriginal()
    {
        var originalContent = File.ReadAllText(_originalFilePath);

        var record = _manager.QuarantineFile(_originalFilePath, "deadbeef", "test-detection");

        Assert.Equal(QuarantineStatus.Quarantined, record.Status);
        Assert.False(File.Exists(_originalFilePath)); // BIZ-08: doi ten + di chuyen ra khoi vi tri goc

        var restored = _manager.Restore(record.QuarantineId);

        Assert.True(restored);
        Assert.True(File.Exists(_originalFilePath));
        Assert.Equal(originalContent, File.ReadAllText(_originalFilePath));
    }

    // BIZ-07: file he thong duoc WRP bao ve -> PendingManualConfirmation,
    // KHONG tu dong quarantine.
    [Fact]
    public void SystemProtectedPath_ClassifiedAsPendingManualConfirmation()
    {
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var fakeSystemPath = Path.Combine(windowsDir, "notepad.exe"); // file that co san, khong bi dong cham

        Assert.True(QuarantineManager.IsInWindowsResourceProtectedDirectory(fakeSystemPath));
    }

    [Fact]
    public void NormalUserPath_NotClassifiedAsProtected()
    {
        Assert.False(QuarantineManager.IsInWindowsResourceProtectedDirectory(_originalFilePath));
    }

    // [KIEM THU HOI QUY] StartsWith("C:\Program Files") truoc day khop
    // NHAM voi "C:\Program FilesXYZ\evil.exe" vi khong kiem tra dau phan
    // cach thu muc ngay sau prefix — khien mot file Malicious nam trong
    // thu muc GIA DANG ten he thong bi phan loai nham thanh "trong vung
    // WRP bao ve" (PendingManualConfirmation) thay vi tu dong Quarantine
    // ngay, lam cham phan ung cua AV.
    [Fact]
    public void SimilarlyNamedSiblingDirectory_NotClassifiedAsProtected()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var parent = Path.GetDirectoryName(programFiles)!;
        var fakeSiblingPath = Path.Combine(parent, Path.GetFileName(programFiles) + "XYZ", "evil.exe");

        Assert.False(QuarantineManager.IsInWindowsResourceProtectedDirectory(fakeSiblingPath));
    }

    // [TINH NANG THEO YEU CAU NGUOI DUNG] "Quarantine co xoa duoc khong,
    // neu duoc thi xoa the nao".
    [Fact]
    public void DeletePermanently_QuarantinedFile_RemovesRecordAndDiskCopy()
    {
        var record = _manager.QuarantineFile(_originalFilePath, "deadbeef", "test-detection");

        var deleted = _manager.DeletePermanently(record.QuarantineId);

        Assert.True(deleted);
        Assert.DoesNotContain(_manager.List(), r => r.QuarantineId == record.QuarantineId);
        // Khong con cach nao khoi phuc duoc nua sau khi xoa vinh vien.
        Assert.False(_manager.Restore(record.QuarantineId));
    }

    [Fact]
    public void DeletePermanently_UnknownId_ReturnsFalse()
    {
        Assert.False(_manager.DeletePermanently("khong-ton-tai"));
    }

    // [test-coverage] ConfirmManualQuarantine truoc day chua co test nao —
    // day la nhanh "PendingManualConfirmation -> Quarantined" (nguoi dung tu
    // tay xac nhan cach ly mot file he thong bi gan co Malicious). Ghi
    // thang record PendingManualConfirmation vao store (khong qua duong dan
    // WRP that, chi can dung status) de test rieng logic cua ham nay.
    [Fact]
    public void ConfirmManualQuarantine_PendingRecord_MovesFileAndUpdatesStatus()
    {
        var originalContent = File.ReadAllText(_originalFilePath);
        var quarantineId = Guid.NewGuid().ToString("N");
        _store.Add(new QuarantineRecord
        {
            QuarantineId = quarantineId,
            OriginalPath = _originalFilePath,
            OriginalFilename = Path.GetFileName(_originalFilePath),
            Sha256Hash = "deadbeef",
            DetectionReason = "test-pending-confirmation",
            QuarantinedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FileSize = (ulong)new FileInfo(_originalFilePath).Length,
            Status = QuarantineStatus.PendingManualConfirmation,
        });

        var confirmed = _manager.ConfirmManualQuarantine(quarantineId);

        Assert.True(confirmed);
        Assert.False(File.Exists(_originalFilePath)); // da di chuyen vao quarantine
        Assert.Equal(QuarantineStatus.Quarantined, _store.Get(quarantineId)!.Status);

        // Xac nhan file THUC SU nam trong quarantine (co the khoi phuc lai duoc).
        var restored = _manager.Restore(quarantineId);
        Assert.True(restored);
        Assert.Equal(originalContent, File.ReadAllText(_originalFilePath));
    }

    [Fact]
    public void ConfirmManualQuarantine_UnknownId_ReturnsFalse()
    {
        Assert.False(_manager.ConfirmManualQuarantine("khong-ton-tai"));
    }

    // Chi duoc phep xac nhan tu trang thai PendingManualConfirmation — mot
    // record da o trang thai khac (vi du da Quarantined roi) khong duoc
    // xu ly lai qua duong nay.
    [Fact]
    public void ConfirmManualQuarantine_RecordNotPending_ReturnsFalse()
    {
        var record = _manager.QuarantineFile(_originalFilePath, "deadbeef", "test-detection");
        Assert.Equal(QuarantineStatus.Quarantined, record.Status);

        Assert.False(_manager.ConfirmManualQuarantine(record.QuarantineId));
    }

    [Fact]
    public void Restore_UnknownId_ReturnsFalse()
    {
        Assert.False(_manager.Restore("khong-ton-tai"));
    }

    // Nhanh loi trong Restore: record HOP LE, status=Quarantined, nhung
    // file .qtn tren dia da bi mat/xoa ngoai y muon — phai tra false va
    // KHONG duoc nem exception, thay vi crash.
    [Fact]
    public void Restore_QuarantinedFileMissingOnDisk_ReturnsFalseDoesNotThrow()
    {
        var record = _manager.QuarantineFile(_originalFilePath, "deadbeef", "test-detection");
        var qtnPath = Path.Combine(_quarantineDir, record.QuarantineId + ".qtn");
        File.Delete(qtnPath); // gia lap file quarantine bi mat tren dia

        var restored = _manager.Restore(record.QuarantineId);

        Assert.False(restored);
    }

    // Khong duoc phep Restore mot record dang o trang thai PendingManual
    // Confirmation (file goc chua bao gio thuc su bi di chuyen vao quarantine).
    [Fact]
    public void Restore_PendingManualConfirmationRecord_ReturnsFalse()
    {
        var quarantineId = Guid.NewGuid().ToString("N");
        _store.Add(new QuarantineRecord
        {
            QuarantineId = quarantineId,
            OriginalPath = _originalFilePath,
            OriginalFilename = Path.GetFileName(_originalFilePath),
            Sha256Hash = "deadbeef",
            DetectionReason = "test-pending-confirmation",
            QuarantinedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FileSize = 0,
            Status = QuarantineStatus.PendingManualConfirmation,
        });

        Assert.False(_manager.Restore(quarantineId));
    }

    // Khong duoc phep Restore hai lan lien tiep tren cung mot record (sau
    // lan dau, status da chuyen thanh Restored, KHONG con la Quarantined).
    [Fact]
    public void Restore_AlreadyRestoredRecord_SecondCallReturnsFalse()
    {
        var record = _manager.QuarantineFile(_originalFilePath, "deadbeef", "test-detection");

        Assert.True(_manager.Restore(record.QuarantineId));
        Assert.False(_manager.Restore(record.QuarantineId));
    }

    // [test-coverage][SUA LOI TRUNG BINH da co trong QuarantineManager.Restore]
    // Neu vi tri goc DA CO mot file khac (vi du nguoi dung luu file moi vao
    // dung cho trong sau khi quarantine), Restore() PHAI tu choi ghi de va
    // tra ve false — truoc day khong co test nao xac nhan dieu nay, chi co
    // nhanh "file quarantine bien mat tren dia" duoc test.
    [Fact]
    public void Restore_OriginalPathHasNewFile_RefusesToOverwrite_ReturnsFalse()
    {
        var record = _manager.QuarantineFile(_originalFilePath, "deadbeef", "test-detection");
        Assert.False(File.Exists(_originalFilePath));

        // Nguoi dung (hoac chuong trinh khac) tao lai mot file MOI, KHONG
        // lien quan, dung ten tai vi tri goc.
        const string newUnrelatedContent = "file moi hoan toan khong lien quan, KHONG duoc mat";
        File.WriteAllText(_originalFilePath, newUnrelatedContent);

        var restored = _manager.Restore(record.QuarantineId);

        Assert.False(restored);
        // Noi dung file MOI phai con nguyen, khong bi ghi de boi noi dung
        // quarantine cu.
        Assert.Equal(newUnrelatedContent, File.ReadAllText(_originalFilePath));
        // Ban ghi DB phai VAN CON o trang thai Quarantined (chua chuyen
        // Restored) — nguoi dung co the thu lai sau khi don duong.
        var stillQuarantined = _store.Get(record.QuarantineId);
        Assert.NotNull(stillQuarantined);
        Assert.Equal(QuarantineStatus.Quarantined, stillQuarantined!.Status);
    }

    // [test-coverage][SUA LOI NGHIEM TRONG da co trong QuarantineFile] Neu
    // MoveIntoQuarantine that bai GIUA CHUNG (sau khi da ghi DB voi trang
    // thai Quarantined), ban ghi DB phai duoc ROLLBACK (xoa di) de khong
    // "mo coi" — truoc day khong co test nao xac nhan rollback nay THAT SU
    // xay ra. Mo phong that bai bang cach quarantine mot duong dan file
    // KHONG TON TAI (File.ReadAllBytes trong MoveIntoQuarantine se nem
    // FileNotFoundException).
    [Fact]
    public void QuarantineFile_MoveFails_RollsBackDbRecord_AndRethrows()
    {
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"avtest_khong_ton_tai_{Guid.NewGuid():N}.exe");
        Assert.False(File.Exists(nonExistentPath));

        var ex = Record.Exception(() => _manager.QuarantineFile(nonExistentPath, "deadbeef", "test-detection"));

        Assert.NotNull(ex);
        Assert.IsType<FileNotFoundException>(ex);

        // Khong duoc con ban ghi "mo coi" nao trong DB cho duong dan nay
        // sau khi rollback.
        Assert.DoesNotContain(_store.List(), r => r.OriginalPath == nonExistentPath);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
        try { File.Delete(_originalFilePath); } catch { }
    }
}
