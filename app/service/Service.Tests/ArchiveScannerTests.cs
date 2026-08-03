using System.IO.Compression;
using Antivirus.Service.Archive;
using Antivirus.Service.Engine;
using Antivirus.Service.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// NFR-AVAIL-01 (nfr/06) + errors/10 FLAG_SUSPICIOUS_ZIPBOMB.
[Collection("EngineSequential")]
public class ArchiveScannerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ScanEngineService _engine;
    private readonly ArchiveScanner _scanner;

    public ArchiveScannerTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("avtest_zip_").FullName;
        _engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        _engine.Initialize(null, null);
        _scanner = new ArchiveScanner(_engine, NullLogger<ArchiveScanner>.Instance);
    }

    [Fact]
    public void ZipBomb_ExceedsCompressionRatio_FlaggedSuspicious()
    {
        var zipPath = Path.Combine(_tempDir, "bomb.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("zeros.bin", CompressionLevel.SmallestSize);
            using var stream = entry.Open();
            // 5MB toan so 0 nen duoc voi ty le rat cao (>> 100 lan).
            var zeros = new byte[5 * 1024 * 1024];
            stream.Write(zeros, 0, zeros.Length);
        }

        var result = _scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.Suspicious, result.Verdict);
        Assert.Equal(DetectionStage.ZipBombGuard, result.Stage);
        Assert.Contains("FLAG_SUSPICIOUS_ZIPBOMB", result.Reason);
    }

    [Fact]
    public void NormalZip_WithinLimits_ReturnsClean()
    {
        var zipPath = Path.Combine(_tempDir, "normal.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("readme.txt", CompressionLevel.Optimal);
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream);
            writer.Write("Noi dung binh thuong, khong nen duoc nhieu.");
        }

        var result = _scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.Clean, result.Verdict);
    }

    // [KIEM THU HOI QUY] Windows Recycle Bin doi ten file bi xoa thanh
    // "$IXXXXXX.<duoi_goc>" (ban ghi metadata nho, KHONG phai file nen
    // that) NHUNG GIU NGUYEN duoi cua file goc — vi du "$IABC123.zip" du
    // noi dung that KHONG phai dinh dang zip. Truoc day chi kiem tra duoi
    // ".zip" nen co ep mo bang ZipFile.OpenRead() va bao loi "hong/sai
    // dinh dang" sai lech; gio phai kiem tra magic bytes that.
    [Fact]
    public void FileWithZipExtensionButNotZipContent_NotTreatedAsZip()
    {
        var fakeZipPath = Path.Combine(_tempDir, "$IABC123.zip");
        // Noi dung gia lap ban ghi metadata Recycle Bin — khong phai zip that.
        File.WriteAllBytes(fakeZipPath, new byte[] { 0x02, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00 });

        Assert.False(ArchiveScanner.IsZipArchive(fakeZipPath));
    }

    [Fact]
    public void RealZipFile_StillDetectedAsZip()
    {
        var zipPath = Path.Combine(_tempDir, "real.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            archive.CreateEntry("a.txt");
        }

        Assert.True(ArchiveScanner.IsZipArchive(zipPath));
    }

    public void Dispose()
    {
        _engine.Dispose();
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }
}
