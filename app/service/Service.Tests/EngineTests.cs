using Antivirus.Service.Engine;
using Antivirus.Service.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// TEST-01 (TC-01 trong tests/07-kiem-thu.md): "Dat file EICAR tinh vao mot
// thu muc thuong, chay full scan -> Engine tra ve Malicious qua DUNG nhanh
// CSDL hash, khong roi vao nhanh heuristic."
[Collection("EngineSequential")]
public class EngineTests : IDisposable
{
    // EICAR standard test string — CHUOI TEST CHUAN CONG KHAI cua nganh
    // antivirus (khong phai malware that), dung dung noi dung neu trong
    // spec-output/v1 (xuat hien trong ten chunk nguon #32).
    private const string EicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private readonly string _tempDir;

    public EngineTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("avtest_engine_").FullName;
    }

    private string BuildSignatureDbWithEicar()
    {
        var csvPath = Path.Combine(_tempDir, "sigs.csv");
        File.WriteAllText(csvPath, $"{EicarSha256},1,255\n");
        var dbPath = Path.Combine(_tempDir, "sigs.avsigdb");
        Assert.True(ScanEngineService.BuildSignatureDb(csvPath, dbPath));
        return dbPath;
    }

    [Fact]
    public void Eicar_Sha256_MatchesKnownPublicHash()
    {
        var eicarPath = Path.Combine(_tempDir, "eicar.com");
        File.WriteAllText(eicarPath, EicarContent);

        using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        Assert.True(engine.Initialize(null, null));
        var hash = engine.Sha256File(eicarPath);

        Assert.Equal(EicarSha256, hash);
    }

    [Fact]
    public void Eicar_DetectedAsMalicious_ViaHashSignature_NotHeuristic()
    {
        var dbPath = BuildSignatureDbWithEicar();
        var eicarPath = Path.Combine(_tempDir, "eicar.com");
        File.WriteAllText(eicarPath, EicarContent);

        using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        Assert.True(engine.Initialize(dbPath, null));

        var result = engine.ScanFile(eicarPath);

        Assert.Equal(ScanVerdict.Malicious, result.Verdict);
        Assert.Equal(DetectionStage.HashSignature, result.Stage); // KHONG duoc roi vao nhanh heuristic
        Assert.Equal(EicarSha256, result.Sha256Hex);
    }

    [Fact]
    public void CleanFile_ReturnsCleanVerdict()
    {
        var dbPath = BuildSignatureDbWithEicar();
        var cleanPath = Path.Combine(_tempDir, "clean.txt");
        File.WriteAllText(cleanPath, "day la mot file van ban binh thuong, khong co gi doc hai.");

        using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        Assert.True(engine.Initialize(dbPath, null));

        var result = engine.ScanFile(cleanPath);

        Assert.Equal(ScanVerdict.Clean, result.Verdict);
    }

    // BIZ-05 domain invariant: "KHONG duoc phep: ScanError -> Clean — khong
    // duoc mac dinh coi ScanError la Clean khi gap loi doc file".
    [Fact]
    public void MissingFile_ReturnsScanError_NeverClean()
    {
        using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        Assert.True(engine.Initialize(null, null));

        var result = engine.ScanFile(Path.Combine(_tempDir, "khong-ton-tai.exe"));

        Assert.Equal(ScanVerdict.ScanError, result.Verdict);
        Assert.NotEqual(ScanVerdict.Clean, result.Verdict);
    }

    // [KIEM THU HOI QUY] signature_db.cpp: record_count doc truc tiep tu 8
    // byte dau file CSDL (khong validate) truoc day duoc NHAN voi
    // sizeof(SignatureRecord) roi so sanh voi kich thuoc file — voi
    // record_count du lon, phep nhan TRAN SO (wrap ve gia tri nho), lam
    // kiem tra bien bi bo qua va co the dan toi doc vuot vung nho da
    // memory-map. File duoi day gia mao record_count = UINT64_MAX tren mot
    // file CSDL chi co 24 byte (chi co header, khong co du lieu that).
    [Fact]
    public void CorruptedSignatureDb_HugeRecordCount_RejectedSafely_NotCrash()
    {
        var dbPath = Path.Combine(_tempDir, "corrupt.avsigdb");
        using (var fs = new FileStream(dbPath, FileMode.Create, FileAccess.Write))
        using (var writer = new BinaryWriter(fs))
        {
            writer.Write("AVSIGDB1"u8.ToArray()); // magic, 8 byte
            writer.Write(ulong.MaxValue);          // record_count gia mao — khong lo
            writer.Write((ulong)0);                // bloom_size = 0
            // Khong ghi them gi — file chi dai 24 byte, KHONG du cho bat ky
            // record nao, chu dung noi record_count = UINT64_MAX.
        }

        using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        engine.Initialize(null, null);

        // Neu con loi tran so, tien trinh test se CRASH (access violation)
        // thay vi tra ve false mot cach an toan — ban than viec test nay
        // CHAY XONG (khong crash) da la bang chung chinh.
        bool loaded = engine.LoadSignatureDb(dbPath);

        Assert.False(loaded);
    }

    // [KIEM THU HOI QUY] Duong dan vuot 260 ky tu (MAX_PATH) — CreateFileW
    // tho truoc day khong co tien to long-path ("\\?\") se that bai voi
    // ERROR_PATH_NOT_FOUND/ERROR_FILENAME_EXCED_RANGE, y het kieu loi gap
    // phai khi full scan quet qua C:\Windows\WinSxS (ten thu muc rat dai).
    [Fact]
    public void VeryLongPath_StillScannable_NotPathTooLongError()
    {
        // Tao mot cay thu muc long de vuot qua 260 ky tu tong do dai duong dan.
        var deepDir = _tempDir;
        while (deepDir.Length < 280)
        {
            deepDir = Path.Combine(deepDir, "sub_directory_name_padding_1234567890");
        }
        Directory.CreateDirectory(deepDir);
        var longPath = Path.Combine(deepDir, "clean.txt");
        File.WriteAllText(longPath, "noi dung binh thuong");
        Assert.True(longPath.Length > 260, $"Duong dan test can dai hon 260 ky tu, hien tai {longPath.Length}");

        using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        Assert.True(engine.Initialize(null, null));

        var result = engine.ScanFile(longPath);

        Assert.Equal(ScanVerdict.Clean, result.Verdict);
        Assert.DoesNotContain("PATH_TOO_LONG", result.Reason);
        Assert.DoesNotContain("NOT_FOUND", result.Reason);
    }

    // [KIEM THU HOI QUY] Loi mo file phai duoc PHAN LOAI (khong con chuoi
    // chung chung), de UI/nguoi van hanh biet duoc nguyen nhan that (file
    // dang bi tien trinh khac khoa, hay thieu quyen, hay duong dan qua dai).
    [Fact]
    public void LockedFile_ClassifiedAsSharingViolation()
    {
        var lockedPath = Path.Combine(_tempDir, "locked.txt");
        File.WriteAllText(lockedPath, "noi dung");

        // Mo doc quyen (khong chia se) tu chinh test de gia lap file dang
        // bi mot tien trinh khac khoa.
        using var exclusiveHandle = new FileStream(lockedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        Assert.True(engine.Initialize(null, null));

        var result = engine.ScanFile(lockedPath);

        Assert.Equal(ScanVerdict.ScanError, result.Verdict);
        Assert.Contains("SHARING_VIOLATION", result.Reason);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }
}

// Vo hieu hoa chay song song giua cac test dung chung trang thai global cua
// scan_engine.dll (Engine_Initialize/Shutdown la trang thai tien trinh, xem
// pipeline.cpp) de tranh doi nhau ket qua giua cac test.
[CollectionDefinition("EngineSequential", DisableParallelization = true)]
public class EngineSequentialCollection { }
