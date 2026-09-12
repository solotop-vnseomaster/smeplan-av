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

    // [BO SUNG TEST GHIM BIEN] Test ZipBomb_ExceedsCompressionRatio o tren
    // dung ty le ~1000x — cao hon nguong (100x) mot bac do lon, nen no van
    // XANH ke ca khi ban va bien bi revert (vi du quay lai phep CHIA co
    // truncation: 100.99x bi cat con 100, khong > 100, LOT). Mot test chi
    // xanh/do o vung xa bien thi khong khoa duoc chinh cho de vo nhat.
    //
    // Test nay dung ty le NGAY TREN nguong de ghim dung bien do.
    [Fact]
    public void ZipBomb_RatioJustAboveThreshold_StillFlagged()
    {
        var zipPath = Path.Combine(_tempDir, "boundary.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("mixed.bin", CompressionLevel.SmallestSize);
            using var stream = entry.Open();
            // Du lieu nen duoc VUA PHAI: mot phan lap lai (nen tot) tron voi
            // du lieu ngau nhien on dinh (nen kem) de ty le rot vao vung
            // ngay tren 100x thay vi hang nghin lan.
            var rng = new Random(12345); // hat giong co dinh -> test tat dinh
            var block = new byte[64 * 1024];
            for (int i = 0; i < 40; i++)
            {
                // Moi khoi 64KB: phan lon la so 0 (nen gan nhu het) + mot
                // duoi ngau nhien (khong nen duoc). Kich thuoc duoi ngau
                // nhien duoc chon de ty le tong roi vao khoang ~115x —
                // ngay TREN nguong 100x, du gan de ghim dung bien.
                Array.Clear(block);
                rng.NextBytes(block.AsSpan(block.Length - 400));
                stream.Write(block, 0, block.Length);
            }
        }

        var result = _scanner.ScanZip(zipPath);
        long compressed, decompressed;
        using (var archive = ZipFile.OpenRead(zipPath))
        {
            compressed = archive.Entries[0].CompressedLength;
            decompressed = archive.Entries[0].Length;
        }

        double ratio = (double)decompressed / compressed;
        // Chi co y nghia neu ty le that su nam gan bien — neu khong, test
        // nay khong ghim duoc gi va phai noi ro thay vi xanh gia.
        Assert.True(ratio > ArchiveScanner.MaxCompressionRatio,
            $"Du lieu dung thu nghiem cho ty le {ratio:0.##}x, KHONG vuot nguong {ArchiveScanner.MaxCompressionRatio}x — test khong ghim duoc bien");
        Assert.True(ratio < ArchiveScanner.MaxCompressionRatio * 5,
            $"Ty le {ratio:0.##}x qua xa bien ({ArchiveScanner.MaxCompressionRatio}x) — test lai roi vao dung cai bay ma no sinh ra de tranh");

        Assert.Equal(ScanVerdict.Suspicious, result.Verdict);
        Assert.Equal(DetectionStage.ZipBombGuard, result.Stage);
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

    // EICAR standard test string — chuoi test chuan cong khai cua nganh
    // antivirus (khong phai malware that), giong EngineTests.cs.
    private const string EicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private ArchiveScanner BuildScannerWithEicarSignature()
    {
        var csvPath = Path.Combine(_tempDir, "sigs.csv");
        File.WriteAllText(csvPath, $"{EicarSha256},1,255\n");
        var dbPath = Path.Combine(_tempDir, "sigs.avsigdb");
        Assert.True(ScanEngineService.BuildSignatureDb(csvPath, dbPath));

        var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        Assert.True(engine.Initialize(dbPath, null));
        return new ArchiveScanner(engine, NullLogger<ArchiveScanner>.Instance);
    }

    // [KIEM THU HOI QUY] Cho loi da sua trong ScanZipRecursive: nhanh zip
    // long nhau TRUOC DAY return NGAY khi gap ScanError tu mot zip con bi
    // hong, bo qua toan bo cac entry con lai trong CUNG archive — ke ca mot
    // file Malicious xuat hien SAU do. Test nay dung mot archive chua (1)
    // mot entry .zip long nhau bi hong (gay ScanError khi mo), roi (2) mot
    // file EICAR (Malicious) — verdict cuoi cung PHAI la Malicious, khong
    // duoc dung lai o ScanError.
    [Fact]
    public void ArchiveWithCorruptedNestedZipThenMaliciousFile_ReturnsMalicious_NotScanError()
    {
        var scanner = BuildScannerWithEicarSignature();
        var zipPath = Path.Combine(_tempDir, "mixed.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            // Entry 1: gia lap mot zip long nhau bi hong — ten co duoi
            // ".zip" de kich hoat nhanh de-quy, nhung noi dung KHONG phai
            // dinh dang zip hop le -> ZipFile.OpenRead ben trong se nem
            // InvalidDataException, duoc bat lai thanh ScanResultDto
            // Verdict=ScanError o tang ScanZip cua nested call... nhung vi
            // ScanZipRecursive de quy truc tiep (khong qua ScanZip), loi nay
            // se throw thang len — bat no o day va gan verdict ScanError
            // tuong tu hanh vi thuc te khi goi qua ScanZip cong khai.
            var corruptEntry = archive.CreateEntry("corrupt_nested.zip", CompressionLevel.NoCompression);
            using (var s = corruptEntry.Open())
            {
                // [CAP NHAT FIXTURE] Nhan dang archive long nhau gio theo
                // MAGIC BYTE chu khong theo duoi file (xem
                // ArchiveScanner.HasZipMagic) — dung nguyen tac ma
                // FileWithZipExtensionButNotZipContent_NotTreatedAsZip da
                // yeu cau o vong ngoai. Nen mot file ten ".zip" chua rac
                // KHONG con la "zip long nhau bi hong", no chi la mot file
                // thuong (dung: do chinh la truong hop $IABC123.zip cua
                // Recycle Bin). De van gia lap duoc ZIP HONG THAT SU, noi
                // dung phai co magic PK hop le nhung cau truc vo — giong
                // TopLevelFileWithValidMagicBytesButGarbageStructure.
                var junk = new byte[] { 0x50, 0x4B, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11 };
                s.Write(junk, 0, junk.Length);
            }

            // Entry 2: file Malicious (EICAR) — phai duoc quet toi va phat
            // hien, KHONG duoc bo qua vi entry truoc do loi.
            var eicarEntry = archive.CreateEntry("eicar.com", CompressionLevel.NoCompression);
            using (var s = eicarEntry.Open())
            using (var writer = new StreamWriter(s))
            {
                writer.Write(EicarContent);
            }
        }

        var result = scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.Malicious, result.Verdict);
    }

    // [KIEM THU HOI QUY] Nhanh "return pendingEntryError ?? Clean" o cuoi
    // ScanZipRecursive: khi archive CHI co loi quet (mot zip long nhau bi
    // hong) va KHONG co entry nao khac Malicious/Suspicious, verdict cuoi
    // PHAI la ScanError (bao dung la co loi chua quet duoc het), KHONG duoc
    // "nuot" thanh Clean nhu hanh vi loi truoc day.
    [Fact]
    public void ArchiveWithOnlyCorruptedNestedZip_NoMaliciousEntry_ReturnsScanError()
    {
        var zipPath = Path.Combine(_tempDir, "only_corrupt.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var corruptEntry = archive.CreateEntry("corrupt_nested.zip", CompressionLevel.NoCompression);
            using (var s = corruptEntry.Open())
            {
                // [CAP NHAT FIXTURE] Nhan dang archive long nhau gio theo
                // MAGIC BYTE chu khong theo duoi file (xem
                // ArchiveScanner.HasZipMagic) — dung nguyen tac ma
                // FileWithZipExtensionButNotZipContent_NotTreatedAsZip da
                // yeu cau o vong ngoai. Nen mot file ten ".zip" chua rac
                // KHONG con la "zip long nhau bi hong", no chi la mot file
                // thuong (dung: do chinh la truong hop $IABC123.zip cua
                // Recycle Bin). De van gia lap duoc ZIP HONG THAT SU, noi
                // dung phai co magic PK hop le nhung cau truc vo — giong
                // TopLevelFileWithValidMagicBytesButGarbageStructure.
                var junk = new byte[] { 0x50, 0x4B, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11 };
                s.Write(junk, 0, junk.Length);
            }

            var cleanEntry = archive.CreateEntry("harmless.txt", CompressionLevel.NoCompression);
            using (var s2 = cleanEntry.Open())
            using (var writer = new StreamWriter(s2))
            {
                writer.Write("noi dung sach, khong lien quan");
            }
        }

        var result = _scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.ScanError, result.Verdict);
    }

    // [KIEM THU HOI QUY] Cho loi da sua: DeflateStream nem InvalidDataException
    // khi du lieu nen cua MOT ENTRY THUONG (khong phai zip long nhau) bi hong
    // — truoc day khong co try/catch quanh vong doc entryStream.Read(), nen
    // loi nay bay thang qua foreach va bien ca archive thanh ScanError, bo
    // qua file Malicious dung sau entry hong. Dung mot entry co du lieu nen
    // (Deflate) bi ghi de bang byte ngau nhien de gia lap hong dia/tai loi
    // thuc te, roi kiem tra entry Malicious phia sau van duoc quet toi.
    [Fact]
    public void ArchiveWithTopLevelCorruptedDeflateEntryThenMaliciousFile_ReturnsMalicious_NotScanError()
    {
        var scanner = BuildScannerWithEicarSignature();
        var zipPath = Path.Combine(_tempDir, "toplevel_corrupt.zip");
        using (var ms = new MemoryStream())
        {
            using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                var e1 = archive.CreateEntry("corrupt.bin", CompressionLevel.Optimal);
                long entry1Start = ms.Position;
                using (var es = e1.Open())
                {
                    var data = System.Text.Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("AAAA BBBB CCCC DDDD ", 5000)));
                    es.Write(data, 0, data.Length);
                }
                long entry1End = ms.Position;

                var e2 = archive.CreateEntry("eicar.com", CompressionLevel.NoCompression);
                using (var es2 = e2.Open())
                using (var writer = new StreamWriter(es2))
                {
                    writer.Write(EicarContent);
                }

                var bytes = ms.GetBuffer();
                var rnd = new Random(42);
                long corruptFrom = entry1Start + 60;
                long corruptTo = entry1End - 4;
                for (long i = corruptFrom; i < corruptTo && i < ms.Length; i++)
                {
                    bytes[i] = (byte)rnd.Next(256);
                }
            }
            File.WriteAllBytes(zipPath, ms.ToArray());
        }

        var result = scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.Malicious, result.Verdict);
    }

    // Boc `content` vao trong `levels` lop zip long nhau, entry ten "n.zip"
    // o moi lop de kich hoat nhanh de quy zip-trong-zip cua ArchiveScanner.
    private static byte[] WrapInNestedZips(byte[] content, int levels, string leafName = "leaf.bin")
    {
        var current = content;
        var currentName = leafName;
        for (int i = 0; i < levels; i++)
        {
            using var ms = new MemoryStream();
            using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = archive.CreateEntry(currentName, CompressionLevel.NoCompression);
                using var es = entry.Open();
                es.Write(current, 0, current.Length);
            }
            current = ms.ToArray();
            currentName = $"level{i}.zip";
        }
        return current;
    }

    // [KIEM THU MOI — GHIM BAN SUA "GUARD DUNG, AP THIEU DUONG"]
    // IsZipArchive (vong ngoai) da bo hoan toan viec xet duoi file va chuyen
    // sang magic byte. Nhung nhanh archive LONG NHAU van con
    // `entry.FullName.EndsWith(".zip")` — nen chi can doi ten zip ben trong
    // thanh mot duoi khac la no khong bao gio duoc giai nen de quet.
    //
    // Test nay dung entry TRONG duoc NEN (SmallestSize) chu KHONG phai
    // NoCompression: neu de NoCompression thi chuoi EICAR nam nguyen van
    // trong byte cua zip long nhau, va _engine.ScanBuffer se bat duoc no ngay
    // ca khi KHONG he recurse — test se xanh gia. Nen no lai lam EICAR bien
    // mat khoi luong byte tho, nen chi co duong recurse THAT SU moi phat hien
    // duoc. Do la cai khoa cho ban sua nay.
    [Fact]
    public void NestedZipWithNonZipExtension_IsStillRecursedInto_DetectsMalicious()
    {
        byte[] nestedZipBytes;
        using (var ms = new MemoryStream())
        {
            using (var inner = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                var e = inner.CreateEntry("eicar.com", CompressionLevel.SmallestSize);
                using var s = new StreamWriter(e.Open());
                s.Write(EicarContent);
            }
            nestedZipBytes = ms.ToArray();
        }

        // Kiem tra tien de cua test: EICAR KHONG con hien dien duoi dang van
        // ban tho trong zip long nhau. Neu dieu nay sai, test khong con chung
        // minh duoc gi ca.
        Assert.DoesNotContain("EICAR-STANDARD", System.Text.Encoding.ASCII.GetString(nestedZipBytes));

        var zipPath = Path.Combine(_tempDir, "outer.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            // Duoi ".dat", KHONG phai ".zip" — noi dung van la mot zip that.
            var entry = archive.CreateEntry("payload.dat", CompressionLevel.NoCompression);
            using var s = entry.Open();
            s.Write(nestedZipBytes, 0, nestedZipBytes.Length);
        }

        // EICAR chi bi phat hien qua CSDL chu ky (hash), nen phai dung
        // scanner co nap DB — giong cac test Malicious khac trong file nay.
        var scanner = BuildScannerWithEicarSignature();
        var result = scanner.ScanZip(zipPath);

        Assert.True(result.Verdict == ScanVerdict.Malicious,
            $"verdict={result.Verdict} stage={result.Stage} reason={result.Reason}");
    }

    // [KIEM THU MOI] Nhanh MaxNestingDepth/FLAG_SUSPICIOUS_TOO_DEEP truoc day
    // chua co test nao cham toi — zip long nhau VUOT QUA do sau toi da (5 lop)
    // phai bi gan co Suspicious, khong duoc quet xuyen qua vo han.
    [Fact]
    public void ZipNestedBeyondMaxDepth_FlaggedSuspicious()
    {
        var leaf = System.Text.Encoding.UTF8.GetBytes("noi dung o day sau nhat, khong quan trong");
        // MaxNestingDepth = 5, ScanZip() bat dau tinh depth=1 cho file goc —
        // boc 6 lop de chac chan vuot qua nguong.
        var wrapped = WrapInNestedZips(leaf, levels: 6);
        var zipPath = Path.Combine(_tempDir, "too_deep.zip");
        File.WriteAllBytes(zipPath, wrapped);

        var result = _scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.Suspicious, result.Verdict);
        Assert.Equal(DetectionStage.ZipBombGuard, result.Stage);
        Assert.Contains("FLAG_SUSPICIOUS_TOO_DEEP", result.Reason);
    }

    // [KIEM THU MOI] Nhanh ScanZip() bat InvalidDataException khi CHINH FILE
    // TOP-LEVEL hong cau truc (khong qua nested-zip) truoc day chua co test —
    // gia lap file co magic byte PK\x03\x04 hop le (de IsZipArchive/logic goi
    // ScanZip nhan dien la zip) nhung phan con lai la rac hoan toan, khien
    // ZipFile.OpenRead() nem InvalidDataException ngay khi mo central directory.
    [Fact]
    public void TopLevelFileWithValidMagicBytesButGarbageStructure_ReturnsScanError()
    {
        var zipPath = Path.Combine(_tempDir, "garbage_structure.zip");
        var garbage = new byte[] { 0x50, 0x4B, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33 };
        File.WriteAllBytes(zipPath, garbage);

        var result = _scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.ScanError, result.Verdict);
        Assert.Equal(DetectionStage.IoError, result.Stage);
    }

    // [KIEM THU MOI] Nhanh MergeEntryVerdict/"pendingEntryError ??=" cho hai
    // nhanh zip-long-nhau va entry-thuong (giu loi DAU TIEN khi CO TU 2 entry
    // loi tro len, khong entry nao Malicious) truoc day chi co test voi DUNG 1
    // loi/archive — khong bat duoc neu ai do doi ??= thanh =. Dung archive voi
    // HAI entry deu la zip-long-nhau bi hong (noi dung rac, duoi ".zip" de
    // kich hoat de quy roi ZipFile.OpenRead ben trong nem InvalidDataException),
    // kiem tra Reason cuoi cung nhac toi entry DAU TIEN.
    [Fact]
    public void ArchiveWithTwoCorruptedNestedZips_NoMalicious_KeepsFirstError()
    {
        var zipPath = Path.Combine(_tempDir, "two_errors.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var e1 = archive.CreateEntry("first_bad.zip", CompressionLevel.NoCompression);
            using (var s1 = e1.Open())
            {
                // Xem ghi chu [CAP NHAT FIXTURE] o ArchiveWithCorruptedNestedZip...
                var junk1 = new byte[] { 0x50, 0x4B, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11 };
                s1.Write(junk1, 0, junk1.Length);
            }

            var e2 = archive.CreateEntry("second_bad.zip", CompressionLevel.NoCompression);
            using (var s2 = e2.Open())
            {
                var junk2 = new byte[] { 0x50, 0x4B, 0x03, 0x04, 0xCA, 0xFE, 0xBA, 0xBE, 0x22, 0x33 };
                s2.Write(junk2, 0, junk2.Length);
            }
        }

        var result = _scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.ScanError, result.Verdict);
        Assert.Contains("first_bad.zip", result.Reason);
    }

    // [KIEM THU HOI QUY] Cho loi da sua: entry.Open() cua .NET TU NO co the
    // nem InvalidDataException (LOCAL FILE HEADER hong — signature sai —
    // khac voi than deflate bi hong), TRUOC ca lan goi Read() dau tien. Fix
    // truoc chi bat exception quanh vong doc Read(), khong bao goi Open(),
    // nen loi dang nay van thoat foreach, bo qua Malicious dung sau. Dung
    // mot entry co 4-byte signature cua local file header bi ghi de, roi
    // kiem tra entry Malicious phia sau van duoc quet toi.
    [Fact]
    public void ArchiveWithCorruptedLocalFileHeaderThenMaliciousFile_ReturnsMalicious_NotScanError()
    {
        var scanner = BuildScannerWithEicarSignature();
        var zipPath = Path.Combine(_tempDir, "corrupt_header.zip");
        using (var msArchive = new MemoryStream())
        {
            using (var archive = new ZipArchive(msArchive, ZipArchiveMode.Create, leaveOpen: true))
            {
                var e1 = archive.CreateEntry("corrupt.bin", CompressionLevel.Optimal);
                long entry1Start = msArchive.Position;
                using (var es = e1.Open())
                {
                    var data = System.Text.Encoding.UTF8.GetBytes("noi dung binh thuong khong lien quan gi ca, chi de co mot entry hop le.");
                    es.Write(data, 0, data.Length);
                }

                var e2 = archive.CreateEntry("eicar.com", CompressionLevel.NoCompression);
                using (var es2 = e2.Open())
                using (var writer = new StreamWriter(es2))
                {
                    writer.Write(EicarContent);
                }

                var bytes = msArchive.GetBuffer();
                // Pha hong cac truong CO DINH cua LOCAL FILE HEADER (bo qua 4
                // byte signature PK\x03\x04 dau tien) — version/flags/method/
                // time/date/crc/sizes, TRUOC phan filename+du lieu nen.
                var rnd = new Random(7);
                for (long i = entry1Start; i < entry1Start + 30; i++)
                {
                    bytes[i] = (byte)rnd.Next(256);
                }
            }
            File.WriteAllBytes(zipPath, msArchive.ToArray());
        }

        var result = scanner.ScanZip(zipPath);

        Assert.Equal(ScanVerdict.Malicious, result.Verdict);
    }

    public void Dispose()
    {
        _engine.Dispose();
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }
}
