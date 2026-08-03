using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Antivirus.Service.Audit;
using Antivirus.Service.Engine;
using Antivirus.Service.FullScan;
using Antivirus.Service.Models;
using Antivirus.Service.Update;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// TEST-10 (TC-10): "Kiem tra update service xu ly dung ca luong incremental
// delta lan fallback full download ... verify chu ky so cua goi CSDL tai
// ve bang WinVerifyTrust [tuong duong RSA o day] truoc khi ap dung".
[Collection("EngineSequential")]
public class UpdateClientServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dropFolder;
    private readonly X509Certificate2 _trustedCert;
    private readonly X509Certificate2 _wrongCert;
    private readonly ScanEngineService _engine;

    public UpdateClientServiceTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("avtest_update_").FullName;
        _dropFolder = Path.Combine(_tempDir, "drop");
        Directory.CreateDirectory(_dropFolder);
        _trustedCert = CreateSelfSignedCert("CN=Test Trusted");
        _wrongCert = CreateSelfSignedCert("CN=Test Attacker");
        _engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        _engine.Initialize(null, null);
    }

    private static X509Certificate2 CreateSelfSignedCert(string subject)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var pfx = cert.Export(X509ContentType.Pfx, "test");
        return X509CertificateLoader.LoadPkcs12(pfx, "test", X509KeyStorageFlags.Exportable);
    }

    private void WritePackage(string fileName, string csvContent, X509Certificate2 signer)
    {
        var payload = Encoding.UTF8.GetBytes(csvContent);
        var signed = UpdatePackageVerifier.Sign(payload, signer);
        File.WriteAllBytes(Path.Combine(_dropFolder, fileName), signed);
    }

    private void WriteManifest(int latestVersion)
    {
        File.WriteAllText(Path.Combine(_dropFolder, "manifest.json"),
            JsonSerializer.Serialize(new { latestVersion, checksum = "n/a" }));
    }

    private UpdateClientService CreateClient(ScanCacheStore? scanCache = null)
    {
        var source = new LocalFolderUpdatePackageSource(_dropFolder);
        var audit = new AuditLogger(Path.Combine(_tempDir, "audit.jsonl"));
        return new UpdateClientService(source, _engine, audit, NullLogger<UpdateClientService>.Instance,
            _trustedCert,
            versionStatePath: Path.Combine(_tempDir, "version.json"),
            accumulatorCsvPath: Path.Combine(_tempDir, "accumulator.csv"),
            signatureDbPath: Path.Combine(_tempDir, "sigs.avsigdb"),
            scanCache: scanCache);
    }

    // [DIEM AN TOAN BAT BUOC — TICH HOP] Xac nhan UpdateClientService THAT
    // SU goi ScanCacheStore.ClearAll() sau khi ap dung CSDL moi thanh cong —
    // day la co che duy nhat ngan mot file "Clean" duoi CSDL cu bi cache
    // bo qua vinh vien sau khi CSDL moi da nhan dien no la ma doc.
    [Fact]
    public async Task SuccessfulUpdate_ClearsFullScanCache()
    {
        var cacheDbPath = Path.Combine(_tempDir, "scan_cache.db");
        var scanCache = new ScanCacheStore(cacheDbPath);
        scanCache.Upsert("C:\\old_file.exe", 1000, 500, signatureDbVersion: 0,
            new ScanResultDto { Verdict = ScanVerdict.Clean, Stage = DetectionStage.None, Sha256Hex = "x", Reason = "sach duoi CSDL cu" });
        Assert.Equal(1, scanCache.Count());

        WriteManifest(latestVersion: 1);
        WritePackage("v0_to_v1.delta", "7777777777777777777777777777777777777777777777777777777777777777,7,200\n", _trustedCert);

        var client = CreateClient(scanCache);
        var status = await client.CheckAndApplyAsync(CancellationToken.None);

        Assert.Equal(1, status.CurrentVersion);
        Assert.Equal(0, scanCache.Count()); // cache phai duoc xoa sach
    }

    [Fact]
    public async Task DeltaSequence_AppliedInOrder_AdvancesVersion()
    {
        WriteManifest(latestVersion: 2);
        WritePackage("v0_to_v1.delta", "1111111111111111111111111111111111111111111111111111111111111111,1,200\n", _trustedCert);
        WritePackage("v1_to_v2.delta", "2222222222222222222222222222222222222222222222222222222222222222,2,200\n", _trustedCert);

        var client = CreateClient();
        var status = await client.CheckAndApplyAsync(CancellationToken.None);

        Assert.Equal(2, status.CurrentVersion);
        Assert.Contains("thanh cong", status.LastResult, StringComparison.OrdinalIgnoreCase);
    }

    // [KIEM THU HOI QUY] Truoc fix FILE_SHARE_DELETE (signature_db.cpp),
    // SignatureDb::Load mo file CSDL voi FILE_SHARE_READ (thieu
    // FILE_SHARE_DELETE) va giu handle mo suot doi song engine. Lan
    // File.Move dau tien thanh cong (file dich chua ton tai), nhung
    // Engine_Initialize ngay sau do mo lai file va giu handle — khien MOI
    // lan cap nhat CSDL KE TIEP that bai voi sharing violation. Test nay
    // goi CheckAndApplyAsync HAI LAN LIEN TIEP tren CUNG mot engine/service
    // instance de xac nhan lan thu hai khong con that bai.
    [Fact]
    public async Task SecondConsecutiveUpdate_StillSucceeds_AfterShareDeleteFix()
    {
        WriteManifest(latestVersion: 1);
        WritePackage("v0_to_v1.delta", "5555555555555555555555555555555555555555555555555555555555555555,5,200\n", _trustedCert);

        var client = CreateClient();
        var first = await client.CheckAndApplyAsync(CancellationToken.None);
        Assert.Equal(1, first.CurrentVersion);

        // Ban CSDL moi (v2) — CUNG client/engine instance, handle tu lan
        // Initialize truoc van con mo neu bug chua duoc sua.
        WriteManifest(latestVersion: 2);
        WritePackage("v1_to_v2.delta", "6666666666666666666666666666666666666666666666666666666666666666,6,200\n", _trustedCert);

        var second = await client.CheckAndApplyAsync(CancellationToken.None);

        Assert.Equal(2, second.CurrentVersion);
        Assert.Contains("thanh cong", second.LastResult, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VersionsBehindOverThreshold_FallsBackToFullDownload()
    {
        WriteManifest(latestVersion: 50); // > 30 phien ban -> phai fallback full
        WritePackage("full_v50.full", "3333333333333333333333333333333333333333333333333333333333333333,3,255\n", _trustedCert);

        var client = CreateClient();
        var status = await client.CheckAndApplyAsync(CancellationToken.None);

        Assert.Equal(50, status.CurrentVersion);
    }

    // ERR-UPD-01 (so tay loi): goi ky sai chu ky phai bi TU CHOI, KHONG duoc ap dung.
    [Fact]
    public async Task PackageSignedByWrongCertificate_IsRejected_VersionDoesNotAdvance()
    {
        WriteManifest(latestVersion: 1);
        WritePackage("v0_to_v1.delta", "4444444444444444444444444444444444444444444444444444444444444444,4,200\n", _wrongCert);

        var client = CreateClient();
        var status = await client.CheckAndApplyAsync(CancellationToken.None);

        Assert.Equal(0, status.CurrentVersion); // khong tang vi chu ky khong hop le
    }

    // [KIEM THU HOI QUY] Regression cho bug da sua: accumulator CSV truoc
    // day CHI noi (append) du lieu delta moi vao cuoi danh sach da doc tu
    // dia, roi ghi lai TRUOC KHI biet RebuildAndSwap co thanh cong hay
    // khong. Neu client retry cung khoang phien ban (vi du sau khi
    // RebuildAndSwap that bai o lan truoc — version.json chua duoc cap
    // nhat nen van coi la "chua ap dung"), file accumulator da chua san du
    // lieu cua chinh goi delta do TU LAN TRUOC se bi doc lai, roi CUNG mot
    // goi delta duoc tai/gop them MOT LAN NUA — hash bi nhan doi. Test nay
    // gia lap dung tinh huong do bang cach GIEO SAN accumulator.csv voi noi
    // dung giong het goi delta se duoc tai (mo phong "lan chay truoc da ghi
    // roi nhung chua kip SaveCurrentVersion"), roi chay CheckAndApplyAsync
    // — xac nhan file CSV KET QUA khong bi nhan doi dong cho cung mot hash.
    [Fact]
    public async Task RetryAfterPartialWrite_AccumulatorCsvDoesNotDuplicateHash()
    {
        const string hashLine = "9999999999999999999999999999999999999999999999999999999999999999,9,200";
        WriteManifest(latestVersion: 1);
        WritePackage("v0_to_v1.delta", hashLine + "\n", _trustedCert);

        var accumulatorPath = Path.Combine(_tempDir, "accumulator.csv");
        File.WriteAllText(accumulatorPath, hashLine + "\n");

        var client = CreateClient();
        var status = await client.CheckAndApplyAsync(CancellationToken.None);

        Assert.Equal(1, status.CurrentVersion);
        var finalLines = File.ReadAllLines(accumulatorPath)
            .Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
        Assert.Single(finalLines); // khong duoc nhan doi dong cho cung mot hash
    }

    public void Dispose()
    {
        _engine.Dispose();
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }
}
