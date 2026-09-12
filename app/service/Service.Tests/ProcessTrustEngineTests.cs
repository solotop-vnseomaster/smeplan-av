using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Models;
using Antivirus.Service.Trust;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// business-rules/05 muc "Quyet dinh cap quyen cho tien trinh moi" (BIZ-04),
// nfr/06 NFR-AVAIL-03: "mac dinh deny-and-log khi service khong phan hoi
// kip", KHONG duoc mac dinh Allowed khi het timeout.
public class ProcessTrustEngineTests : IDisposable
{
    private readonly string _dbPath;
    private readonly string _exePath;
    private readonly RuleStore _rules;
    private readonly PermissionRequestBroker _broker;
    private readonly AuditLogger _audit;

    public ProcessTrustEngineTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_trust_{Guid.NewGuid():N}.db");
        _rules = new RuleStore(_dbPath);
        _broker = new PermissionRequestBroker();
        _audit = new AuditLogger(Path.Combine(Path.GetTempPath(), $"avtest_audit_{Guid.NewGuid():N}.jsonl"));

        // Mot file "thuc thi" gia, khong ky so, khong nam trong thu muc
        // trusted -> chac chan roi vao PendingUserDecision.
        _exePath = Path.Combine(Path.GetTempPath(), $"avtest_unsigned_{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(_exePath, new byte[] { 0x4D, 0x5A, 0x00, 0x00 }); // header MZ toi gian, khong phai PE hop le
    }

    [Fact]
    public async Task UnknownUnsignedFile_NoResponse_DeniedByTimeout_NotAllowed()
    {
        // Timeout rat ngan de test chay nhanh — hanh vi giong het timeout
        // 30s that, chi rut ngan thoi gian cho.
        var engine = new ProcessTrustEngine(_rules, _broker, _audit,
            NullLogger<ProcessTrustEngine>.Instance, userDecisionTimeout: TimeSpan.FromMilliseconds(300));

        var decision = await engine.EvaluateAsync(_exePath, 1234, CancellationToken.None);

        Assert.Equal(ProcessTrustState.DeniedByTimeout, decision.State);
        Assert.False(decision.Allowed); // NFR-AVAIL-03: khong duoc allow mu khi het timeout
    }

    [Fact]
    public async Task RuleAllowByHash_TakesPrecedence_SkipsUserPrompt()
    {
        var engine = new ProcessTrustEngine(_rules, _broker, _audit, NullLogger<ProcessTrustEngine>.Instance);
        var hash = System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(_exePath));
        var hashHex = Convert.ToHexString(hash).ToLowerInvariant();

        _rules.Add(new AppRule
        {
            Sha256Hash = hashHex, FilePath = _exePath, Action = RuleAction.Allow,
            Scope = RuleScope.Hash, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });

        var decision = await engine.EvaluateAsync(_exePath, 1234, CancellationToken.None);

        Assert.Equal(ProcessTrustState.RuleAllow, decision.State);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public async Task UserChoosesAllowAlways_PersistsRule()
    {
        var engine = new ProcessTrustEngine(_rules, _broker, _audit,
            NullLogger<ProcessTrustEngine>.Instance, userDecisionTimeout: TimeSpan.FromSeconds(5));

        var evalTask = engine.EvaluateAsync(_exePath, 1234, CancellationToken.None);

        // Doi request xuat hien roi tra loi "Cho phep luon" nhu UI se lam.
        PendingPermissionRequest? request = null;
        for (int i = 0; i < 50 && request is null; i++)
        {
            request = _broker.ListPending().FirstOrDefault();
            if (request is null) await Task.Delay(20);
        }
        Assert.NotNull(request);
        _broker.Respond(request!.RequestId, UserPermissionChoice.AllowAlways);

        var decision = await evalTask;

        Assert.Equal(ProcessTrustState.AllowedAlways, decision.State);
        Assert.True(decision.Allowed);
        Assert.NotNull(_rules.FindByHash(decision.Sha256));
    }

    // Regression cho bug da sua: ComputeSha256 tra ve "" khi hash that bai
    // (file bi khoa doc doc quyen boi tien trinh khac). Truoc day rule
    // AllowAlways duoc luu voi Sha256Hash="" thi BAT KY file khac nao ma
    // hash cung that bai se khop nham vao rule "cho phep" do (FindByHash("")).
    // Test nay xac nhan: (1) khong luu rule scope=hash rong, (2) mot file
    // KHAC hoan toan (khong lien quan) ma hash cung that bai KHONG duoc tu
    // dong allow qua rule cu.
    [Fact]
    public async Task HashComputationFails_AllowAlways_DoesNotCreateEmptyHashRule()
    {
        var engine = new ProcessTrustEngine(_rules, _broker, _audit,
            NullLogger<ProcessTrustEngine>.Instance, userDecisionTimeout: TimeSpan.FromSeconds(5));

        using var lockHandle = new FileStream(_exePath, FileMode.Open, FileAccess.Read, FileShare.None);

        var evalTask = engine.EvaluateAsync(_exePath, 1234, CancellationToken.None);

        PendingPermissionRequest? request = null;
        for (int i = 0; i < 50 && request is null; i++)
        {
            request = _broker.ListPending().FirstOrDefault();
            if (request is null) await Task.Delay(20);
        }
        Assert.NotNull(request);
        _broker.Respond(request!.RequestId, UserPermissionChoice.AllowAlways);

        var decision = await evalTask;

        Assert.Equal("", decision.Sha256);
        Assert.Null(_rules.FindByHash(""));

        // Mot file KHAC hoan toan, khong lien quan, ma hash cung that bai
        // (gia lap bang cach danh gia lai chinh file dang bi khoa) KHONG
        // duoc phep tu dong Allow qua rule rong cu — phai lai roi vao
        // PendingUserDecision/timeout nhu binh thuong.
        var secondEvalTask = engine.EvaluateAsync(_exePath, 5678, CancellationToken.None);
        PendingPermissionRequest? secondRequest = null;
        for (int i = 0; i < 50 && secondRequest is null; i++)
        {
            secondRequest = _broker.ListPending().FirstOrDefault();
            if (secondRequest is null) await Task.Delay(20);
        }
        Assert.NotNull(secondRequest);
        _broker.Respond(secondRequest!.RequestId, UserPermissionChoice.Block);
        var secondDecision = await secondEvalTask;
        Assert.False(secondDecision.Allowed);
    }

    // [test-coverage] Chi co RuleAllow duoc test truoc day — neu logic dao
    // Allow/Block bi loi (vi du gan nham ruleByHash.Action == RuleAction.Allow
    // thanh != ), khong test nao bat duoc. Doi xung voi RuleAllowByHash o tren.
    [Fact]
    public async Task RuleBlockByHash_TakesPrecedence_SkipsUserPrompt()
    {
        var engine = new ProcessTrustEngine(_rules, _broker, _audit, NullLogger<ProcessTrustEngine>.Instance);
        var hash = System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(_exePath));
        var hashHex = Convert.ToHexString(hash).ToLowerInvariant();

        _rules.Add(new AppRule
        {
            Sha256Hash = hashHex, FilePath = _exePath, Action = RuleAction.Block,
            Scope = RuleScope.Hash, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });

        var decision = await engine.EvaluateAsync(_exePath, 1234, CancellationToken.None);

        Assert.Equal(ProcessTrustState.RuleBlock, decision.State);
        Assert.False(decision.Allowed);
    }

    // [test-coverage] FindByPublisher / RuleAllow-Block theo publisher chua
    // tung duoc test — dung mot ban sao mot file he thong CO CHU KY
    // AUTHENTICODE NHUNG VAO (khong phai chi catalog-signed — xem
    // AuthenticodeVerifier.Verify: publisher/thumbprint doc qua
    // X509Certificate.CreateFromSignedFile, CHI hoat dong voi chu ky nhung
    // vao file, notepad.exe/cmd.exe tren Windows hien dai la catalog-signed
    // nen KHONG dung duoc cho muc dich nay) dat NGOAI cac thu muc
    // trusted-by-default (Windows/Program Files) de bat buoc engine roi
    // xuong nhanh kiem tra rule-theo-publisher thay vi trusted-by-default
    // hay rule-theo-hash. svchost.exe/explorer.exe on dinh la nhung file
    // nhung vao tren moi ban Windows hien dai.
    private static readonly string[] EmbeddedSignedCandidates =
    {
        @"C:\Windows\System32\svchost.exe",
        @"C:\Windows\explorer.exe",
        @"C:\Program Files\Windows Defender\MpCmdRun.exe",
    };

    private static string? CopySignedSystemBinaryOutsideTrustedDir()
    {
        foreach (var source in EmbeddedSignedCandidates)
        {
            if (!File.Exists(source)) continue;
            try
            {
#pragma warning disable SYSLIB0057
                using var probe = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(source);
#pragma warning restore SYSLIB0057
            }
            catch
            {
                continue; // khong co chu ky nhung vao (chi catalog) — thu file khac
            }

            var destDir = Directory.CreateTempSubdirectory("avtest_signed_copy_").FullName;
            var dest = Path.Combine(destDir, Path.GetFileName(source));
            File.Copy(source, dest);
            return dest;
        }
        return null;
    }

    [Fact]
    public async Task RuleBlockByPublisher_AppliesForSignedFileOutsideTrustedDirectory_WhenNoHashRuleExists()
    {
        var signedPath = CopySignedSystemBinaryOutsideTrustedDir();
        if (signedPath is null) return; // khong tim thay file nao co chu ky nhung vao tren may nay — bo qua

        try
        {
            // Chay lan dau KHONG co rule nao de lay PublisherThumbprint THAT
            // tu chu ky Authenticode cua ban sao file he thong (van hop le
            // du duong dan khong con nam trong thu muc trusted).
            var probeEngine = new ProcessTrustEngine(_rules, _broker, _audit,
                NullLogger<ProcessTrustEngine>.Instance, userDecisionTimeout: TimeSpan.FromMilliseconds(200));
            var probeDecision = await probeEngine.EvaluateAsync(signedPath, 1111, CancellationToken.None);
            Assert.Equal(ProcessTrustState.DeniedByTimeout, probeDecision.State);
            Assert.False(string.IsNullOrEmpty(probeDecision.PublisherThumbprint));

            _rules.Add(new AppRule
            {
                Sha256Hash = "",
                PublisherThumbprint = probeDecision.PublisherThumbprint,
                FilePath = signedPath,
                Action = RuleAction.Block,
                Scope = RuleScope.Publisher,
                CreatedAt = 1,
                CreatedBy = RuleCreatedBy.User,
            });

            var engine = new ProcessTrustEngine(_rules, _broker, _audit, NullLogger<ProcessTrustEngine>.Instance);
            var decision = await engine.EvaluateAsync(signedPath, 2222, CancellationToken.None);

            Assert.Equal(ProcessTrustState.RuleBlock, decision.State);
            Assert.False(decision.Allowed);
        }
        finally
        {
            try { Directory.Delete(Path.GetDirectoryName(signedPath)!, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task RuleAllowByPublisher_AppliesForSignedFileOutsideTrustedDirectory_WhenNoHashRuleExists()
    {
        var signedPath = CopySignedSystemBinaryOutsideTrustedDir();
        if (signedPath is null) return; // khong tim thay file nao co chu ky nhung vao tren may nay — bo qua

        try
        {
            var probeEngine = new ProcessTrustEngine(_rules, _broker, _audit,
                NullLogger<ProcessTrustEngine>.Instance, userDecisionTimeout: TimeSpan.FromMilliseconds(200));
            var probeDecision = await probeEngine.EvaluateAsync(signedPath, 1111, CancellationToken.None);
            Assert.False(string.IsNullOrEmpty(probeDecision.PublisherThumbprint));

            _rules.Add(new AppRule
            {
                Sha256Hash = "",
                PublisherThumbprint = probeDecision.PublisherThumbprint,
                FilePath = signedPath,
                Action = RuleAction.Allow,
                Scope = RuleScope.Publisher,
                CreatedAt = 1,
                CreatedBy = RuleCreatedBy.User,
            });

            var engine = new ProcessTrustEngine(_rules, _broker, _audit, NullLogger<ProcessTrustEngine>.Instance);
            var decision = await engine.EvaluateAsync(signedPath, 2222, CancellationToken.None);

            Assert.Equal(ProcessTrustState.RuleAllow, decision.State);
            Assert.True(decision.Allowed);
        }
        finally
        {
            try { Directory.Delete(Path.GetDirectoryName(signedPath)!, recursive: true); } catch { }
        }
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
        try { File.Delete(_exePath); } catch { }
    }
}
