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

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
        try { File.Delete(_exePath); } catch { }
    }
}
