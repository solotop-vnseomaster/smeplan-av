using Antivirus.Service.Extensions.Sandbox;
using Antivirus.Service.Models;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Quyet dinh ket luan tu ket qua sandbox".
public class SandboxVerdictAggregatorTests
{
    private readonly SandboxVerdictAggregator _aggregator = new();

    [Fact]
    public void NoApiCallsAtAll_ReturnsSuspicious_NotClean_WithNoBehaviorFlag()
    {
        var result = _aggregator.Evaluate(new List<ObservedApiCall>());

        Assert.Equal(ScanVerdict.Suspicious, result.Verdict);
        Assert.True(result.NoBehaviorObserved);
    }

    [Fact]
    public void OnlyBenignFileWrites_ReturnsSuspicious_NoBehaviorFlag_NotClean()
    {
        var calls = new List<ObservedApiCall>
        {
            new("WriteFile", ObservedApiCategory.FileWrite, 1000, null),
            new("CreateFileW", ObservedApiCategory.FileWrite, 1001, null),
        };

        var result = _aggregator.Evaluate(calls);

        Assert.Equal(ScanVerdict.Suspicious, result.Verdict);
        Assert.True(result.NoBehaviorObserved);
        Assert.Equal(0, result.Score);
    }

    [Fact]
    public void InjectionCombo_Alone_ScoresHighButBelowMaliciousThreshold()
    {
        // To hop injection mot minh cong 60 diem, nguong Malicious la 70 —
        // can them mot tin hieu khac (vi du autorun) moi vuot nguong, dung
        // "Score = sự cộng dồn của NHIỀU nhóm hành vi", khong phải một
        // nhóm duy nhất luôn tự đủ để kết luận Malicious.
        var calls = new List<ObservedApiCall>
        {
            new("WriteProcessMemory", ObservedApiCategory.ProcessInjection, 1000, null),
            new("CreateRemoteThread", ObservedApiCategory.ProcessInjection, 1010, null),
        };

        var result = _aggregator.Evaluate(calls);

        Assert.Equal(ScanVerdict.Suspicious, result.Verdict);
        Assert.False(result.NoBehaviorObserved);
        Assert.Equal(60, result.Score);
    }

    [Fact]
    public void OnlyWriteProcessMemory_WithoutCreateRemoteThread_DoesNotTriggerInjectionScore()
    {
        var calls = new List<ObservedApiCall>
        {
            new("WriteProcessMemory", ObservedApiCategory.ProcessInjection, 1000, null),
        };

        var result = _aggregator.Evaluate(calls);

        // Khong co to hop day du -> khong hanh vi dang chu y -> "khong quan
        // sat duoc", KHONG phai Malicious.
        Assert.True(result.NoBehaviorObserved);
    }

    [Fact]
    public void RegistryAutorunWrite_Alone_ReturnsSuspicious_NotMalicious()
    {
        var calls = new List<ObservedApiCall>
        {
            new("RegSetValueExW", ObservedApiCategory.RegistryAutorun, 1000, @"HKCU\...\Run"),
        };

        var result = _aggregator.Evaluate(calls);

        Assert.Equal(ScanVerdict.Suspicious, result.Verdict);
        Assert.False(result.NoBehaviorObserved);
        Assert.Equal(25, result.Score);
    }

    [Fact]
    public void NetworkBurst_FiveCallsWithinFiveSeconds_TriggersNetworkScore()
    {
        var calls = new List<ObservedApiCall>();
        for (int i = 0; i < 5; i++)
        {
            calls.Add(new("connect", ObservedApiCategory.Network, 1000 + i * 500, $"1.2.3.{i}"));
        }

        var result = _aggregator.Evaluate(calls);

        Assert.False(result.NoBehaviorObserved);
        Assert.Equal(10, result.Score);
        Assert.Equal(ScanVerdict.Suspicious, result.Verdict); // duoi nguong Malicious (70)
    }

    [Fact]
    public void SparseNetworkCalls_OutsideBurstWindow_DoesNotTriggerScore()
    {
        var calls = new List<ObservedApiCall>
        {
            new("connect", ObservedApiCategory.Network, 1000, "1.2.3.4"),
            new("connect", ObservedApiCategory.Network, 20000, "1.2.3.5"),
        };

        var result = _aggregator.Evaluate(calls);

        Assert.True(result.NoBehaviorObserved);
    }

    [Fact]
    public void CombinedInjectionAndAutorun_ScoresAdditively_AboveMaliciousThreshold()
    {
        var calls = new List<ObservedApiCall>
        {
            new("WriteProcessMemory", ObservedApiCategory.ProcessInjection, 1000, null),
            new("CreateRemoteThread", ObservedApiCategory.ProcessInjection, 1010, null),
            new("RegSetValueExW", ObservedApiCategory.RegistryAutorun, 1020, @"HKCU\...\Run"),
        };

        var result = _aggregator.Evaluate(calls);

        Assert.Equal(85, result.Score);
        Assert.Equal(ScanVerdict.Malicious, result.Verdict);
        Assert.Equal(2, result.Reasons.Count);
    }
}
