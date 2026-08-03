using Antivirus.Service.Models;

namespace Antivirus.Service.Extensions.Sandbox;

public enum ObservedApiCategory { FileWrite, Network, ProcessInjection, RegistryAutorun }

public sealed record ObservedApiCall(string ApiName, ObservedApiCategory Category, long TimestampMs, string? Detail);

public sealed class SandboxVerdictResult
{
    public required ScanVerdict Verdict { get; init; }
    public int Score { get; init; }
    public required List<string> Reasons { get; init; }

    // "khong quan sat duoc hanh vi dang chu y nao... KHONG nen tu dong nang
    // len Clean chi vi sandbox khong thay gi bat thuong trong khung thoi
    // gian quan sat co han cua no" — caller (correlator) phai KET HOP voi
    // ket luan tu hash/YARA/heuristic da dua file vao hang doi sandbox
    // thay vi tu quyet dinh Clean chi dua tren co field nay.
    public bool NoBehaviorObserved { get; init; }
}

// "tai lieu moi.txt" muc "Quyet dinh ket luan tu ket qua sandbox": weighted
// score tu danh sach API call quan sat duoc trong sandbox, giu nguyen 4
// trang thai ScanVerdict da co (khong tao tap trang thai rieng cho sandbox).
public sealed class SandboxVerdictAggregator
{
    private const int MaliciousThreshold = 70;

    // "to hop injection... cong diem CAO NHAT vi hiem khi xuat hien o phan
    // mem hop le"
    private const int InjectionComboScore = 60;

    // "ghi vao khoa registry autorun cong diem TRUNG BINH"
    private const int RegistryAutorunScore = 25;

    // "ket noi mang ra ngoai voi tan suat cao trong thoi gian ngan cong
    // diem THAP HON (vi nhieu phan mem hop le cung goi API cap nhat khi
    // khoi dong lan dau)"
    private const int NetworkBurstScore = 10;
    private const int NetworkBurstMinCallsInWindow = 5;
    private static readonly TimeSpan NetworkBurstWindow = TimeSpan.FromSeconds(5);

    public SandboxVerdictResult Evaluate(IReadOnlyList<ObservedApiCall> calls)
    {
        if (calls.Count == 0)
        {
            return NoBehaviorResult("Khong quan sat duoc bat ky loi goi API nao trong suot thoi gian detonation (30-60 giay)");
        }

        int score = 0;
        var reasons = new List<string>();

        bool hasWriteProcessMemory = calls.Any(c => c.Category == ObservedApiCategory.ProcessInjection &&
            c.ApiName.Equals("WriteProcessMemory", StringComparison.OrdinalIgnoreCase));
        bool hasCreateRemoteThread = calls.Any(c => c.Category == ObservedApiCategory.ProcessInjection &&
            c.ApiName.Equals("CreateRemoteThread", StringComparison.OrdinalIgnoreCase));
        if (hasWriteProcessMemory && hasCreateRemoteThread)
        {
            score += InjectionComboScore;
            reasons.Add("To hop WriteProcessMemory + CreateRemoteThread trong cung phien detonation — dau hieu process injection kinh dien");
        }

        bool autorunWrite = calls.Any(c => c.Category == ObservedApiCategory.RegistryAutorun);
        if (autorunWrite)
        {
            score += RegistryAutorunScore;
            reasons.Add("Ghi vao khoa registry autorun da biet — dau hieu co gang duy tri su ton tai sau khoi dong lai");
        }

        var networkCalls = calls.Where(c => c.Category == ObservedApiCategory.Network).OrderBy(c => c.TimestampMs).ToList();
        if (HasNetworkBurst(networkCalls, out int burstCount))
        {
            score += NetworkBurstScore;
            reasons.Add($"Ket noi mang ra ngoai voi tan suat cao ({burstCount} lan trong {NetworkBurstWindow.TotalSeconds:0}s)");
        }

        if (score == 0)
        {
            return NoBehaviorResult("Co ghi nhan loi goi API nhung khong hanh vi nao thuoc nhom dang chu y (injection/autorun/network-burst)");
        }

        var verdict = score >= MaliciousThreshold ? ScanVerdict.Malicious : ScanVerdict.Suspicious;
        return new SandboxVerdictResult { Verdict = verdict, Score = score, Reasons = reasons, NoBehaviorObserved = false };
    }

    private static SandboxVerdictResult NoBehaviorResult(string reason) => new()
    {
        // "khong nen mac dinh la Clean ma nen la mot trang thai YEU HON" —
        // dung Suspicious (yeu hon Malicious, khac Clean) kem co
        // NoBehaviorObserved=true de caller biet day la "khong thay gi" chu
        // khong phai "thay dau hieu ro rang o muc thap".
        Verdict = ScanVerdict.Suspicious,
        Score = 0,
        Reasons = new List<string> { reason },
        NoBehaviorObserved = true,
    };

    private static bool HasNetworkBurst(List<ObservedApiCall> networkCallsSorted, out int burstCount)
    {
        for (int i = 0; i < networkCallsSorted.Count; i++)
        {
            int count = 1;
            for (int j = i + 1; j < networkCallsSorted.Count; j++)
            {
                if (networkCallsSorted[j].TimestampMs - networkCallsSorted[i].TimestampMs <= NetworkBurstWindow.TotalMilliseconds) count++;
                else break;
            }
            if (count >= NetworkBurstMinCallsInWindow)
            {
                burstCount = count;
                return true;
            }
        }
        burstCount = 0;
        return false;
    }
}
