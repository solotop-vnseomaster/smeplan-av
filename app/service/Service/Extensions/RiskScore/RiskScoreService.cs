using Antivirus.Service.Extensions.Firewall;
using Antivirus.Service.Extensions.Ransomware;
using Antivirus.Service.Extensions.Usb;
using Antivirus.Service.Extensions.Vulnerability;
using Antivirus.Service.Models;
using Antivirus.Service.Quarantine;
using Antivirus.Service.Update;

namespace Antivirus.Service.Extensions.RiskScore;

public sealed class RiskScoreComponent
{
    public required string Name { get; init; }
    public int PointsDeducted { get; init; }
    public required string Detail { get; init; }
}

public sealed class RiskScoreResult
{
    public int Score { get; init; }
    public required string Label { get; init; }
    public required List<RiskScoreComponent> Components { get; init; }
}

// "tai lieu moi.txt" muc "Trung tam canh bao va risk score tong hop":
// RiskScore = 100 - min(30, malicious dang cho x10) - min(20, firewall
// chan gan day x2) - min(15, ransomware dang theo doi x15) - min(10, USB
// la chua xu ly x5) - min(10, lo hong nghiem trong chua va x2) - (10 neu
// real-time tat) - (5 neu CSDL qua han).
//
// [QUYET DINH TRIEN KHAI] Cong thuc goc dung 7 tin hieu; ba trong so do
// khong co nguon du lieu THAT tuong ung 1-1 trong codebase nay, xu ly nhu
// sau (giu dung Y NGHIA cua tung thanh phan, khong bo qua thanh phan nao):
//   - "malicious dang cho xu ly": khong co trang thai QuarantineStatus nao
//     dai dien dung "malicious nhung CHUA duoc nguoi dung xu ly" ngoai
//     PendingManualConfirmation (file trong thu muc he thong duoc bao ve,
//     KHONG tu dong quarantine — dung cho "dang cho" nhat). File da bi
//     chuyen vao quarantine (status Quarantined) coi nhu DA duoc xu ly
//     (da bi cach ly), khong tinh vao day.
//   - "firewall chan gan day": khong co bo dem chan ket noi that (khong co
//     WFP kernel enforcement trong moi truong nay — xem ConnectionMonitor.cs).
//     Dung so beacon suspicion gan day (ConnectionMonitor) lam xap xi —
//     day la tin hieu GAN NHAT co (nghi ngo ket noi C2), khong phai dung
//     dinh nghia "da chan" nhu tai lieu mo ta.
//   - "real-time protection dang tat": KHONG co co che tat real-time
//     protection nao duoc xay trong app nay (luon bat) — thanh phan nay
//     LUON tra ve 0 diem tru, giu trong cong thuc de dung cau truc tai
//     lieu (va san sang khi/neu sau nay co toggle that).
public sealed class RiskScoreService
{
    private const int SafeThreshold = 80;
    private const int WarningThreshold = 50;

    // "CSDL qua han cap nhat" — chua qua 2 lan chu ky kiem tra mac dinh
    // (2h/lan) ma chua kiem tra duoc lan nao thanh cong coi la qua han.
    private static readonly TimeSpan UpdateOverdueThreshold = UpdateClientService.DefaultCheckInterval * 2;

    private readonly QuarantineManager _quarantine;
    private readonly ConnectionMonitor _connectionMonitor;
    private readonly RansomwareGuardService _ransomwareGuard;
    private readonly UsbMonitorService _usbMonitor;
    private readonly VulnerabilityScanService _vulnerabilityScan;
    private readonly UpdateClientService _updateService;

    public RiskScoreService(QuarantineManager quarantine, ConnectionMonitor connectionMonitor,
        RansomwareGuardService ransomwareGuard, UsbMonitorService usbMonitor,
        VulnerabilityScanService vulnerabilityScan, UpdateClientService updateService)
    {
        _quarantine = quarantine;
        _connectionMonitor = connectionMonitor;
        _ransomwareGuard = ransomwareGuard;
        _usbMonitor = usbMonitor;
        _vulnerabilityScan = vulnerabilityScan;
        _updateService = updateService;
    }

    public RiskScoreResult Compute()
    {
        var components = new List<RiskScoreComponent>();
        int score = 100;

        int pendingMalicious = _quarantine.List().Count(r => r.Status == QuarantineStatus.PendingManualConfirmation);
        int maliciousDeduction = Math.Min(30, pendingMalicious * 10);
        components.Add(new RiskScoreComponent { Name = "Threat malicious dang cho xu ly", PointsDeducted = maliciousDeduction, Detail = $"{pendingMalicious} file" });
        score -= maliciousDeduction;

        int recentFirewallSuspicions = _connectionMonitor.GetRecentSuspicions().Count;
        int firewallDeduction = Math.Min(20, recentFirewallSuspicions * 2);
        components.Add(new RiskScoreComponent { Name = "Ket noi mang dang ngo gan day", PointsDeducted = firewallDeduction, Detail = $"{recentFirewallSuspicions} ket noi" });
        score -= firewallDeduction;

        long oneHourAgoMs = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeMilliseconds();
        int recentRansomwareAlerts = _ransomwareGuard.GetRecentAlerts().Count(a => a.DetectedAtUnixMs >= oneHourAgoMs);
        int ransomwareDeduction = Math.Min(15, recentRansomwareAlerts * 15);
        components.Add(new RiskScoreComponent { Name = "Canh bao ransomware dang theo doi", PointsDeducted = ransomwareDeduction, Detail = $"{recentRansomwareAlerts} canh bao (1h gan day)" });
        score -= ransomwareDeduction;

        int unresolvedUsbDevices = _usbMonitor.GetRecentArrivals().Count(a => a.ResolvedAction == "Ask" && a.DetectedAtUnixMs >= oneHourAgoMs);
        int usbDeduction = Math.Min(10, unresolvedUsbDevices * 5);
        components.Add(new RiskScoreComponent { Name = "Thiet bi USB la chua xu ly", PointsDeducted = usbDeduction, Detail = $"{unresolvedUsbDevices} thiet bi" });
        score -= usbDeduction;

        int severeVulnerabilities = _vulnerabilityScan.GetLastFindings().Count(f => f.SeverityScore >= 7.0);
        int vulnDeduction = Math.Min(10, severeVulnerabilities * 2);
        components.Add(new RiskScoreComponent { Name = "Lo hong phan mem nghiem trong chua va", PointsDeducted = vulnDeduction, Detail = $"{severeVulnerabilities} lo hong (CVSS >= 7.0)" });
        score -= vulnDeduction;

        // Khong co toggle tat real-time protection trong app nay -> luon 0.
        components.Add(new RiskScoreComponent { Name = "Real-time protection", PointsDeducted = 0, Detail = "Dang bat (khong co co che tat trong ban nay)" });

        bool signatureOverdue = _updateService.Status.LastCheckedAt is null ||
            DateTimeOffset.UtcNow - _updateService.Status.LastCheckedAt.Value > UpdateOverdueThreshold;
        int signatureDeduction = signatureOverdue ? 5 : 0;
        components.Add(new RiskScoreComponent
        {
            Name = "CSDL virus",
            PointsDeducted = signatureDeduction,
            Detail = signatureOverdue ? "Qua han kiem tra cap nhat" : $"Da kiem tra luc {_updateService.Status.LastCheckedAt:HH:mm dd/MM}",
        });
        score -= signatureDeduction;

        score = Math.Max(0, score);
        string label = score >= SafeThreshold ? "An toan" : (score >= WarningThreshold ? "Can chu y" : "Rui ro cao");

        return new RiskScoreResult { Score = score, Label = label, Components = components };
    }
}
