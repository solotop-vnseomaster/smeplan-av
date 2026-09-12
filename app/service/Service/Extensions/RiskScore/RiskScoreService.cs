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
    private readonly Antivirus.Service.Security.ProtectionStatusService _protectionStatus;

    public RiskScoreService(QuarantineManager quarantine, ConnectionMonitor connectionMonitor,
        RansomwareGuardService ransomwareGuard, UsbMonitorService usbMonitor,
        VulnerabilityScanService vulnerabilityScan, UpdateClientService updateService,
        Antivirus.Service.Security.ProtectionStatusService protectionStatus)
    {
        _quarantine = quarantine;
        _connectionMonitor = connectionMonitor;
        _ransomwareGuard = ransomwareGuard;
        _usbMonitor = usbMonitor;
        _vulnerabilityScan = vulnerabilityScan;
        _updateService = updateService;
        _protectionStatus = protectionStatus;
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

        // [SUA LOI NGHIEM TRONG] TRUOC DAY dong nay ghi CUNG 0 diem tru kem
        // chu thich "Dang bat (khong co co che tat trong ban nay)". Khang dinh
        // do sai: cac tang bao ve VAN TAT duoc — chi la khong qua mot cai
        // toggle, ma vi chung KHONG KHOI DONG DUOC (vi du
        // Win32_ProcessStartTrace bao Access denied khi service khong chay
        // quyen Administrator, CSDL chu ky khong nap duoc, kenh cap nhat
        // dong...).
        //
        // Hau qua nhin thay truc tiep tren man hinh: the "Tong quan bao ve"
        // bao "KHÔNG được bảo vệ" (do), the ngay ben duoi bao "100 — An toàn —
        // mọi lớp bảo vệ đều ổn" (xanh). Hai the mau thuan nhau, nguoi dung
        // khong biet tin cai nao — va cai mau xanh la cai de tin hon.
        //
        // Sua: doc tu ProtectionStatusService, dung NGUON SU THAT ma
        // /api/status dung, nen hai the khong the lech nhau nua.
        var degradations = _protectionStatus.Compute();
        var criticalLayers = degradations
            .Where(d => d.Severity == Antivirus.Service.Security.ProtectionDegradation.Critical).ToList();
        var warningLayers = degradations
            .Where(d => d.Severity == Antivirus.Service.Security.ProtectionDegradation.Warning).ToList();

        int layerDeduction = Math.Min(50, criticalLayers.Count * 25) + Math.Min(15, warningLayers.Count * 5);
        components.Add(new RiskScoreComponent
        {
            Name = "Cac tang bao ve dang hoat dong",
            PointsDeducted = layerDeduction,
            Detail = criticalLayers.Count > 0
                ? $"{criticalLayers.Count} tang KHONG hoat dong, {warningLayers.Count} tang suy giam"
                : (warningLayers.Count > 0 ? $"{warningLayers.Count} tang suy giam" : "Tat ca dang hoat dong"),
        });
        score -= layerDeduction;

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

        var (finalScore, label) = FinalizeScore(score, criticalLayers.Count > 0);
        return new RiskScoreResult { Score = finalScore, Label = label, Components = components };
    }

    // Tach rieng de kiem chung duoc bang test — day la noi giu BAT BIEN quan
    // trong nhat cua man hinh tong quan.
    //
    // BAT BIEN: khong the goi la "An toan" trong khi mot tang phong thu dang
    // CHET. Neu chi tru diem thuan tuy, mot may khong co su co nao van vuot
    // duoc SafeThreshold du process-trust da tat — dung lai chinh cai mau
    // thuan vua sua (the tren "KHÔNG được bảo vệ" do, the duoi "An toàn"
    // xanh). Ep tran diem khi co suy giam muc critical de nhan cua hai the
    // luon nhat quan.
    public static (int Score, string Label) FinalizeScore(int rawScore, bool hasCriticalLayerFailure)
    {
        int score = Math.Max(0, rawScore);
        if (hasCriticalLayerFailure)
        {
            score = Math.Min(score, WarningThreshold - 1);
        }
        string label = score >= SafeThreshold ? "An toan" : (score >= WarningThreshold ? "Can chu y" : "Rui ro cao");
        return (score, label);
    }
}
