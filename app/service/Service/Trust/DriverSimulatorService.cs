using System.Management;
using Antivirus.Service.Models;
using Antivirus.Service.Audit;

namespace Antivirus.Service.Trust;

// [HAN CHE DA BIET] Day KHONG PHAI la minifilter/driver that. Minifilter
// kernel-mode that (xem app/drivers/minifilter) chan IRP_MJ_CREATE DONG BO
// TRUOC khi tien trinh chay dong lenh dau tien (PsSetCreateProcessNotifyRoutineEx),
// nen co the tu choi tao tien trinh hoan toan. Lop nay chi dung
// Win32_ProcessStartTrace (WMI) — mot API user-mode CO THAT tren Windows —
// de quan sat tien trinh MOI DA duoc tao, roi goi sang ProcessTrustEngine
// giong het luong that (FLOW-01), va neu quyet dinh la Block thi co gang
// Kill() tien trinh do NHU MOT BIEN PHAP GIAM THIEU HAU KHOI TAO — yeu hon
// han so voi chan truoc khi tao. Muc dich: minh hoa dung end-to-end luong
// nghiep vu Process Trust Decision trong moi truong khong co WDK/driver ky so.
public sealed class DriverSimulatorService : BackgroundService
{
    private readonly ProcessTrustEngine _trustEngine;
    private readonly AuditLogger _audit;
    private readonly Antivirus.Service.Extensions.EventBus _eventBus;
    private readonly ILogger<DriverSimulatorService> _logger;
    private ManagementEventWatcher? _watcher;

    // [SUA LOI NGHIEM TRONG] Xem ExecuteAsync: khi Win32_ProcessStartTrace
    // khong khoi dong duoc (thuong xuyen — can quyen Administrator), TOAN BO
    // tang danh gia tin cay tien trinh khong chay, va truoc day dieu do chi
    // nam trong MOT dong log warn luc khoi dong roi bien mat. Khong mot API
    // nao phoi ra, nen UI khong the biet va nguoi dung tin rang tien trinh
    // moi dang duoc kiem tra. Phoi trang thai ra de /api/status bao cao.
    public bool IsWatchingProcessCreation { get; private set; }
    public string? StartupFailureReason { get; private set; }

    public DriverSimulatorService(ProcessTrustEngine trustEngine, AuditLogger audit,
        Antivirus.Service.Extensions.EventBus eventBus, ILogger<DriverSimulatorService> logger)
    {
        _trustEngine = trustEngine;
        _audit = audit;
        _eventBus = eventBus;
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            _watcher = new ManagementEventWatcher(query);
            _watcher.EventArrived += OnProcessStarted;
            _watcher.Start();
            IsWatchingProcessCreation = true;
            _logger.LogInformation(
                "Driver-simulation (Win32_ProcessStartTrace) da khoi dong — CHU Y: day la fallback " +
                "user-mode, khong thay the minifilter kernel-mode that (xem app/drivers/minifilter).");
            _audit.Log("process-trust",
                "Driver-simulation user-mode da khoi dong (khong phai kernel minifilter that — han che moi truong)");
        }
        catch (Exception ex)
        {
            IsWatchingProcessCreation = false;
            StartupFailureReason = $"{ex.GetType().Name}: {ex.Message}";

            // Nang tu LogWarning len LogError va ghi audit: mot tang bao ve
            // KHONG chay la su kien can dieu tra, khong phai ghi chu ben le.
            _logger.LogError(ex,
                "Khong khoi dong duoc Win32_ProcessStartTrace (thuong can quyen Administrator) — " +
                "TANG DANH GIA TIN CAY TIEN TRINH KHONG HOAT DONG. " +
                "Luong Process Trust Decision chi con goi duoc thu cong qua API /api/trust/evaluate.");
            _audit.Log("process-trust",
                "TANG DANH GIA TIN CAY TIEN TRINH KHONG KHOI DONG DUOC: " + StartupFailureReason +
                " — tien trinh moi KHONG duoc kiem tra");
        }

        return Task.CompletedTask;
    }

    private async void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            string processName = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? "";
            int pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);

            string? fullPath = TryResolveFullPath(pid, processName);
            if (fullPath is null) return;

            // [SUA LOI NGHIEM TRONG — GUARD DUNG, TRUOC DAY AP THIEU DUONG]
            // PathUtil.IsLocalDrivePath duoc goi o 3 endpoint /api/* de chan
            // forced-authentication/NTLM-relay, nhung KHONG o day. Mot tien
            // trinh chay TRUC TIEP tu UNC share (\\host\share\x.exe — hoan
            // toan hop le tren Windows) lam MainModule.FileName tra ve chinh
            // duong dan UNC do, va ProcessTrustEngine.EvaluateAsync sau do se
            // mo file de bam hash + kiem tra chu ky. Tien trinh service chay
            // quyen SYSTEM, nen viec cham vao duong dan do ep may tu xac thuc
            // NTLM toi may chu ma KE TAN CONG chon — chi can ho khoi chay
            // duoc mot tien trinh tu share cua ho.
            if (!Antivirus.Service.Common.PathUtil.IsLocalDrivePath(fullPath))
            {
                _logger.LogWarning(
                    "Bo qua danh gia tin cay cho PID {Pid} ({Path}): tien trinh chay tu duong dan " +
                    "khong phai o dia cuc bo — KHONG cham vao duong dan de tranh forced authentication",
                    pid, fullPath);
                _audit.Log("process-trust",
                    $"BO QUA danh gia tin cay {fullPath} (PID {pid}) — duong dan khong phai o dia cuc bo (chan NTLM-relay)");
                return;
            }

            var decision = await _trustEngine.EvaluateAsync(fullPath, pid, CancellationToken.None);
            if (!decision.Allowed)
            {
                // [SUA LOI NGHIEM TRONG] Kill() duoi quyen LocalSystem la mot
                // hanh dong KHONG HOAN TAC DUOC va duoc thuc hien tren tung
                // tien trinh MOI khoi chay. Truoc day no chay cho MOI ket qua
                // khong-Allowed, ke ca ket qua ma chinh chung ta khong ket
                // luan duoc: khi WinVerifyTrust het deadline (proxy doanh
                // nghiep chan CRL/OCSP, DNS cham), moi nhi phan hop le deu roi
                // vao nhanh nay CUNG MOT LUC. Do la mot su co mang bien thanh
                // mot dot giet tien trinh hang loat tren may nguoi dung.
                //
                // Khi chuoi chung thu CHUA duoc xac minh xong, "khong cho
                // phep" chi co nghia la "chua du co so de cho phep" — no
                // KHONG phai co so de giet. Ghi audit that ro va de tien
                // trinh chay tiep; lan danh gia sau (khi mang binh thuong
                // tro lai) se cho ket luan that.
                // [SUA LOI CHAN PHAT HANH — QUAN SAT DUOC TREN MAY THAT]
                //
                // TRUOC DAY moi ket qua khong-Allowed deu di thang toi
                // proc.Kill() duoi quyen LocalSystem, KE CA DeniedByTimeout.
                //
                // Voi minifilter kernel that, "deny" nghia la TU CHOI TAO
                // tien trinh — sai thi nguoi dung chi thay app khong mo len.
                // Nhung lop mo phong user-mode nay chay SAU khi tien trinh da
                // duoc tao, nen cung mot chu "deny" o day nghia la GIET MOT
                // TIEN TRINH DANG CHAY. Chinh sach deny-and-log cua
                // NFR-AVAIL-03 duoc ke thua nguyen xi tu thiet ke driver ma
                // khong tinh toi khac biet do.
                //
                // DeniedByTimeout xay ra khi khong ai tra loi hop thoai xin
                // quyen trong 30 giay — ma hop thoai do doi dashboard dang mo
                // va nguoi dung dang nhin. Service chay nen thi dieu do gan
                // nhu khong bao gio dung. Do trong mot lan chay that: moi
                // tien trinh Chrome deu bi Kill() sau dung 30 giay, 5 lan lien
                // tiep. Moi ung dung KHONG PHAI Microsoft (Chrome, VS Code,
                // Git...) deu chung so phan.
                //
                // Sua (theo quyet dinh cua chu san pham): CHI giet khi co mot
                // ket luan DUT KHOAT — rule Block tuong minh, hoac nguoi dung
                // bam "Chan". Het thoi gian cho KHONG phai ket luan; khi do
                // ghi audit + phat canh bao len Alert Center va DE TIEN TRINH
                // CHAY TIEP.
                if (!IsExplicitBlockDecision(decision.State))
                {
                    _logger.LogWarning(
                        "KHONG chan PID {Pid} ({Path}): trang thai {State} khong phai mot ket luan dut khoat " +
                        "(khong co rule Block va nguoi dung chua tra loi). Ghi nhan de xem xet thay vi giet tien trinh.",
                        pid, fullPath, decision.State);
                    _audit.Log("process-trust",
                        $"KHONG chan {fullPath} (PID {pid}): {decision.State} — {decision.Reason}. " +
                        "Chi Kill() khi co rule Block tuong minh hoac nguoi dung bam 'Chan'.");
                    _eventBus.Publish(new Antivirus.Service.Extensions.CorrelationEvent
                    {
                        EntityKey = string.IsNullOrEmpty(decision.Sha256) ? $"file:{fullPath}" : $"sha256:{decision.Sha256}",
                        SourceEngine = "process-trust",
                        Severity = 45,
                        Summary = $"Tiến trình chưa được cấp quyền vẫn đang chạy: {System.IO.Path.GetFileName(fullPath)} "
                                + "— chưa ai trả lời yêu cầu cấp quyền, tiến trình KHÔNG bị chặn.",
                        TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    });
                    return;
                }

                if (!decision.ChainVerificationCompleted)
                {
                    _logger.LogWarning(
                        "KHONG chan PID {Pid} ({Path}): chua xac minh xong chuoi chung thu (het thoi gian cho " +
                        "WinVerifyTrust — thuong do CRL/OCSP bi chan). Khong ket luan duoc thi khong giet tien trinh.",
                        pid, fullPath);
                    _audit.Log("process-trust",
                        $"KHONG chan {fullPath} (PID {pid}): xac minh chu ky CHUA hoan tat (timeout mang) — " +
                        "tu choi Kill() tren mot ket qua khong ket luan duoc");
                    return;
                }

                TryKillProcess(pid, decision.Reason);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Loi xu ly su kien tao tien trinh");
        }
    }

    private string? TryResolveFullPath(int pid, string fallbackName)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return proc.MainModule?.FileName;
        }
        catch
        {
            return null; // tien trinh da thoat qua nhanh, hoac khong du quyen doc MainModule
        }
    }

    // Chi hai trang thai duoi day la KET LUAN DUT KHOAT, du de bien minh cho
    // mot hanh dong KHONG HOAN TAC DUOC:
    //   RuleBlock — khop mot rule Block tuong minh trong CSDL chinh sach.
    //   Blocked   — nguoi dung bam "Chan", HOAC file thuc thi khong con tren
    //               dia (mot tien trinh dang chay ma image da bien mat la dau
    //               hieu process-hollowing/self-delete — van dang chan).
    // Moi trang thai con lai (dac biet DeniedByTimeout) nghia la "chua ket
    // luan duoc", va chua ket luan duoc thi khong duoc giet.
    public static bool IsExplicitBlockDecision(ProcessTrustState state) =>
        state is ProcessTrustState.RuleBlock or ProcessTrustState.Blocked;

    private void TryKillProcess(int pid, string reason)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            proc.Kill();
            _audit.Log("process-trust",
                $"Da co gang chan tien trinh SAU KHI da khoi tao (fallback user-mode, khong dong bo truoc " +
                $"khoi tao nhu minifilter that) — PID {pid}, ly do: {reason}");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Khong the Kill() PID {Pid}", pid);
        }
    }

    public override void Dispose()
    {
        _watcher?.Stop();
        _watcher?.Dispose();
        base.Dispose();
    }
}
