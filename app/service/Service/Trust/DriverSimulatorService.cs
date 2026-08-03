using System.Management;
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
    private readonly ILogger<DriverSimulatorService> _logger;
    private ManagementEventWatcher? _watcher;

    public DriverSimulatorService(ProcessTrustEngine trustEngine, AuditLogger audit,
        ILogger<DriverSimulatorService> logger)
    {
        _trustEngine = trustEngine;
        _audit = audit;
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
            _logger.LogInformation(
                "Driver-simulation (Win32_ProcessStartTrace) da khoi dong — CHU Y: day la fallback " +
                "user-mode, khong thay the minifilter kernel-mode that (xem app/drivers/minifilter).");
            _audit.Log("process-trust",
                "Driver-simulation user-mode da khoi dong (khong phai kernel minifilter that — han che moi truong)");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Khong khoi dong duoc Win32_ProcessStartTrace (thuong can quyen Administrator). " +
                "Luong Process Trust Decision van goi duoc thu cong qua API /api/trust/evaluate de demo/test.");
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

            var decision = await _trustEngine.EvaluateAsync(fullPath, pid, CancellationToken.None);
            if (!decision.Allowed)
            {
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
