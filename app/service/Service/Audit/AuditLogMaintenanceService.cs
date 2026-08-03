namespace Antivirus.Service.Audit;

// [TINH NANG THEO YEU CAU NGUOI DUNG] "hien tai may cai error se ngay cang
// nhieu thi co co che nao xoa log tu dong va thu cong khong" — co che tu
// dong: kiem tra dinh ky, neu file audit.jsonl vuot nguong kich thuoc thi
// tu cat bot con lai N dong gan nhat gan nhat. Co che thu cong: xem
// endpoint POST /api/audit/prune va DELETE /api/audit (Program.cs), goi
// tu nut trong UI (Nhat ky).
public sealed class AuditLogMaintenanceService : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);
    private const long MaxSizeBytesBeforePrune = 20 * 1024 * 1024; // 20MB
    private const int KeepLinesAfterPrune = 20_000;

    private readonly AuditLogger _audit;
    private readonly ILogger<AuditLogMaintenanceService> _logger;

    public AuditLogMaintenanceService(AuditLogger audit, ILogger<AuditLogMaintenanceService> logger)
    {
        _audit = audit;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_audit.GetLogFileSizeBytes() > MaxSizeBytesBeforePrune)
                {
                    int removed = _audit.PruneToMaxLines(KeepLinesAfterPrune);
                    if (removed > 0)
                    {
                        _logger.LogInformation("Audit log vuot {MaxMb}MB — da tu dong don, xoa {Removed} dong cu, giu lai {Keep} dong gan nhat",
                            MaxSizeBytesBeforePrune / (1024 * 1024), removed, KeepLinesAfterPrune);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Loi kiem tra/don audit log dinh ky");
            }

            try { await Task.Delay(CheckInterval, stoppingToken); }
            catch (TaskCanceledException) { break; }
        }
    }
}
