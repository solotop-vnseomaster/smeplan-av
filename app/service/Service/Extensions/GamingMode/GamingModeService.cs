using System.Runtime.InteropServices;

namespace Antivirus.Service.Extensions;

// "tai lieu moi.txt" muc "Gaming/Silent mode khi phat hien ung dung toan
// man hinh": SHQueryUserNotificationState la API user-mode thuan, khong
// can driver — khi vao gaming mode: AN notification, TAM DUNG tac vu nen
// nang (full scan...), nhung KHONG tat real-time/firewall (ranh gioi quan
// trong tai lieu nhan manh: che giau thong bao khac han tat bao ve).
public sealed class GamingModeService : BackgroundService
{
    private enum QUNS
    {
        QUNS_NOT_PRESENT = 1,
        QUNS_BUSY = 2,
        QUNS_RUNNING_D3D_FULL_SCREEN = 3,
        QUNS_PRESENTATION_MODE = 4,
        QUNS_ACCEPTS_NOTIFICATIONS = 5,
        QUNS_QUIET_TIME = 6,
        QUNS_APP = 7,
    }

    [DllImport("shell32.dll")]
    private static extern int SHQueryUserNotificationState(out QUNS state);

    private readonly ILogger<GamingModeService> _logger;
    private readonly Queue<(string Title, string Body)> _suppressedNotifications = new();
    private readonly object _lock = new();

    public bool IsActive { get; private set; }
    public event Action? OnEnter;
    public event Action? OnExit;

    public GamingModeService(ILogger<GamingModeService> logger)
    {
        _logger = logger;
    }

    // Cac module khac (toast, full scan...) goi ham nay de kiem tra truoc
    // khi hien thong bao/chay tac vu nang.
    public void SuppressOrDeliver(string title, string body, Action<string, string> deliverNow)
    {
        if (IsActive)
        {
            lock (_lock) { _suppressedNotifications.Enqueue((title, body)); }
        }
        else
        {
            deliverNow(title, body);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                bool fullscreenExclusive = SHQueryUserNotificationState(out var state) == 0 &&
                                            state == QUNS.QUNS_RUNNING_D3D_FULL_SCREEN;

                if (fullscreenExclusive && !IsActive)
                {
                    IsActive = true;
                    _logger.LogInformation("Gaming/Silent mode: BAT (phat hien fullscreen exclusive)");
                    OnEnter?.Invoke();
                }
                else if (!fullscreenExclusive && IsActive)
                {
                    IsActive = false;
                    _logger.LogInformation("Gaming/Silent mode: TAT — se hien lai {Count} thong bao da tich luy",
                        _suppressedNotifications.Count);
                    OnExit?.Invoke();
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Loi kiem tra trang thai fullscreen");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken); }
            catch (TaskCanceledException) { }
        }
    }

    public List<(string Title, string Body)> DrainSuppressedNotifications()
    {
        lock (_lock)
        {
            var list = _suppressedNotifications.ToList();
            _suppressedNotifications.Clear();
            return list;
        }
    }
}
