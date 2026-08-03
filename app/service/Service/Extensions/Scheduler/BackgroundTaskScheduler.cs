using System.Runtime.InteropServices;
using Antivirus.Service.FullScan;

namespace Antivirus.Service.Extensions.Scheduler;

public enum ResourceClass { CpuBound, IoBound, NetworkBound }

public sealed class TaskRegistration
{
    public required string TaskId { get; init; }
    public ResourceClass ResourceClass { get; init; }
    public int Priority { get; init; }
    public bool RequiresIdle { get; init; }
    public TimeSpan MaxDurationBeforeYield { get; init; }
}

// "tai lieu moi.txt" muc "Len lich quet va tac vu nen theo thoi diem may
// ranh": mot task scheduler noi bo tap trung dieu phoi, thay vi de tung
// module (sandbox detonation, quet lo hong, giam sat mang gia dinh, full
// scan) tu quyet dinh lich chay doc lap va de chong lan.
//
// [HAN CHE DA BIET] Tai lieu liet ke "full scan dinh ky" la mot trong cac
// tac vu can dieu phoi qua scheduler nay, nhung base app (spec goc truoc
// tai lieu mo rong nay) CHI co full scan thu cong/kich hoat qua USB, khong
// co co che lich chay dinh ky nao — khong tu them tinh nang lich full scan
// dinh ky moi vao day vi nam ngoai pham vi tai lieu duoc giao (chi mo rong
// tinh nang co san, khong tu suy dien them). Scheduler van la mot bo dieu
// phoi day du chuc nang, dang duoc VulnerabilityScanService va
// HomeNetworkMonitorService su dung that cho vong lap dinh ky cua chung.
//
// Ten lop la "BackgroundTaskScheduler" (khong phai "TaskScheduler") de
// tranh trung ten voi System.Threading.Tasks.TaskScheduler cua .NET BCL.
public class BackgroundTaskScheduler
{
    // "toi da MOT tac vu I/O-bound nang tai mot thoi diem, de full scan va
    // sandbox detonation khong cung tranh chap dia".
    private const int MaxConcurrentIoBound = 1;
    private const int MaxConcurrentCpuBound = 2;
    private const int MaxConcurrentNetworkBound = 2;

    // "theo CUNG tieu chi GetLastInputInfo da dung o bai truoc" — dung lai
    // dung nguong "idle du de chay toc do day du" (60s) cua FullScanService,
    // khong phai nguong "vua tuong tac" (2s) chi dung de giam nhe toc do.
    private const uint IdleThresholdMs = 60_000;

    private readonly Dictionary<string, TaskRegistration> _registrations = new();
    private readonly Dictionary<ResourceClass, int> _runningCounts = new();
    private readonly object _lock = new();

    public void Register(TaskRegistration registration)
    {
        lock (_lock) { _registrations[registration.TaskId] = registration; }
    }

    public IReadOnlyList<TaskRegistration> ListRegistrations()
    {
        lock (_lock) { return _registrations.Values.ToList(); }
    }

    // Goi TRUOC khi mot tac vu dinh ky bat dau lam viec that; tra ve false
    // neu chua duoc phep chay (may dang ban va tac vu yeu cau idle, hoac da
    // du so tac vu cung resource_class dang chay) — caller nen bo qua chu
    // ky nay va thu lai o chu ky ke tiep, KHONG chan/cho dong bo.
    public bool TryAcquire(string taskId)
    {
        lock (_lock)
        {
            if (!_registrations.TryGetValue(taskId, out var reg)) return false;
            if (reg.RequiresIdle && !IsUserIdle()) return false;

            int cap = CapFor(reg.ResourceClass);
            int current = _runningCounts.GetValueOrDefault(reg.ResourceClass);
            if (current >= cap) return false;

            _runningCounts[reg.ResourceClass] = current + 1;
            return true;
        }
    }

    public void Release(string taskId)
    {
        lock (_lock)
        {
            if (!_registrations.TryGetValue(taskId, out var reg)) return;
            int current = _runningCounts.GetValueOrDefault(reg.ResourceClass);
            if (current > 0) _runningCounts[reg.ResourceClass] = current - 1;
        }
    }

    // "max_duration_before_yield bat buoc moi tac vu nen phai tu ngat va
    // nhuong lai tai nguyen sau mot khoang thoi gian chay lien tuc nhat
    // dinh, KE CA KHI CHUA XONG VIEC" — tra ve mot token se tu huy sau
    // dung khoang thoi gian da dang ky, doc lap voi token huy tu ben ngoai
    // (dung/shutdown service).
    public CancellationTokenSource CreateYieldTokenSource(string taskId, CancellationToken externalCt)
    {
        TaskRegistration? reg;
        lock (_lock) { _registrations.TryGetValue(taskId, out reg); }

        var cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        if (reg is not null && reg.MaxDurationBeforeYield > TimeSpan.Zero)
        {
            cts.CancelAfter(reg.MaxDurationBeforeYield);
        }
        return cts;
    }

    // Ao hoa de test co the gia lap trang thai "may dang ban"/"may idle"
    // ma khong phu thuoc trang thai chuot/ban phim that cua may chay test.
    public virtual bool IsUserIdle()
    {
        var lii = new NativeInterop.LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<NativeInterop.LASTINPUTINFO>() };
        if (!NativeInterop.GetLastInputInfo(ref lii)) return true; // khong lay duoc -> khong chan tac vu
        uint idleMs = NativeInterop.GetTickCount() - lii.dwTime;
        return idleMs >= IdleThresholdMs;
    }

    private static int CapFor(ResourceClass resourceClass) => resourceClass switch
    {
        ResourceClass.IoBound => MaxConcurrentIoBound,
        ResourceClass.CpuBound => MaxConcurrentCpuBound,
        ResourceClass.NetworkBound => MaxConcurrentNetworkBound,
        _ => 1,
    };
}
