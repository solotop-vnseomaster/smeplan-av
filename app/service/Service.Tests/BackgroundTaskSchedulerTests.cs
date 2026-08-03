using Antivirus.Service.Extensions.Scheduler;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Len lich quet va tac vu nen theo thoi diem may
// ranh". Dung mot subclass gia lap IsUserIdle() de kiem soat duoc trang
// thai "may dang ban/ranh" thay vi phu thuoc chuot/ban phim that cua may
// chay test.
file sealed class FakeScheduler : BackgroundTaskScheduler
{
    public bool FakeIdle { get; set; } = true;
    public override bool IsUserIdle() => FakeIdle;
}

public class BackgroundTaskSchedulerTests
{
    [Fact]
    public void UnregisteredTask_CannotAcquire()
    {
        var scheduler = new FakeScheduler();
        Assert.False(scheduler.TryAcquire("khong-ton-tai"));
    }

    [Fact]
    public void RequiresIdleTask_WhenMachineBusy_CannotAcquire()
    {
        var scheduler = new FakeScheduler { FakeIdle = false };
        scheduler.Register(new TaskRegistration
        {
            TaskId = "t1", ResourceClass = ResourceClass.IoBound, Priority = 1,
            RequiresIdle = true, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });

        Assert.False(scheduler.TryAcquire("t1"));
    }

    [Fact]
    public void RequiresIdleTask_WhenMachineIdle_CanAcquire()
    {
        var scheduler = new FakeScheduler { FakeIdle = true };
        scheduler.Register(new TaskRegistration
        {
            TaskId = "t1", ResourceClass = ResourceClass.IoBound, Priority = 1,
            RequiresIdle = true, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });

        Assert.True(scheduler.TryAcquire("t1"));
    }

    [Fact]
    public void TaskNotRequiringIdle_CanAcquireEvenWhenBusy()
    {
        var scheduler = new FakeScheduler { FakeIdle = false };
        scheduler.Register(new TaskRegistration
        {
            TaskId = "t1", ResourceClass = ResourceClass.CpuBound, Priority = 1,
            RequiresIdle = false, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });

        Assert.True(scheduler.TryAcquire("t1"));
    }

    [Fact]
    public void IoBound_OnlyOneConcurrentTaskAllowed_SecondMustWaitUntilReleased()
    {
        // "toi da MOT tac vu I/O-bound nang tai mot thoi diem, de full scan
        // va sandbox detonation khong cung tranh chap dia".
        var scheduler = new FakeScheduler { FakeIdle = true };
        scheduler.Register(new TaskRegistration
        {
            TaskId = "io-a", ResourceClass = ResourceClass.IoBound, Priority = 1,
            RequiresIdle = false, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });
        scheduler.Register(new TaskRegistration
        {
            TaskId = "io-b", ResourceClass = ResourceClass.IoBound, Priority = 1,
            RequiresIdle = false, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });

        Assert.True(scheduler.TryAcquire("io-a"));
        Assert.False(scheduler.TryAcquire("io-b")); // da co 1 IO-bound dang chay

        scheduler.Release("io-a");
        Assert.True(scheduler.TryAcquire("io-b")); // da nhuong slot
    }

    [Fact]
    public void DifferentResourceClasses_DoNotShareConcurrencyCap()
    {
        var scheduler = new FakeScheduler { FakeIdle = true };
        scheduler.Register(new TaskRegistration
        {
            TaskId = "io-task", ResourceClass = ResourceClass.IoBound, Priority = 1,
            RequiresIdle = false, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });
        scheduler.Register(new TaskRegistration
        {
            TaskId = "net-task", ResourceClass = ResourceClass.NetworkBound, Priority = 1,
            RequiresIdle = false, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });

        Assert.True(scheduler.TryAcquire("io-task"));
        Assert.True(scheduler.TryAcquire("net-task")); // resource class khac, khong bi chan boi io-task
    }

    [Fact]
    public void CreateYieldTokenSource_CancelsAfterMaxDuration()
    {
        var scheduler = new FakeScheduler();
        scheduler.Register(new TaskRegistration
        {
            TaskId = "short-lived", ResourceClass = ResourceClass.CpuBound, Priority = 1,
            RequiresIdle = false, MaxDurationBeforeYield = TimeSpan.FromMilliseconds(50),
        });

        using var cts = scheduler.CreateYieldTokenSource("short-lived", CancellationToken.None);
        Assert.False(cts.IsCancellationRequested);

        Thread.Sleep(200);
        Assert.True(cts.IsCancellationRequested);
    }

    [Fact]
    public void ListRegistrations_ReturnsAllRegisteredTasks()
    {
        var scheduler = new FakeScheduler();
        scheduler.Register(new TaskRegistration
        {
            TaskId = "a", ResourceClass = ResourceClass.IoBound, Priority = 1,
            RequiresIdle = true, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });
        scheduler.Register(new TaskRegistration
        {
            TaskId = "b", ResourceClass = ResourceClass.NetworkBound, Priority = 2,
            RequiresIdle = true, MaxDurationBeforeYield = TimeSpan.FromMinutes(1),
        });

        var list = scheduler.ListRegistrations();

        Assert.Equal(2, list.Count);
        Assert.Contains(list, r => r.TaskId == "a");
        Assert.Contains(list, r => r.TaskId == "b");
    }
}
