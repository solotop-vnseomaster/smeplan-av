using Antivirus.Service.FullScan;
using Xunit;

namespace Antivirus.Service.Tests;

// Regression cho bug da sua trong FullScanService (xem ghi chu trong
// ResumeWatermarkTracker.cs): resume-state truoc day duoc luu bang file ma
// MOT worker BAT KY vua quet xong, khong quan tam thu tu enumerate/dispatch
// — neu cac worker song song hoan tat KHONG theo thu tu do, resume marker
// co the "nhay coc" qua nhung file chua thuc su duoc quet, khien lan resume
// sau bo sot file.
public class ResumeWatermarkTrackerTests
{
    [Fact]
    public void CompletionsInOrder_AdvancesWatermarkImmediately()
    {
        var tracker = new ResumeWatermarkTracker(TimeSpan.Zero);

        Assert.Equal("a.txt", tracker.Complete(0, "a.txt"));
        Assert.Equal("b.txt", tracker.Complete(1, "b.txt"));
        Assert.Equal("c.txt", tracker.Complete(2, "c.txt"));
    }

    // Kich ban CHINH cua bug: seq 2 (dispatch SAU CUNG) hoan tat TRUOC seq 0
    // va 1 (worker khac nhanh hon). TRUOC DAY code cu se luu thang "c.txt"
    // lam resume marker ngay lap tuc — sai, vi a.txt/b.txt (dung TRUOC no
    // trong thu tu dispatch) CHUA duoc quet xong. Tracker phai giu watermark
    // o "cho" cho toi khi ca a.txt va b.txt bao hoan tat, roi moi duoc phep
    // nhay thang qua ca c.txt (vi luc do ca 3 da lien tuc hoan tat).
    [Fact]
    public void OutOfOrderCompletion_DoesNotAdvanceUntilGapFilled()
    {
        var tracker = new ResumeWatermarkTracker(TimeSpan.Zero);

        // seq 2 xong truoc (worker nhanh) — KHONG duoc phep luu lam marker
        // vi seq 0/1 con "lo hong".
        Assert.Null(tracker.Complete(2, "c.txt"));

        // seq 0 xong — watermark tien duoc toi 0 (a.txt), dung vi day la
        // file DAU TIEN theo thu tu dispatch.
        Assert.Equal("a.txt", tracker.Complete(0, "a.txt"));

        // seq 1 xong — lap "lo hong" cuoi cung, watermark duoc phep nhay
        // THANG qua seq 2 (da co san trong bo dem) toi c.txt luon, vi gio
        // ca 0,1,2 da lien tuc hoan tat.
        Assert.Equal("c.txt", tracker.Complete(1, "b.txt"));
    }

    [Fact]
    public void PersistInterval_ThrottlesDiskWritesButKeepsWatermarkCorrect()
    {
        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var tracker = new ResumeWatermarkTracker(TimeSpan.FromSeconds(2), () => now);

        // Lan dau luon duoc flush (lastFlush khoi tao = DateTime.MinValue).
        Assert.Equal("a.txt", tracker.Complete(0, "a.txt"));

        // Chua qua 2 giay -> watermark van tien (dung) nhung KHONG tra ve
        // (tuc la khong ghi xuong dia lan nay) — day la phan giam chi phi
        // I/O (#11), watermark noi bo van chinh xac cho lan flush ke tiep.
        now = now.AddSeconds(1);
        Assert.Null(tracker.Complete(1, "b.txt"));

        // Qua 2 giay ke tu lan flush truoc -> duoc phep ghi, va gia tri tra
        // ve phai la watermark MOI NHAT (c.txt), khong phai b.txt bi "lo".
        now = now.AddSeconds(1.5);
        Assert.Equal("c.txt", tracker.Complete(2, "c.txt"));
    }
}
