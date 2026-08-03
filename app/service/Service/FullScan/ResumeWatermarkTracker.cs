namespace Antivirus.Service.FullScan;

// [SUA LOI NGHIEM TRONG] FullScanService truoc day luu resume-state bang
// duong dan file ma MOI worker thread VUA quet xong, ngay tai thoi diem no
// xong — vi cac worker chay SONG SONG va hoan tat KHONG theo thu tu
// enumerate (file duoc dispatch tuan tu nhung co the mat thoi gian xu ly
// khac nhau), "lastFile" ghi xuong dia co the la mot file bat ky vua xong
// GAN DAY, khong dam bao MOI file TRUOC no (theo thu tu enumerate/dispatch)
// da thuc su duoc quet. Neu scan bi gian doan (crash/restart) dung luc do,
// lan resume sau se dung sai "lastFile" nay lam moc va BO QUA het cac file
// dung TRUOC no trong thu tu enumerate — ke ca file chua bao gio duoc quet
// (bo sot file, ke ca file doc hai).
//
// Class nay tach rieng phan logic "watermark" de co the unit-test doc lap
// voi FullScanService (von can rat nhieu dependency de dung thu): moi file
// duoc gan mot so thu tu TANG DAN luc DISPATCH (luon dung thu tu enumerate
// that vi chi vong lap chinh, don luong, gan so nay); Complete() chi cho
// phep watermark (moc duoc phep luu) tien len khi TOAN BO cac so thu tu
// LIEN TUC truoc do da duoc bao hoan tat — dam bao file tra ve de luu
// xuong dia LUON la mot diem ma moi file truoc no (theo thu tu dispatch)
// da chac chan duoc quet, bat ke thu tu HOAN TAT thuc te.
//
// Dong thoi gioi han tan suat FLUSH thuc su xuong dia (persistInterval) —
// watermark trong bo nho van luon chinh xac tuc thi, chi tre viec ghi
// xuong dia de giam chi phi I/O dong bo tren scan hang tram nghin file
// (chap nhan mat toi da ~persistInterval tien do neu crash dung luc).
public sealed class ResumeWatermarkTracker
{
    private readonly object _lock = new();
    private readonly Dictionary<long, string> _outOfOrder = new();
    private readonly TimeSpan _persistInterval;
    private readonly Func<DateTime> _clock;
    private long _watermarkSeq = -1;
    private string? _watermarkFile;
    private DateTime _lastFlush = DateTime.MinValue;

    public ResumeWatermarkTracker(TimeSpan persistInterval, Func<DateTime>? clock = null)
    {
        _persistInterval = persistInterval;
        _clock = clock ?? (() => DateTime.UtcNow);
    }

    // Goi khi mot worker hoan tat file co so thu tu dispatch `seq`. Tra ve
    // duong dan file CAN ghi xuong dia lam resume marker moi, hoac null neu
    // watermark chua tien them (van con "lo hong" o mot seq nho hon chua
    // hoan tat) HOAC da tien nhung chua den luc flush (throttle).
    public string? Complete(long seq, string completedFile)
    {
        lock (_lock)
        {
            _outOfOrder[seq] = completedFile;
            bool advanced = false;
            while (_outOfOrder.TryGetValue(_watermarkSeq + 1, out var nextFile))
            {
                _watermarkSeq++;
                _outOfOrder.Remove(_watermarkSeq);
                _watermarkFile = nextFile;
                advanced = true;
            }
            if (advanced && _clock() - _lastFlush >= _persistInterval)
            {
                _lastFlush = _clock();
                return _watermarkFile;
            }
            return null;
        }
    }
}
