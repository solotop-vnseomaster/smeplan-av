using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Antivirus.Service.Models;

namespace Antivirus.Service.Audit;

// modules/02-kien-truc.md muc 3 "Luong ghi log": "moi quyet dinh allow/block
// va ket qua scan ghi vao audit trail ky thuat (structured JSON lines,
// khong hien thi truc tiep cho nguoi dung); mot ban tom tat duoc loc va
// dien giai lai tu audit trail de hien thi tren UI" (UI-07).
public sealed class AuditLogger
{
    private readonly string _logPath;
    private readonly object _fileLock = new();
    private readonly ConcurrentQueue<AuditEvent> _recentForUi = new();
    private const int MaxRecentInMemory = 500;

    // Cache san encoding UTF-8 KHONG BOM (giong het File.AppendAllText mac
    // dinh) de tranh validate/tao lai encoder o moi lan goi Log().
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    public AuditLogger(string logPath)
    {
        _logPath = logPath;
    }

    // [DA THU VA TU CHOI: giu mot FileStream mo suot doi song AuditLogger]
    // Phuong an "giu handle mo" (nhu de xuat trong code review) DA duoc thu
    // nghiem that su o day va bi LOAI BO sau khi chay dotnet test: giu MOT
    // handle GHI mo lien tuc (du tu mo voi FileShare.ReadWrite) khien MOI
    // lan File.ReadAllLines/File.ReadAllText/File.WriteAllText tu BEN NGOAI
    // (ca PruneToMaxLines/ClearAll cua CHINH class nay, lan AuditLoggerTests)
    // nem IOException "file dang duoc tien trinh khac su dung" — vi cac ham
    // File.* do mac dinh tu mo voi FileShare.Read (chi cho phep chia se voi
    // handle KHONG co quyen Ghi), xung dot voi bat ky handle Ghi nao dang mo
    // du ban than no cho phep chia se rong den dau. Day la gioi han cua
    // Windows file sharing, khong the vuot qua tu phia AuditLogger. Vi
    // AuditLoggerTests.cs (va chinh PruneToMaxLines/ClearAll) doc file truc
    // tiep bang cac ham File.* nay ngay sau khi goi Log(), giu handle mo se
    // pha vo hanh vi ma code khac dang phu thuoc — vi pham dieu kien "khong
    // duoc doi semantics ma code/test khac dang dua vao". Sua thay the bang
    // mot cai thien AN TOAN HON: van mo/ghi/dong MOI lan goi (giu nguyen kha
    // nang cac tien trinh/API khac doc file bat ky luc nao, dung nhu truoc),
    // nhung ghi thang byte UTF-8 da encode san qua FileStream tho thay vi di
    // qua StreamWriter+Encoder cua File.AppendAllText — giam cap phat/kiem
    // tra encoding lap lai moi lan goi trong pham vi giu lock, ma khong doi
    // dinh dang file tren dia hay share-mode nguoi doc ben ngoai dang phu
    // thuoc.
    public void Log(string category, string summary, object? detail = null)
    {
        var evt = new AuditEvent
        {
            EventId = Guid.NewGuid().ToString("N"),
            TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Category = category,
            Summary = summary,
            Detail = detail,
        };

        var line = JsonSerializer.Serialize(evt);
        var bytes = Utf8NoBom.GetBytes(line + Environment.NewLine);
        lock (_fileLock)
        {
            using var stream = new FileStream(_logPath, FileMode.Append, FileAccess.Write, FileShare.Read);
            stream.Write(bytes, 0, bytes.Length);
        }

        _recentForUi.Enqueue(evt);
        while (_recentForUi.Count > MaxRecentInMemory && _recentForUi.TryDequeue(out _)) { }
    }

    // Ban tom tat da "loc va dien giai lai" cho UI — khong phai JSON tho.
    public IReadOnlyList<AuditEvent> GetRecentForUi(int limit = 100)
    {
        return _recentForUi.Reverse().Take(limit).ToList();
    }

    // [TINH NANG THEO YEU CAU NGUOI DUNG] File audit.jsonl truoc day chi
    // GHI THEM vinh vien, khong bao gio duoc don dep — voi may quet nhieu
    // (hang trieu file, hang nghin loi) file nay co the phinh to khong
    // gioi han qua thoi gian. Them co che don thu cong (nut trong UI) VA
    // tu dong dinh ky (xem AuditLogMaintenanceService) — ca hai deu goi
    // chung PruneToMaxLines.
    public long GetLogFileSizeBytes()
    {
        try { return new FileInfo(_logPath).Length; }
        catch { return 0; }
    }

    // Giu lai toi da "maxLines" DONG GAN NHAT trong file tren dia (khong
    // dong nao bi sua noi dung, chi cat bot dong cu nhat) — doc toan bo
    // file vao bo nho de xu ly, chap nhan duoc vi day la thao tac THINH
    // THOANG (dinh ky vai gio hoac theo yeu cau thu cong), khong phai
    // duong dan nong (hot path) nhu Log().
    public int PruneToMaxLines(int maxLines)
    {
        lock (_fileLock)
        {
            if (!File.Exists(_logPath)) return 0;

            var allLines = File.ReadAllLines(_logPath);
            if (allLines.Length <= maxLines) return 0;

            var kept = allLines[^maxLines..];
            File.WriteAllLines(_logPath, kept);
            return allLines.Length - kept.Length;
        }
    }

    // Xoa toan bo nhat ky (ca file tren dia lan bo nho trong RAM cho UI) —
    // hanh dong nguoi dung phai xac nhan truoc trong UI (khong the hoan tac).
    public void ClearAll()
    {
        lock (_fileLock)
        {
            File.WriteAllText(_logPath, string.Empty);
        }
        while (_recentForUi.TryDequeue(out _)) { }
    }
}
