using System.Collections.Concurrent;
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

    public AuditLogger(string logPath)
    {
        _logPath = logPath;
    }

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
        lock (_fileLock)
        {
            File.AppendAllText(_logPath, line + Environment.NewLine);
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
