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

    // Xem khoi try/catch trong Log(): ghi audit that bai KHONG duoc phep dung
    // cac tang bao ve, nhung cung khong duoc bien mat khong dau vet — mat
    // audit trail chinh la thu ke tan cong nham toi.
    private int _writeFailureCount;
    public int WriteFailureCount => Volatile.Read(ref _writeFailureCount);
    public string? LastWriteError { get; private set; }
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

        // [SUA LOI NGHIEM TRONG — DUONG TAT AV KHONG CAN DAC QUYEN]
        //
        // TRUOC DAY khoi ghi duoi day KHONG co try/catch. Ham nay duoc goi tu
        // ben trong nhieu BackgroundService (UpdateClientService,
        // DownloadsWatcherService, EventBusSweepService, RansomwareGuardService
        // ...). Tu .NET 6, mac dinh cua host la
        // BackgroundServiceExceptionBehavior.StopHost: mot ngoai le khong bat
        // trong ExecuteAsync lam DUNG CA TIEN TRINH.
        //
        // Nghia la mot tien trinh quyen THUONG chi can mo audit.jsonl voi
        // FileShare.None va giu handle — lan ghi audit tiep theo nem
        // IOException, va toan bo dich vu antivirus tat. Khong can dac quyen,
        // khong can khai thac gi ca. Cung duong do mo ra khi dia day.
        //
        // Nguyen tac: mot loi GHI NHAT KY khong bao gio duoc phep dung cac
        // TANG BAO VE. Nhung cung khong duoc nuot im lang — mat audit trail la
        // su kien bao mat that (do chinh la thu ke tan cong muon), nen no duoc
        // dem lai va phoi ra trang thai de UI bao do.
        try
        {
            lock (_fileLock)
            {
                using var stream = new FileStream(_logPath, FileMode.Append, FileAccess.Write, FileShare.Read);
                stream.Write(bytes, 0, bytes.Length);
            }
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _writeFailureCount);
            LastWriteError = $"{ex.GetType().Name}: {ex.Message}";
            // Van giu su kien trong bo nho cho UI ben duoi — mat file khong
            // dong nghia mat luon ban ghi gan nhat.
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
            var dropped = allLines[..^maxLines];

            // [SUA LOI CAO — GUARD DUNG, TRUOC DAY AP THIEU DUONG] ClearAll()
            // da duoc sua de LUU TRU thay vi HUY, voi ly do dung: "mot nhat ky
            // xoa duoc bang chinh giao dien ma no dang giam sat thi khong con
            // la nhat ky kiem toan". Nhung PruneToMaxLines — duong con lai di
            // toi cung mot cho — van ghi de file va huy vinh vien nhung dong
            // cu nhat. Va no te hon ClearAll o mot diem: no chay TU DONG,
            // dinh ky, qua AuditLogMaintenanceService, khong can ai bam nut.
            // Ke tan cong chi can sinh du dong nhat ky rac (vi du kich hoat
            // hang loat su kien quet) la day duoc dau vet cua chinh minh ra
            // khoi cua so maxLines, roi doi lan prune tu dong ke tiep xoa
            // sach — khong de lai gi.
            // Sua: dung CHUNG co che luu tru voi ClearAll — noi cac dong bi
            // cat vao audit-pruned-<timestamp>.jsonl trong cung thu muc logs
            // (da duoc ACL bao ve). Neu KHONG luu tru duoc thi KHONG cat —
            // tha de file phinh to con hon huy bang chung trong im lang,
            // dung nguyen tac fail-closed da ap cho ClearAll.
            var dir = Path.GetDirectoryName(_logPath)!;
            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss");
            var archivePath = Path.Combine(dir, $"audit-pruned-{stamp}.jsonl");
            int suffix = 1;
            while (File.Exists(archivePath))
            {
                archivePath = Path.Combine(dir, $"audit-pruned-{stamp}-{suffix}.jsonl");
                suffix++;
            }

            try
            {
                File.WriteAllLines(archivePath, dropped);
            }
            catch (Exception ex)
            {
                // Khong nem ra ngoai (prune chay nen dinh ky, khong duoc phep
                // lam sap service) nhung KHONG cat gi ca va phai de lai vet.
                // lock(_fileLock) la Monitor -> reentrant tren cung mot
                // luong, nen goi Log() o day an toan.
                Log("system",
                    $"KHONG luu tru duoc {dropped.Length} dong nhat ky cu vao {archivePath} " +
                    $"({ex.GetType().Name}: {ex.Message}) — KHONG cat bot file, giu nguyen bang chung");
                return 0;
            }

            File.WriteAllLines(_logPath, kept);
            Log("system",
                $"Da cat {dropped.Length} dong nhat ky cu nhat, LUU TRU tai {archivePath} (khong bi xoa)");
            return dropped.Length;
        }
    }

    // [SUA LOI CAO] TRUOC DAY ham nay ghi de file nhat ky bang chuoi rong —
    // HUY VINH VIEN. Va no duoc phoi ra qua DELETE /api/audit, tuc la bat ky
    // ai co token API deu xoa sach duoc moi bang chung ve nhung gi da xay ra
    // tren may: rule "cho phep luon" ai them, file nao bi cach ly, ai khoi
    // phuc cai gi. Mot nhat ky xoa duoc bang chinh giao dien ma no dang giam
    // sat thi khong con la nhat ky kiem toan.
    //
    // Sua: LUU TRU thay vi HUY. File hien tai duoc doi ten thanh
    // audit-<timestamp>.jsonl trong CUNG thu muc logs (da duoc ACL bao ve —
    // xem AclProtection.ProtectAllDataDirectories), roi bat dau mot file
    // trong moi. Nguoi dung van co trai nghiem "don sach man hinh nhat ky"
    // nhu truoc, nhung du lieu khong bien mat khoi dia. Tra ve duong dan ban
    // luu tru de endpoint bao lai cho nguoi dung biet no nam o dau.
    public string? ClearAll()
    {
        string? archivePath = null;
        lock (_fileLock)
        {
            if (File.Exists(_logPath) && new FileInfo(_logPath).Length > 0)
            {
                var dir = Path.GetDirectoryName(_logPath)!;
                var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss");
                archivePath = Path.Combine(dir, $"audit-{stamp}.jsonl");

                // Neu trung ten (hai lan xoa trong cung mot giay), them hau to.
                int suffix = 1;
                while (File.Exists(archivePath))
                {
                    archivePath = Path.Combine(dir, $"audit-{stamp}-{suffix}.jsonl");
                    suffix++;
                }

                try
                {
                    File.Move(_logPath, archivePath);
                }
                catch
                {
                    // Khong luu tru duoc (file dang bi khoa?) — KHONG duoc
                    // roi vao nhanh xoa trang. Tha khong don duoc nhat ky
                    // con hon huy bang chung trong im lang.
                    return null;
                }
            }

            File.WriteAllText(_logPath, string.Empty);
        }
        while (_recentForUi.TryDequeue(out _)) { }

        if (archivePath is not null)
        {
            Log("system", $"Nhat ky truoc do da duoc LUU TRU tai {archivePath} (khong bi xoa)");
        }
        return archivePath;
    }
}
