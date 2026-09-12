using Antivirus.Service.Engine;
using Antivirus.Service.Trust;
using Antivirus.Service.Update;

namespace Antivirus.Service.Security;

// Mot suy giam bao ve da duoc CHUAN HOA. `Severity` duoc doc co kieu (khong
// phai qua reflection) vi ca /api/status lan RiskScoreService deu phai dem so
// muc critical.
public sealed record ProtectionDegradation(string Id, string Severity, string Message)
{
    public const string Critical = "critical";
    public const string Warning = "warning";
}

// Chan doan thu thap MOT LAN luc khoi dong (trong Program.cs, truoc khi
// container DI duoc dung) — khong the tinh lai theo yeu cau, nen truyen vao
// duoi dang gia tri bat bien.
public sealed record StartupDiagnostics(
    IReadOnlyList<string> UnprotectedDataDirectories,
    string? UpdateSigningDisabledReason);

// [SUA LOI NGHIEM TRONG — "trang thai bao ve la hang so o ca ba tang"]
//
// TRUOC DAY trang thai bao ve duoc khai bao DOC LAP o ba noi, va ca ba deu la
// hang so:
//   1. Program.cs  — `protectionEnabled = true` cung nhac.
//   2. index.html  — "Đang bảo vệ" + vong tron ghim `stroke-dashoffset:20`.
//   3. RiskScoreService — thanh phan "Real-time protection" ghi cung 0 diem
//      tru voi chu thich "Dang bat (khong co co che tat trong ban nay)".
//
// Hai cai dau da duoc sua truoc; rieng cai thu ba con lai lam hai bang tren
// cung mot man hinh MAU THUAN nhau truc tiep: the tren bao "KHÔNG được bảo vệ"
// (mau do) trong khi the ngay duoi bao "100 — An toàn — mọi lớp bảo vệ đều
// ổn" (mau xanh). Nguoi dung khong co cach nao biet tin cai nao.
//
// Nguyen nhan goc khong phai la ba loi rieng le ma la MOT thieu sot kien truc:
// khong co NGUON SU THAT DUY NHAT nao ve "cac tang phong thu co dang chay
// khong". Lop nay chinh la nguon do; ca /api/status lan RiskScoreService deu
// doc tu day, nen chung khong the lech nhau nua.
public sealed class ProtectionStatusService
{
    private readonly ScanEngineService _engine;
    private readonly UpdateClientService _update;
    private readonly DriverSimulatorService _processTrust;
    private readonly StartupDiagnostics _startup;
    private readonly Antivirus.Service.Audit.AuditLogger _audit;

    public ProtectionStatusService(ScanEngineService engine, UpdateClientService update,
        DriverSimulatorService processTrust, StartupDiagnostics startup,
        Antivirus.Service.Audit.AuditLogger audit)
    {
        _engine = engine;
        _update = update;
        _processTrust = processTrust;
        _startup = startup;
        _audit = audit;
    }

    public IReadOnlyList<ProtectionDegradation> Compute()
    {
        var list = new List<ProtectionDegradation>();

        if (_engine.SignatureDbMissing)
        {
            list.Add(new ProtectionDegradation("signature-db", ProtectionDegradation.Critical,
                "Không nạp được CSDL chữ ký — phát hiện theo hash KHÔNG hoạt động."));
        }

        // Win32_ProcessStartTrace thuong xuyen khong khoi dong duoc (can quyen
        // Administrator). Khi do TOAN BO tang danh gia tin cay tien trinh
        // khong chay.
        if (!_processTrust.IsWatchingProcessCreation)
        {
            list.Add(new ProtectionDegradation("process-trust", ProtectionDegradation.Critical,
                "Tầng đánh giá tin cậy tiến trình KHÔNG hoạt động"
                + (_processTrust.StartupFailureReason is null ? "" : $" ({_processTrust.StartupFailureReason})")
                + " — tiến trình mới KHÔNG được kiểm tra. Thường do service chưa chạy với quyền Administrator."));
        }

        // Mat audit trail la su kien bao mat that: do chinh la thu ke tan cong
        // muon dat duoc. Truoc day mot loi ghi audit lam DUNG ca dich vu (xem
        // AuditLogger.Log); nay no khong dung dich vu nua, nhung phai nhin
        // thay duoc thay vi bien mat.
        if (_audit.WriteFailureCount > 0)
        {
            list.Add(new ProtectionDegradation("audit-trail", ProtectionDegradation.Critical,
                $"KHÔNG ghi được nhật ký audit ({_audit.WriteFailureCount} lần thất bại"
                + (_audit.LastWriteError is null ? "" : $", gần nhất: {_audit.LastWriteError}")
                + ") — hành động của sản phẩm đang không để lại dấu vết điều tra."));
        }

        // [SUA PHAN LOAI SAI] TRUOC DAY muc nay la Critical, va vi
        // protectionEnabled = !HasCritical, mot may DANG bao ve tot van hien
        // "KHÔNG được bảo vệ". Do luong truc tiep tren may da cai: tha EICAR
        // vao Downloads, bi chan va cach ly trong 10 giay — trong khi dashboard
        // bao khong duoc bao ve.
        //
        // Hai loai suy giam khac nhau ve BAN CHAT, khong duoc tron chung mot
        // muc:
        //   - "mot tang KHONG DANG CHAY" (signature-db, process-trust,
        //     data-acl, audit-trail) => ngay bay gio khong duoc bao ve.
        //   - "khong TU CAP NHAT duoc" (muc nay) => hom nay van bao ve binh
        //     thuong, nhung CSDL chu ky dong bang va yeu dan theo thoi gian.
        //
        // Bao "KHONG duoc bao ve" cho truong hop thu hai khong chi sai ma con
        // co hai theo cach kho thay: no day nguoi dung toi cho quen nhin den
        // chi bao trang thai. Xep Warning -> muc tong hop thanh "degraded"
        // ("Bảo vệ suy giảm"), dung voi thuc te, va thong diep van noi ro hau
        // qua de khong ai coi nhe.
        if (!_update.SigningTrustConfigured)
        {
            list.Add(new ProtectionDegradation("update-channel", ProtectionDegradation.Warning,
                "Kênh cập nhật ĐÃ TẮT: "
                + (_startup.UpdateSigningDisabledReason ?? "chưa cấu hình certificate ký gói cập nhật")
                + " — CSDL chữ ký sẽ không bao giờ được cập nhật."));
        }

        if (_startup.UnprotectedDataDirectories.Count > 0)
        {
            list.Add(new ProtectionDegradation("data-acl", ProtectionDegradation.Critical,
                $"{_startup.UnprotectedDataDirectories.Count} thư mục dữ liệu KHÔNG được khoá ACL "
                + $"({string.Join(", ", _startup.UnprotectedDataDirectories)}) — "
                + "tiến trình quyền thấp có thể sửa CSDL chữ ký, rule và token API."));
        }

        if (!Antivirus.Service.Extensions.Firewall.ConnectionMonitor.RulesAreEnforced)
        {
            list.Add(new ProtectionDegradation("firewall-enforcement", ProtectionDegradation.Warning,
                "Rule tường lửa được LƯU và đối chiếu nhưng CHƯA được thực thi ở tầng mạng — "
                + "kết nối khớp rule Block VẪN CHẠY."));
        }

        // Driver kernel-mode khong duoc dong goi/nap trong ban nay (xem
        // app/ops/docs/known-limitations.md). Day la suy giam THUONG TRUC —
        // phai noi ro qua API thay vi de UI hard-code mot dong chu tinh.
        list.Add(new ProtectionDegradation("kernel-driver", ProtectionDegradation.Warning,
            "Driver kernel-mode (minifilter/ELAM/WFP) CHƯA được cài — chặn tiến trình chỉ là "
            + "biện pháp giảm thiểu hậu khởi tạo ở user-mode, không chặn trước khi tiến trình chạy."));

        return list;
    }

    public static bool HasCritical(IReadOnlyList<ProtectionDegradation> degradations) =>
        degradations.Any(d => d.Severity == ProtectionDegradation.Critical);

    public static string LevelOf(IReadOnlyList<ProtectionDegradation> degradations) =>
        HasCritical(degradations) ? "critical" : (degradations.Count > 0 ? "degraded" : "ok");
}
