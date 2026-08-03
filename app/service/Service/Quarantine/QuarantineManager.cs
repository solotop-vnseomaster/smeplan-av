using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Models;

namespace Antivirus.Service.Quarantine;

// business-rules/05-nghiep-vu.md muc "File trong Quarantine" +
// security/09-bao-mat.md muc 3 "Luu tru & bao ve du lieu nhay cam".
public sealed class QuarantineManager
{
    // Khoa XOR co dinh: CHI de ngan chuong trinh khac doc/chay tinh co,
    // KHONG phai chong phan tich chuyen sau (security/09 muc 3, ghi ro
    // trong chinh spec: "muc dich chi la ngan doc/chay tinh co").
    private static readonly byte[] XorKey =
    {
        0x5A, 0x3C, 0x91, 0xE7, 0x18, 0xAF, 0x62, 0xD4,
        0x0B, 0x77, 0xC5, 0x29, 0x94, 0x4E, 0xB8, 0xF1,
    };

    private readonly QuarantineStore _store;
    private readonly AuditLogger _audit;
    private readonly ILogger<QuarantineManager> _logger;
    private readonly string _quarantineDir;

    // quarantineDir/applyAcl la optional: mac dinh dung DataPaths.QuarantineDir
    // + tu dat ACL SYSTEM-only (san xuat that, xem SEC-06). Kiem thu don vi
    // truyen mot thu muc tam rieng va applyAcl=false vi tien trinh test
    // chay voi quyen nguoi dung thuong se tu khoa chinh minh ra neu bat ACL —
    // viec ACL co hoat dong dung hay khong da duoc AclProtection kiem thu
    // gian tiep qua viec service that chay duoi quyen SYSTEM.
    public QuarantineManager(QuarantineStore store, AuditLogger audit, ILogger<QuarantineManager> logger,
        string? quarantineDir = null, bool applyAcl = true)
    {
        _store = store;
        _audit = audit;
        _logger = logger;
        _quarantineDir = quarantineDir ?? DataPaths.QuarantineDir;
        Directory.CreateDirectory(_quarantineDir);

        if (applyAcl)
        {
            try
            {
                AclProtection.ProtectQuarantineDirectory(_quarantineDir);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Khong dat duoc ACL cho thu muc quarantine (can chay quyen SYSTEM/Administrator) — han che moi truong da biet");
            }
        }
    }

    // business-rules/05: "Malicious -> Quarantined (tu dong, khi file khong
    // nam trong thu muc he thong duoc bao ve)"; neu nam trong thu muc WRP
    // bao ve -> PendingManualConfirmation, KHONG tu dong quarantine.
    public QuarantineRecord QuarantineFile(string originalPath, string sha256, string detectionReason)
    {
        bool inProtectedSystemDir = IsInWindowsResourceProtectedDirectory(originalPath);
        var quarantineId = Guid.NewGuid().ToString("N");
        var fileInfo = new FileInfo(originalPath);
        ulong size = fileInfo.Exists ? (ulong)fileInfo.Length : 0;

        var record = new QuarantineRecord
        {
            QuarantineId = quarantineId,
            OriginalPath = originalPath,
            OriginalFilename = Path.GetFileName(originalPath),
            Sha256Hash = sha256,
            DetectionReason = detectionReason,
            QuarantinedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            FileSize = size,
            Status = inProtectedSystemDir ? QuarantineStatus.PendingManualConfirmation : QuarantineStatus.Active,
        };

        if (inProtectedSystemDir)
        {
            _store.Add(record);
            _audit.Log("quarantine",
                $"File he thong bi gan co Malicious nhung KHONG tu dong quarantine (can xac nhan thu cong): {originalPath}",
                new { quarantineId, originalPath });
            _logger.LogWarning("File he thong duoc bao ve bi gan co Malicious, cho xac nhan thu cong: {Path}", originalPath);
            return record;
        }

        // [SUA LOI NGHIEM TRONG] TRUOC DAY thu tu la MoveIntoQuarantine() (di
        // chuyen + xoa file goc) RỒI MỚI _store.Add(record) — neu ghi DB that
        // bai giua chung (dia day, DB bi khoa, ngoai le bat ky...), file goc
        // DA BI XOA nhung KHONG CO ban ghi nao theo doi no trong QuarantineStore,
        // mat dau vet vinh vien (khong the List()/Restore() lai duoc, ke ca
        // biet ten file .qtn tren dia cung khong the anh xa nguoc ve
        // OriginalPath). Sua: ghi DB TRUOC (trang thai Quarantined coi nhu
        // "cam ket" se di chuyen), roi MOI di chuyen file that su; neu buoc
        // di chuyen that bai, ROLLBACK ban ghi DB vua ghi (xoa no di) — khi
        // do file goc VAN CON NGUYEN vi tri cu (an toan hon nhieu so voi mat
        // dau vet), va loi duoc nem tiep de nguoi goi biet thao tac that bai.
        record.Status = QuarantineStatus.Quarantined;
        _store.Add(record);
        try
        {
            MoveIntoQuarantine(originalPath, quarantineId);
        }
        catch (Exception ex)
        {
            _store.Delete(quarantineId);
            _logger.LogError(ex,
                "Loi di chuyen file vao quarantine, da rollback ban ghi DB (file goc van con nguyen): {Path}",
                originalPath);
            throw;
        }
        _audit.Log("quarantine", $"Da cach ly file: {originalPath} (ly do: {detectionReason})",
            new { quarantineId, originalPath, sha256 });
        return record;
    }

    // "Malicious -> PendingManualConfirmation -> Quarantined (chi sau khi
    // nguoi dung xac nhan thu cong)"
    public bool ConfirmManualQuarantine(string quarantineId)
    {
        var record = _store.Get(quarantineId);
        if (record is null || record.Status != QuarantineStatus.PendingManualConfirmation) return false;

        // Cung nguyen tac chong mo côi ban ghi nhu QuarantineFile o tren: cap
        // nhat trang thai DB TRUOC, di chuyen file SAU; that bai thi rollback
        // trang thai ve PendingManualConfirmation (file he thong goc chua
        // bao gio bi dong den trong nhanh nay, van an toan de giu nguyen
        // trang thai cho xac nhan lai).
        _store.UpdateStatus(quarantineId, QuarantineStatus.Quarantined);
        try
        {
            MoveIntoQuarantine(record.OriginalPath, quarantineId);
        }
        catch (Exception ex)
        {
            _store.UpdateStatus(quarantineId, QuarantineStatus.PendingManualConfirmation);
            _logger.LogError(ex,
                "Loi di chuyen file he thong vao quarantine, da rollback trang thai ve PendingManualConfirmation: {Path}",
                record.OriginalPath);
            throw;
        }
        _audit.Log("quarantine", $"Nguoi dung xac nhan quarantine thu cong file he thong: {record.OriginalPath}",
            new { quarantineId });
        return true;
    }

    // "Quarantined -> Restored (nguoi dung xac nhan false positive qua giao
    // dien chinh, khoi phuc chinh xac ve vi tri goc bang metadata da luu)"
    // — CHI qua ham nay (goi tu API cua UI chinh), khong qua Explorer.
    public bool Restore(string quarantineId)
    {
        var record = _store.Get(quarantineId);
        if (record is null || record.Status != QuarantineStatus.Quarantined) return false;

        var quarantinedPath = Path.Combine(_quarantineDir, quarantineId + ".qtn");
        if (!File.Exists(quarantinedPath))
        {
            _logger.LogError("Khong tim thay file quarantine {Id} tren dia", quarantineId);
            return false;
        }

        // [SUA LOI TRUNG BINH] TRUOC DAY File.WriteAllBytes ghi de thang len
        // record.OriginalPath ma khong kiem tra file co ton tai san hay
        // khong — neu nguoi dung (hoac chuong trinh khac) da tao lai mot
        // file MOI cung ten tai vi tri do sau khi quarantine (truong hop
        // hoan toan hop ly: file bi xoa/di chuyen roi nguoi dung luu file
        // khac vao dung cho trong), Restore() se AM THAM XOA MAT noi dung
        // file moi do ma khong canh bao gi — mat du lieu nguoi dung. Sua:
        // that bai an toan (khong ghi de, tra ve false + log ro rang) neu
        // vi tri goc DA CO file khac, thay vi ghi de trong im lang.
        if (File.Exists(record.OriginalPath))
        {
            _logger.LogError(
                "Khong the khoi phuc {Id}: vi tri goc {Path} da co mot file khac (co the da duoc tao lai sau khi quarantine) — tu choi ghi de de tranh mat du lieu",
                quarantineId, record.OriginalPath);
            return false;
        }

        var encrypted = File.ReadAllBytes(quarantinedPath);
        var decrypted = XorTransform(encrypted);
        Directory.CreateDirectory(Path.GetDirectoryName(record.OriginalPath)!);
        File.WriteAllBytes(record.OriginalPath, decrypted);
        File.Delete(quarantinedPath);

        _store.UpdateStatus(quarantineId, QuarantineStatus.Restored);
        _audit.Log("quarantine", $"Da khoi phuc file tu quarantine ve: {record.OriginalPath}", new { quarantineId });
        return true;
    }

    public List<QuarantineRecord> List() => _store.List();

    // [TINH NANG THEO YEU CAU NGUOI DUNG] "Quarantine co xoa duoc khong,
    // neu duoc thi xoa the nao" — truoc day CHI co Restore (khoi phuc ve
    // vi tri goc), khong co cach nao xoa han file da cach ly. Ham nay xoa
    // VINH VIEN: file .qtn (neu con, chi ton tai khi status=Quarantined)
    // roi moi xoa ban ghi trong DB — KHONG the hoan tac.
    public bool DeletePermanently(string quarantineId)
    {
        var record = _store.Get(quarantineId);
        if (record is null) return false;

        if (record.Status == QuarantineStatus.Quarantined)
        {
            var quarantinedPath = Path.Combine(_quarantineDir, quarantineId + ".qtn");
            try { if (File.Exists(quarantinedPath)) File.Delete(quarantinedPath); }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Khong xoa duoc file quarantine {Id} tren dia, van xoa ban ghi DB", quarantineId);
            }
        }
        // Trang thai PendingManualConfirmation: file goc chua bao gio bi di
        // chuyen (van nam nguyen vi tri that trong thu muc he thong duoc
        // bao ve) — xoa ban ghi o day KHONG dung/xoa file goc, chi ngung
        // theo doi "cho xac nhan" nay.

        _store.Delete(quarantineId);
        _audit.Log("quarantine", $"Da xoa vinh vien khoi quarantine: {record.OriginalPath}", new { quarantineId });
        return true;
    }

    private void MoveIntoQuarantine(string originalPath, string quarantineId)
    {
        // BIZ-08: doi ten thanh dinh danh khong mang phan mo rong goc (GUID)
        // + ma hoa noi dung truoc khi di chuyen.
        var destPath = Path.Combine(_quarantineDir, quarantineId + ".qtn");
        var content = File.ReadAllBytes(originalPath);
        var encrypted = XorTransform(content);
        File.WriteAllBytes(destPath, encrypted);
        File.Delete(originalPath);
    }

    private static byte[] XorTransform(byte[] data)
    {
        var output = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            output[i] = (byte)(data[i] ^ XorKey[i % XorKey.Length]);
        }
        return output;
    }

    // Xap xi WRP (Windows Resource Protection): cac thu muc he thong loi
    // duoc Windows bao ve, dung lam tin hieu "khong tu dong quarantine".
    private static readonly string[] ProtectedRoots =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
    };

    public static bool IsInWindowsResourceProtectedDirectory(string path)
    {
        return ProtectedRoots.Where(r => !string.IsNullOrEmpty(r))
            .Any(root => Antivirus.Service.Common.PathUtil.IsPathUnderDirectory(path, root));
    }
}
