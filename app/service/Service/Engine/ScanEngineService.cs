using System.Text;
using Antivirus.Service.Models;

namespace Antivirus.Service.Engine;

// Wrapper quan ly cho scan_engine.dll — day la "scan engine" trong kien truc
// 6 khoi (modules/02-kien-truc.md), dung chung cho ca full scan lan
// real-time scanning (goi tu nhieu noi, engine khong biet ai goi no).
public sealed class ScanEngineService : IDisposable
{
    private readonly ILogger<ScanEngineService> _logger;
    private bool _initialized;

    public ScanEngineService(ILogger<ScanEngineService> logger)
    {
        _logger = logger;
    }

    // Khop voi ENGINE_INIT_SIGNATURE_DB_FAILED trong engine/include/scan_engine.h.
    private const int EngineInitSignatureDbFailed = 1;

    // TRUE khi engine da khoi tao nhung KHONG co CSDL chu ky dung duoc —
    // tang phat hien theo hash khong hoat dong. Phai duoc phan anh ra trang
    // thai bao ve hien thi cho nguoi dung, khong duoc coi la "dang bao ve
    // day du".
    public bool SignatureDbMissing { get; private set; }

    public bool Initialize(string? signatureDbPath, string? yaraRulesDir)
    {
        var rc = ScanEngineInterop.Engine_Initialize(signatureDbPath, yaraRulesDir, 0.001);
        // [SUA LOI NGHIEM TRONG] rc == ENGINE_INIT_SIGNATURE_DB_FAILED nghia la
        // engine chay duoc nhung khong co CSDL hash — truoc day engine tra 0
        // cho ca truong hop nay va Program.cs con bo qua luon gia tri tra ve,
        // nen service phuc vu binh thuong voi mot tang phat hien da chet ma
        // khong co dau hieu nao o bat ky dau.
        // [SUA LOI NGHIEM TRONG — SEAM] TRUOC DAY chi xet rc. Nhung khi
        // signatureDbPath la null (Program.cs dat null khi File.Exists tra
        // false — tuc la may HOAN TOAN chua co CSDL chu ky), phia C++ o
        // pipeline.cpp short-circuit dieu kien `if (signature_db_path && ...)`
        // nen sig_db_failed giu nguyen false va Engine_Initialize tra 0.
        // Ket qua: SignatureDbMissing = false tren dung cai may KHONG CO chu
        // ky nao ca, va ProtectionStatusService (chi doc co nay) bao
        // protectionEnabled = true.
        //
        // Program.cs co biet su that — no viet `engine.SignatureDbMissing ||
        // sigDb is null` khi ghi log — nhung chi dung de LOG roi vut di, nen
        // thong tin do khong bao gio toi duoc tang trang thai. Ba vung deu
        // "hop ly" khi doc rieng; lo hong nam o duong noi giua chung.
        //
        // Sua tai NGUON: "thieu CSDL chu ky" phai dung nghia la khong co CSDL
        // hash dung duoc — bat ke vi khong co duong dan hay vi nap that bai.
        // Thu tu quan trong: _initialized phai duoc suy ra tu RC truoc. Neu
        // tinh no tu SignatureDbMissing (da mo rong ben duoi), mot lan khoi
        // tao THAT BAI THAT SU (rc khac 0 va khac 1) tren may khong co duong
        // dan CSDL se bi che thanh "da khoi tao".
        _initialized = rc == 0 || rc == EngineInitSignatureDbFailed;
        SignatureDbMissing = _initialized
            && (rc == EngineInitSignatureDbFailed || string.IsNullOrEmpty(signatureDbPath));
        if (!_initialized)
        {
            _logger.LogWarning("Scan engine khoi tao that bai (rc={Rc})", rc);
        }
        else if (SignatureDbMissing)
        {
            _logger.LogError(
                "Scan engine da chay NHUNG KHONG nap duoc CSDL chu ky tu {Db} — phat hien theo hash DANG TAT, chi con YARA/heuristic",
                signatureDbPath ?? "(khong co)");
        }
        else
        {
            _logger.LogInformation(
                "Scan engine da san sang. CSDL signature: {Db}, thu muc YARA: {Yara}",
                signatureDbPath ?? "(khong co)", yaraRulesDir ?? "(khong co)");
        }
        return _initialized;
    }

    public ScanResultDto ScanFile(string filePath)
    {
        try
        {
            var rc = ScanEngineInterop.Engine_ScanFile(filePath, out var native);
            if (rc != 0)
            {
                return ErrorResult("Loi goi Engine_ScanFile (rc=" + rc + ")");
            }
            return ToManaged(native);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Loi khi quet file {Path}", filePath);
            return ErrorResult("Ngoai le khi quet: " + ex.Message);
        }
    }

    public ScanResultDto ScanBuffer(byte[] data, string? virtualName)
    {
        try
        {
            var rc = ScanEngineInterop.Engine_ScanBuffer(data, (UIntPtr)data.LongLength, virtualName, out var native);
            if (rc != 0)
            {
                return ErrorResult("Loi goi Engine_ScanBuffer (rc=" + rc + ")");
            }
            return ToManaged(native);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Loi khi quet buffer {Name}", virtualName);
            return ErrorResult("Ngoai le khi quet: " + ex.Message);
        }
    }

    private static ScanResultDto ToManaged(ScanEngineInterop.NativeScanResult native)
    {
        return new ScanResultDto
        {
            Verdict = (ScanVerdict)native.Verdict,
            Stage = (DetectionStage)native.Stage,
            ThreatId = native.ThreatId,
            Severity = native.Severity,
            HeuristicScore = native.HeuristicScore,
            Sha256Hex = NulTerminatedToString(native.Sha256Hex),
            Reason = NulTerminatedToString(native.Reason),
        };
    }

    private static string NulTerminatedToString(byte[] raw)
    {
        int len = Array.IndexOf(raw, (byte)0);
        if (len < 0) len = raw.Length;
        return Encoding.UTF8.GetString(raw, 0, len);
    }

    private static ScanResultDto ErrorResult(string reason) => new()
    {
        Verdict = ScanVerdict.ScanError,
        Stage = DetectionStage.IoError,
        Reason = reason,
        Sha256Hex = "",
    };

    public static bool BuildSignatureDb(string csvPath, string outDbPath)
    {
        return ScanEngineInterop.Engine_BuildSignatureDb(csvPath, outDbPath) == 0;
    }

    // [SUA LOI NGHIEM TRONG] Dung khi HOAN DOI file CSDL luc dang chay
    // (update service) — KHONG dung Initialize() cho truong hop nay. Phai
    // goi UnmapSignatureDb() TRUOC KHI File.Move/rename file CSDL, roi
    // LoadSignatureDb() SAU KHI da rename xong; nguoc lai Windows tu choi
    // rename file con dang co view memory-map dang hoat dong. Xem
    // scan_engine.h va UpdateClientService.RebuildAndSwap.
    public void UnmapSignatureDb() => ScanEngineInterop.Engine_UnmapSignatureDb();

    public bool LoadSignatureDb(string signatureDbPath) =>
        ScanEngineInterop.Engine_LoadSignatureDb(signatureDbPath) == 0;

    public string? Sha256File(string filePath)
    {
        try
        {
            var buf = new byte[65];
            var rc = ScanEngineInterop.Engine_Sha256File(filePath, buf);
            if (rc != 0) return null;
            return NulTerminatedToString(buf);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Khong hash duoc file {Path}", filePath);
            return null;
        }
    }

    public void Dispose()
    {
        if (_initialized)
        {
            ScanEngineInterop.Engine_Shutdown();
            _initialized = false;
        }
    }
}
