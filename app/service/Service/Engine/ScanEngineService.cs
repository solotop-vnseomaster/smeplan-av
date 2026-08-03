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

    public bool Initialize(string? signatureDbPath, string? yaraRulesDir)
    {
        var rc = ScanEngineInterop.Engine_Initialize(signatureDbPath, yaraRulesDir, 0.001);
        _initialized = rc == 0;
        if (!_initialized)
        {
            _logger.LogWarning("Scan engine khoi tao that bai (rc={Rc})", rc);
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
