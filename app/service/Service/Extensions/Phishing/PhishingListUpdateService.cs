using System.Security.Cryptography.X509Certificates;
using System.Text;
using Antivirus.Service.Audit;
using Antivirus.Service.Update;

namespace Antivirus.Service.Extensions.Phishing;

// "tai lieu moi.txt": "danh sach domain/IP phishing... nen den tu nguon
// cap nhat thuong xuyen (TAI SU DUNG dung co che update service theo delta
// da xay cho CSDL virus o bai truoc, chi khac loai du lieu tai ve)".
//
// [QUYET DINH TRIEN KHAI] Tai su dung THAT hai thanh phan cot loi cua
// UpdateClientService: IUpdatePackageSource (nguon goi, cung
// LocalFolderUpdatePackageSource nhung tro toi thu muc rieng
// "update-drop-phishing") va UpdatePackageVerifier (ky/xac minh RSA-SHA256
// tren cung certificate cong ty). Diem khac: KHONG dung lai co che delta
// tuan tu nhieu buoc (v1_to_v2.delta...) cua CSDL nhi phan — danh sach
// domain/IP la du lieu van ban nho, moi lan cap nhat thay THE TOAN BO danh
// sach bang MOT goi "full" duy nhat don gian hon la xay lai toan bo logic
// gop delta cho mot dinh dang khac, van giu dung phan quan trong nhat can
// tai su dung: nguon goi + xac minh chu ky truoc khi ap dung.
public sealed class PhishingListUpdateService : BackgroundService
{
    public static readonly TimeSpan DefaultCheckInterval = TimeSpan.FromHours(2);

    private readonly IUpdatePackageSource _source;
    private readonly PhishingListStore _store;
    private readonly AuditLogger _audit;
    private readonly ILogger<PhishingListUpdateService> _logger;
    // [SUA LOI CHAN PHAT HANH — A3] Xem ghi chu cung noi dung o
    // UpdateClientService: null = chua cau hinh neo tin cay => kenh cap
    // nhat danh sach phishing tat han, goi nao cung bi tu choi (fail-closed),
    // phan con lai cua service van chay.
    private readonly X509Certificate2? _trustedCert;
    private readonly TimeSpan _interval;
    private readonly string _versionStatePath;

    public int CurrentVersion { get; private set; }

    // Phoi ra /api/phishing/stats de trang thai suy giam nhin thay duoc.
    public bool SigningTrustConfigured => _trustedCert is not null;

    // Cua DUY NHAT di toi UpdatePackageVerifier trong class nay.
    private bool TryVerifyPackage(byte[] signedPackage, out byte[] payload)
    {
        if (_trustedCert is null)
        {
            payload = Array.Empty<byte>();
            return false;
        }
        return UpdatePackageVerifier.TryVerifyAndExtract(signedPackage, _trustedCert, out payload);
    }

    public PhishingListUpdateService(IUpdatePackageSource source, PhishingListStore store, AuditLogger audit,
        ILogger<PhishingListUpdateService> logger, X509Certificate2? trustedCert, TimeSpan? interval = null,
        string? versionStatePath = null)
    {
        _source = source;
        _store = store;
        _audit = audit;
        _logger = logger;
        _trustedCert = trustedCert;
        _interval = interval ?? DefaultCheckInterval;
        _versionStatePath = versionStatePath ?? Path.Combine(Antivirus.Service.Data.DataPaths.StateDir, "phishing_list_version.json");
        CurrentVersion = LoadCurrentVersion();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_trustedCert is null)
        {
            _logger.LogWarning(
                "Kenh cap nhat danh sach phishing DA TAT vi thieu cau hinh UpdateSigning:CertPath / " +
                "UpdateSigning:CertPasswordEnvVar — danh sach hien co van duoc dung de kiem tra URL, " +
                "nhung se KHONG duoc cap nhat tu dong.");
            _audit.Log("phishing-update",
                "Kenh cap nhat danh sach phishing DA TAT: thieu certificate ky goi cap nhat (fail-closed)");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await CheckAndApplyAsync(stoppingToken); }
            catch (Exception ex) { _logger.LogError(ex, "Loi cap nhat danh sach phishing"); }

            try { await Task.Delay(_interval, stoppingToken); }
            catch (TaskCanceledException) { break; }
        }
    }

    public async Task<bool> CheckAndApplyAsync(CancellationToken ct)
    {
        var latest = await _source.CheckLatestVersionAsync(ct);
        if (latest.LatestVersion <= CurrentVersion)
        {
            return true; // da o phien ban moi nhat, khong phai loi
        }

        string pkgName = $"phishing_full_v{latest.LatestVersion}.full";
        var pkg = await _source.DownloadPackageAsync(pkgName, ct);
        if (pkg is null)
        {
            _audit.Log("phishing-update", $"ERR: khong tai duoc goi danh sach phishing {pkgName}");
            return false;
        }

        if (!TryVerifyPackage(pkg, out var payload))
        {
            _audit.Log("phishing-update", $"ERR: goi {pkgName} KHONG hop le chu ky so — tu choi ap dung");
            _logger.LogWarning("Goi danh sach phishing {Pkg} khong verify duoc chu ky, bi tu choi", pkgName);
            return false;
        }

        var (domains, ips) = ParsePayload(payload);

        // [SUA LOI NGHIEM TRONG] ReplaceAll XOA SACH danh sach cu roi ghi
        // danh sach moi. TRUOC DAY khong co guard nao: mot goi CO CHU KY
        // HOP LE nhung sai dinh dang (payload rong, sai ky tu phan cach,
        // encoding khac) parse ra 0 muc -> toan bo blacklist bi xoa sach,
        // SaveCurrentVersion ghi nhan da len phien ban moi nen KHONG BAO GIO
        // tai lai nua, va audit ghi "Da cap nhat... 0 domain" nhu mot thanh
        // cong. Chong phishing chet vinh vien trong im lang.
        //
        // Fail-closed: mot ban cap nhat lam RONG danh sach la ket qua vo ly
        // trong moi tinh huong hop le — tu choi ap dung va GIU danh sach cu.
        if (domains.Count == 0 && ips.Count == 0)
        {
            _audit.Log("phishing-update",
                $"ERR: goi {pkgName} parse ra 0 domain va 0 IP — TU CHOI ap dung de khong xoa sach danh sach hien co");
            _logger.LogError(
                "Goi danh sach phishing {Pkg} co chu ky hop le nhung khong chua muc nao — giu nguyen danh sach cu ({Count} muc)",
                pkgName, _store.Count());
            return false;
        }

        _store.ReplaceAll(domains, ips);
        SaveCurrentVersion(latest.LatestVersion);
        _audit.Log("phishing-update", $"Da cap nhat danh sach phishing len v{latest.LatestVersion}: {domains.Count} domain, {ips.Count} IP");
        return true;
    }

    private static (List<string> Domains, List<string> Ips) ParsePayload(byte[] payload)
    {
        var domains = new List<string>();
        var ips = new List<string>();
        var text = Encoding.UTF8.GetString(payload);
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;
            var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2) continue;
            if (string.Equals(parts[0], "DOMAIN", StringComparison.OrdinalIgnoreCase)) domains.Add(parts[1]);
            else if (string.Equals(parts[0], "IP", StringComparison.OrdinalIgnoreCase)) ips.Add(parts[1]);
        }
        return (domains, ips);
    }

    private int LoadCurrentVersion() => Antivirus.Service.Common.JsonVersionState.Load(_versionStatePath);

    private void SaveCurrentVersion(int version)
    {
        CurrentVersion = version;
        Antivirus.Service.Common.JsonVersionState.Save(_versionStatePath, version);
    }
}
