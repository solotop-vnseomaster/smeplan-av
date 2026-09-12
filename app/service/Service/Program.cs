using System.Net;
using System.Text.Json.Serialization;
using Antivirus.Service.Archive;
using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Downloads;
using Antivirus.Service.Engine;
using Antivirus.Service.Extensions;
using Antivirus.Service.FullScan;
using Antivirus.Service.Models;
using Antivirus.Service.Quarantine;
using Antivirus.Service.Security;
using Antivirus.Service.Settings;
using Antivirus.Service.Trust;
using Antivirus.Service.Update;

var builder = WebApplication.CreateBuilder(args);

// [SUA LOI CHAN PHAT HANH] Xem ghi chu tai Service.csproj: khong co dong
// nay, tien trinh chay duoi SCM khong bao gio bao SERVICE_RUNNING, SCM tra
// loi 1053 va MSI rollback ca ban cai. UseWindowsService() la no-op khi
// tien trinh KHONG duoc SCM khoi chay (chay tay tu console luc dev van
// binh thuong), nen an toan de bat vo dieu kien.
builder.Host.UseWindowsService(options =>
{
    // Phai trung Name trong <ServiceInstall> cua app/installer/Product.wxs.
    options.ServiceName = "SmePlanAvService";
});

// [SUA LOI CHAN PHAT HANH — THU TU BAT BUOC] Khoi nay PHAI dung o day, TRUOC
// moi dang ky DI ben duoi.
//
// Truoc day no nam sau builder.Build(). Nhung cac dong `new RuleStore(
// DataPaths.RulesDbPath)`, `new QuarantineStore(...)`, ... duoc lượng gia
// TUC THI luc dang ky, va moi thuoc tinh DataPaths.Xxx goi EnsureDir ->
// Directory.CreateDirectory. Nghia la toan bo cay %ProgramData%\AntivirusApp
// da nam tren dia voi ACL KE THUA tu ProgramData (Users tao/ghi duoc,
// CREATOR OWNER FullControl) truoc khi dong khoa ACL kip chay. Va neu
// CompanyCertificateProvider ben duoi nem loi (thieu cau hinh cert tren may
// san xuat) thi dong khoa ACL KHONG BAO GIO chay toi — cay du lieu ton tai
// vinh vien khong duoc bao ve tren MOI may cai bang MSI.
//
// Tu do mo ra: token fixation qua api-token.txt (ghi truoc mot token dung
// dinh dang), ghi de signatures.avsigdb bang CSDL rong, sua rules.db/
// settings.json, va doc file PFX khoa riêng de tu ky goi cap nhat.
//
// ProtectAllDataDirectories tu goi Directory.CreateDirectory theo dung thu
// tu (RootDir truoc de ngat ke thua o goc, roi tung thu muc con), nen goi
// no o day vua tao vua khoa — khong con cua so nao de chen vao giua.
var aclErrors = new List<(string Dir, Exception Error)>();
var aclFailures = AclProtection.ProtectAllDataDirectories(
    (dir, ex) => aclErrors.Add((dir, ex)));


// modules/02-kien-truc.md: UI la tang rieng, chi hien thi/nhan thao tac,
// KHONG tu xu ly logic phat hien — moi logic nam trong service nay. Vi vay
// API chi bind loopback (127.0.0.1), khong bao gio nghe tren mang ngoai.
builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, 5270);
});

// Serialize enum (ScanVerdict, DetectionStage, QuarantineStatus, ...) thanh
// ten chuoi (vi du "Malicious") thay vi so nguyen — de UI doc va so sanh
// truc tiep, khop voi cac gia tri verdict trong business-rules/05.
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

builder.Services.AddCors(options =>
{
    // [SUA LOI NHO] Truoc day con them "...5271" — Kestrel o tren CHI nghe
    // dung MOT port (5270, xem ConfigureKestrel ngay ben tren), khong co
    // listener nao tren 5271 ca. Entry thua nay khong mang lai loi ich
    // chuc nang nao, chi la du thua/gay nham lan khi doc code.
    options.AddDefaultPolicy(policy => policy
        .WithOrigins("http://127.0.0.1:5270", "http://localhost:5270")
        .AllowAnyHeader()
        .AllowAnyMethod());
});

// --- Dang ky cac thanh phan cot loi (DI singletons) ---
builder.Services.AddSingleton<ApiTokenProvider>();
builder.Services.AddSingleton(new AuditLogger(DataPaths.AuditLogPath));
builder.Services.AddHostedService<AuditLogMaintenanceService>();
builder.Services.AddSingleton<ScanEngineService>();
builder.Services.AddSingleton<ArchiveScanner>();
builder.Services.AddSingleton(new RuleStore(DataPaths.RulesDbPath));
builder.Services.AddSingleton(new QuarantineStore(DataPaths.QuarantineDbPath));
builder.Services.AddSingleton<QuarantineManager>();
builder.Services.AddSingleton<PermissionRequestBroker>();
// Cache dung CHUNG cho moi lan danh gia: mot binary duoc bam va xac minh chu
// ky mot lan, cac lan chay sau chi tra ve ket qua da co. Dang ky o tang DI de
// no that su dung chung, khong phai moi instance mot cache rieng.
builder.Services.AddSingleton<FileIdentityCache>();
builder.Services.AddSingleton<ProcessTrustEngine>();
builder.Services.AddSingleton<DownloadsDecisionBroker>();
builder.Services.AddSingleton(new ScanCacheStore(DataPaths.ScanCacheDbPath));
builder.Services.AddSingleton(sp => new AppSettingsStore(DataPaths.SettingsPath, sp.GetRequiredService<AuditLogger>()));

// --- "tai lieu moi.txt": Task scheduler noi bo (dang ky truoc cac module
// dinh ky moi vi chung phu thuoc no de idle-gate) ---
builder.Services.AddSingleton<Antivirus.Service.Extensions.Scheduler.BackgroundTaskScheduler>();

// --- "tai lieu moi.txt": Event bus + Gaming mode (dang ky truoc FullScanService vi no phu thuoc GamingModeService) ---
builder.Services.AddSingleton<EventBus>();
builder.Services.AddHostedService<EventBusSweepService>();
builder.Services.AddSingleton<GamingModeService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<GamingModeService>());

builder.Services.AddSingleton(new Antivirus.Service.Extensions.Firewall.FirewallRuleStore(DataPaths.FirewallRulesDbPath));
builder.Services.AddSingleton<Antivirus.Service.Extensions.Firewall.ConnectionMonitor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Antivirus.Service.Extensions.Firewall.ConnectionMonitor>());

builder.Services.AddSingleton(new Antivirus.Service.Extensions.Ransomware.VersionStore(DataPaths.VersionStoreDbPath, DataPaths.VersionStoreDir));
builder.Services.AddSingleton<Antivirus.Service.Extensions.Ransomware.RansomwareGuardService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Antivirus.Service.Extensions.Ransomware.RansomwareGuardService>());

builder.Services.AddSingleton<FullScanService>();

// UsbMonitorService phu thuoc FullScanService (tu dong quet volume USB moi
// gan) nen dang ky sau FullScanService.
builder.Services.AddSingleton(new Antivirus.Service.Extensions.Usb.UsbRuleStore(DataPaths.UsbRulesDbPath));
builder.Services.AddSingleton<Antivirus.Service.Extensions.Usb.UsbMonitorService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Antivirus.Service.Extensions.Usb.UsbMonitorService>());

builder.Services.AddSingleton<Antivirus.Service.Extensions.Vulnerability.VulnerabilityScanService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Antivirus.Service.Extensions.Vulnerability.VulnerabilityScanService>());

builder.Services.AddSingleton(new Antivirus.Service.Extensions.Webcam.CamMicWhitelistStore(DataPaths.CamMicWhitelistDbPath));
builder.Services.AddSingleton<Antivirus.Service.Extensions.Webcam.WebcamMicMonitorService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Antivirus.Service.Extensions.Webcam.WebcamMicMonitorService>());

builder.Services.AddSingleton(new Antivirus.Service.Extensions.Network.KnownNetworkDeviceStore(DataPaths.KnownNetworkDevicesDbPath));
builder.Services.AddSingleton<Antivirus.Service.Extensions.Network.HomeNetworkMonitorService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Antivirus.Service.Extensions.Network.HomeNetworkMonitorService>());

// [SUA LOI CHAN PHAT HANH — A3] TRUOC DAY dong nay lượng gia
// GetOrCreateForEnvironment NGAY tai cho dang ky DI. Tren may cai bang MSI,
// Environment = Production (Product.wxs khong dat bien moi truong nao) va
// UpdateSigning:CertPath = null, nen no nem InvalidOperationException va
// service KHONG BAO GIO khoi dong duoc — khong phai "khong tu cap nhat",
// ma la KHONG CO AV NAO CHAY CA.
//
// Quyet dinh fail-closed goc van dung va duoc GIU NGUYEN: khong bao gio am
// tham dung cert dev de ky goi cap nhat trong san xuat. Cai thay doi la
// PHAM VI cua that bai — thay vi giet ca service, no chi tat rieng kenh cap
// nhat (UpdateClientService + PhishingListUpdateService tu choi moi goi,
// xem TryVerifyPackage o hai class do), con quet/real-time/quarantine/
// firewall van chay. Trang thai suy giam duoc phoi ra /api/status va ghi
// audit, khong am tham.
System.Security.Cryptography.X509Certificates.X509Certificate2? updateSigningCert = null;
string? updateSigningDisabledReason = null;
try
{
    updateSigningCert = CompanyCertificateProvider.GetOrCreateForEnvironment(
        builder.Environment, builder.Configuration);
}
catch (Exception ex)
{
    updateSigningDisabledReason = ex.Message;
}
builder.Services.AddSingleton<IUpdatePackageSource>(_ =>
    new LocalFolderUpdatePackageSource(DataPaths.UpdateDropDir));
builder.Services.AddSingleton<UpdateClientService>(sp => new UpdateClientService(
    sp.GetRequiredService<IUpdatePackageSource>(),
    sp.GetRequiredService<ScanEngineService>(),
    sp.GetRequiredService<AuditLogger>(),
    sp.GetRequiredService<ILogger<UpdateClientService>>(),
    updateSigningCert,
    scanCache: sp.GetRequiredService<ScanCacheStore>()));
builder.Services.AddHostedService(sp => sp.GetRequiredService<UpdateClientService>());

// --- "tai lieu moi.txt": Cloud threat intelligence (mock local backend) ---
builder.Services.AddSingleton(new Antivirus.Service.Extensions.CloudIntel.CloudReputationClient(DataPaths.CloudReputationDbPath));

// --- Sandbox verdict aggregator (thuan logic tinh diem, khong trang thai) ---
builder.Services.AddSingleton<Antivirus.Service.Extensions.Sandbox.SandboxVerdictAggregator>();

// --- Anti-phishing: danh sach domain/IP (tai su dung IUpdatePackageSource +
// UpdatePackageVerifier cua UpdateClientService, tro toi thu muc drop
// RIENG de khong dung chung version/goi voi kenh CSDL virus) ---
builder.Services.AddSingleton(new Antivirus.Service.Extensions.Phishing.PhishingListStore(DataPaths.PhishingListDbPath));
builder.Services.AddSingleton<Antivirus.Service.Extensions.Phishing.PhishingUrlChecker>();
builder.Services.AddSingleton<Antivirus.Service.Extensions.Phishing.PhishingListUpdateService>(sp => new Antivirus.Service.Extensions.Phishing.PhishingListUpdateService(
    new LocalFolderUpdatePackageSource(DataPaths.PhishingUpdateDropDir),
    sp.GetRequiredService<Antivirus.Service.Extensions.Phishing.PhishingListStore>(),
    sp.GetRequiredService<AuditLogger>(),
    sp.GetRequiredService<ILogger<Antivirus.Service.Extensions.Phishing.PhishingListUpdateService>>(),
    updateSigningCert));
builder.Services.AddHostedService(sp => sp.GetRequiredService<Antivirus.Service.Extensions.Phishing.PhishingListUpdateService>());

// --- Risk score tong hop (EXT-RISK-01/02) — dang ky sau cung vi phu thuoc
// hau het cac module khac lam nguon tin hieu ---
builder.Services.AddSingleton<Antivirus.Service.Extensions.RiskScore.RiskScoreService>();

// Dang ky kieu singleton + hosted service (thay vi chi AddHostedService) de
// /api/status doc duoc TRANG THAI THAT cua hai tang real-time nay. Truoc day
// chung chi la hosted service an danh: khong ai lay duoc tham chieu, nen khong
// noi nao bao cao duoc rang chung co dang chay hay khong.
// Nguon su that DUY NHAT ve "cac tang phong thu co dang chay khong" — ca
// /api/status lan RiskScoreService deu doc tu day. Xem ghi chu dai trong
// ProtectionStatusService.cs: truoc day ba noi khai bao trang thai bao ve
// DOC LAP va ca ba deu la hang so, dan toi hai the tren cung mot man hinh
// mau thuan truc tiep voi nhau.
builder.Services.AddSingleton(new Antivirus.Service.Security.StartupDiagnostics(
    aclFailures, updateSigningDisabledReason));
builder.Services.AddSingleton<Antivirus.Service.Security.ProtectionStatusService>();

builder.Services.AddSingleton<DownloadsWatcherService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<DownloadsWatcherService>());
builder.Services.AddSingleton<DriverSimulatorService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<DriverSimulatorService>());

var app = builder.Build();
app.UseCors();

if (aclFailures.Count > 0)
{
    foreach (var (dir, ex) in aclErrors)
    {
        app.Logger.LogError(ex, "KHONG khoa duoc ACL cho thu muc du lieu {Dir}", dir);
    }

    // Phai hien ro trong log/audit: mot thu muc khong khoa duoc nghia la
    // gia dinh bao mat nen tang (chi SYSTEM/Admin ghi duoc) KHONG con dung
    // cho thu muc do — khong duoc de no troi qua im lang.
    app.Logger.LogWarning(
        "Co {Count} thu muc du lieu KHONG duoc bao ve bang ACL: {Dirs} — du lieu trong do co the bi tien trinh quyen thap sua doi",
        aclFailures.Count, string.Join(", ", aclFailures));
}

// [SUA LOI CHAN PHAT HANH — A3] Trang thai suy giam cua kenh cap nhat phai
// duoc ghi MOT LAN ngay luc khoi dong, khong chi doi ai do goi /api/status.
if (updateSigningDisabledReason is not null)
{
    app.Logger.LogWarning(
        "KENH CAP NHAT DA TAT — service van quet va bao ve binh thuong, nhung CSDL chu ky " +
        "va danh sach phishing se KHONG duoc cap nhat tu dong. Ly do: {Reason}",
        updateSigningDisabledReason);
    app.Services.GetRequiredService<AuditLogger>().Log("startup",
        $"Kenh cap nhat DA TAT (fail-closed): {updateSigningDisabledReason}");
}

// [SUA LOI NGHIEM TRONG] Xac thuc bang token cho MOI request toi /api/* —
// xem Security/ApiTokenProvider.cs. Truoc day API loopback hoan toan mo,
// cho phep bat ky tien trinh cuc bo nao (ke ca malware dang bi danh gia)
// tu goi POST /api/rules de whitelist chinh no.
// [SUA LOI CAO — CLICKJACKING] TRUOC DAY khong co X-Frame-Options hay
// frame-ancestors nao. Mot trang web bat ky ma nguoi dung dang mo co the
// nhung http://127.0.0.1:5270 vao iframe trong suot va lua ho bam vao cac
// nut that ben duoi — bao gom "Cho phep luon" trong hop thoai cap quyen va
// "Xoa vinh vien" trong danh sach cach ly. Giao dien nay chi duoc phep hien
// thi o cua so cap cao nhat (WebView2 cua Shell hoac tab trinh duyet), khong
// bao gio trong khung cua trang khac.
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Frame-Options"] = "DENY";
    headers["Content-Security-Policy"] = "frame-ancestors 'none'";
    headers["X-Content-Type-Options"] = "nosniff";
    // Khong ro ri duong dan/token qua Referer khi UI mo lien ket ra ngoai.
    headers["Referrer-Policy"] = "no-referrer";
    await next();
});

var apiToken = app.Services.GetRequiredService<ApiTokenProvider>();
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api"))
    {
        // [SUA LOI TRUNG BINH] TRUOC DAY con fallback doc token tu query
        // string (?token=) cho MOI request /api/*. app.js (xem
        // wwwroot/js/app.js) CHI dung header X-Av-Token cho tat ca cac
        // cuoc goi /api/* — query string ?token= CHI duoc WebView2 dung MOT
        // LAN duy nhat de nap trang goc "/" (khong nam duoi /api, khong qua
        // middleware nay), sau do app.js tu luu token vao localStorage va
        // luon gui qua header cho cac request tiep theo. Vi vay fallback
        // query-string o day KHONG duoc chinh UI su dung, chi mo them be
        // mat rui ro khong can thiet (token co the lo qua log truy cap/
        // lich su dieu huong neu URL /api/*?token=... tung duoc dung truc
        // tiep) ma khong mang lai loi ich chuc nang nao. Bo fallback nay,
        // chi chap nhan header X-Av-Token cho /api/*.
        string? candidate = context.Request.Headers["X-Av-Token"].FirstOrDefault();
        if (!apiToken.Validate(candidate))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Thieu hoac sai X-Av-Token" });
            return;
        }
    }
    await next();
});

// --- Khoi tao scan engine luc start (seed CSDL demo neu chua co, xem
// ops/scripts/seed-demo-signatures.ps1 cho quy trinh day du) ---
var engine = app.Services.GetRequiredService<ScanEngineService>();
string? sigDb = File.Exists(DataPaths.SignatureDbPath) ? DataPaths.SignatureDbPath : null;
string? yaraDir = Directory.Exists(DataPaths.YaraRulesDir) && Directory.EnumerateFiles(DataPaths.YaraRulesDir, "*.yar").Any()
    ? DataPaths.YaraRulesDir : null;
// [SUA LOI NGHIEM TRONG] TRUOC DAY gia tri tra ve cua Initialize bi bo hoan
// toan: khi thieu file CSDL (sigDb == null) hoac nap that bai, service van
// khoi dong va phuc vu binh thuong voi engine khong co CSDL chu ky, trong
// khi UI bao "dang duoc bao ve". Ghi ro tinh trang nay vao log VA audit de
// no khong the troi qua im lang.
bool engineReady = engine.Initialize(sigDb, yaraDir);

var audit = app.Services.GetRequiredService<AuditLogger>();
audit.Log("system", "Antivirus service da khoi dong");

if (apiToken.AclFailure is not null)
{
    // [SUA LOI CAO] TRUOC DAY loi ACL tren file token bi catch {} nuot im
    // lang. File nay gac TOAN BO /api/* — no khong duoc bao ve nghia la
    // moi gia dinh xac thuc cua san pham khong con dung.
    app.Logger.LogCritical(apiToken.AclFailure,
        "KHONG bao ve duoc ACL cho file token API {Path} — token gac toan bo /api/* dang nam khong duoc bao ve",
        apiToken.TokenFilePath);
    audit.Log("system",
        $"ERR: khong bao ve duoc ACL cho file token API {apiToken.TokenFilePath} — xac thuc /api/* co the bi qua mat");
}

if (!engineReady)
{
    app.Logger.LogCritical("Scan engine KHONG khoi tao duoc — dich vu quet KHONG hoat dong");
    audit.Log("system", "ERR: scan engine KHONG khoi tao duoc — dich vu quet KHONG hoat dong");
}
else if (engine.SignatureDbMissing || sigDb is null)
{
    app.Logger.LogError(
        "KHONG co CSDL chu ky dung duoc tai {Path} — phat hien theo hash DANG TAT",
        DataPaths.SignatureDbPath);
    audit.Log("system",
        $"ERR: khong co CSDL chu ky tai {DataPaths.SignatureDbPath} — phat hien theo hash DANG TAT, chi con YARA/heuristic");
}

// EXT-EXP-01: tu bao ve chinh tien trinh Service bang exploit mitigation
// (khong can driver — xem Extensions/ExploitProtection.cs).
var exploitMitigations = ExploitProtection.ApplySelfProtection(app.Services.GetRequiredService<ILogger<WebApplication>>());
audit.Log("system", $"Exploit self-protection: {string.Join(", ", exploitMitigations)}");
// [SUA LOI NGHIEM TRONG] TRUOC DAY log thang gia tri apiToken.Token (bi
// mat gac toan bo /api/*) o muc Information — file log/Event Log THUONG
// CO ACL LONG LEO HON nhieu so voi chinh file token (duoc AclProtection
// bao ve rieng, xem ApiTokenProvider), khien token de bi doc trom hon qua
// kenh log thay vi phai doc dung file duoc bao ve. Token da duoc ghi san
// vao TokenFilePath (ACL rieng) — nguoi/tien trinh can mo UI thu cong chi
// can doc file do, KHONG can token xuat hien them lan nua trong log.
app.Logger.LogInformation(
    "API token da san sang tai {TokenFile} — doc file nay de lay token mo UI qua http://127.0.0.1:5270/?token=<token>",
    apiToken.TokenFilePath);

// =====================================================================
// API cho UI (chi hien thi/nhan thao tac — moi quyet dinh nghiep vu nam
// trong cac service o tren, dung nguyen tac modules/02-kien-truc.md muc 1)
// =====================================================================

// [SUA LOI CHAN PHAT HANH] TRUOC DAY `protectionEnabled` la HANG SO `true`.
// Do la diem chiu luc cua toan bo mo hinh an toan cua service: nhieu quyet
// dinh fail-open trong file nay duoc bien minh bang lap luan "trang thai suy
// giam PHAI nhin thay duoc tu UI" — nhung UI khong the nhin thay gi neu
// endpoint duy nhat no goi luon tra ve "dang bao ve". Bon truong suy giam
// (updateSigningConfigured/updateSigningDisabledReason/
// unprotectedDataDirectories/...) van duoc phoi ra, nhung khong co truong
// TONG HOP nao, nen UI phai tu suy dien — va no khong lam.
//
// Sua: tinh THAT trang thai bao ve tu cac tin hieu co san, va phoi them
// danh sach `degradations` da chuan hoa (severity + thong diep tieng Viet)
// de UI chi viec hien thi, khong phai suy dien lai logic bao mat.
app.MapGet("/api/status", (ScanEngineService engine, UpdateClientService update,
    Antivirus.Service.Security.ProtectionStatusService protection) =>
{
    var degradations = protection.Compute();

    return Results.Ok(new
    {
        // KHONG con la hang so: false ngay khi co bat ky suy giam muc
        // critical nao. UI doc dung truong nay de quyet dinh mau/nhan.
        protectionEnabled = !Antivirus.Service.Security.ProtectionStatusService.HasCritical(degradations),
        protectionLevel = Antivirus.Service.Security.ProtectionStatusService.LevelOf(degradations),
        degradations = degradations.Select(d => new { id = d.Id, severity = d.Severity, message = d.Message }),
        updateStatus = update.Status,
        // Cac truong chi tiet giu nguyen de khong pha vo client hien co.
        updateSigningConfigured = update.SigningTrustConfigured,
        updateSigningDisabledReason,
        unprotectedDataDirectories = aclFailures,
        signatureDbMissing = engine.SignatureDbMissing,
        firewallRulesEnforced = Antivirus.Service.Extensions.Firewall.ConnectionMonitor.RulesAreEnforced,
        serverTimeUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
    });
});

// --- Rules (app_rules) ---
app.MapGet("/api/rules", (RuleStore rules) => Results.Ok(rules.List()));
// [SUA LOI CAO] TRUOC DAY moi endpoint GHI CHINH SACH duoi day khong ghi
// MOT dong audit nao — trong khi quarantine/settings thi co. Nghia la duong
// nguy hiem nhat (tu them rule "cho phep luon" cho mot binary, mo cong
// firewall, whitelist webcam, khoi phuc file) la duong DUY NHAT khong de
// lai dau vet. Ket hop voi DELETE /api/audit xoa sach, khong con gi de dieu
// tra sau su co. Tu day moi thay doi chinh sach deu duoc ghi.
app.MapPost("/api/rules", (RuleStore rules, AuditLogger auditLogger, AppRule rule) =>
{
    rule.CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    // [SUA LOI CAO] CreatedBy TRUOC DAY do client tu khai — mot rule do
    // client tao co the tu nhan la "default_policy" (chinh sach he thong),
    // lam sai lech moi bao cao va moi lan dieu tra ve sau. Nguon goc phai
    // do MAY CHU quyet dinh: da di qua /api/* thi la hanh dong nguoi dung.
    rule.CreatedBy = RuleCreatedBy.User;
    var id = rules.Add(rule);
    auditLogger.Log("rules",
        $"Da them rule {rule.Action} (scope={rule.Scope}) cho hash={rule.Sha256Hash}, publisher={rule.PublisherThumbprint}, path={rule.FilePath}",
        new { id, rule.Action, rule.Scope, rule.Sha256Hash, rule.PublisherThumbprint, rule.FilePath });
    return Results.Ok(new { id });
});
app.MapDelete("/api/rules/{id:long}", (RuleStore rules, AuditLogger auditLogger, long id) =>
{
    rules.Delete(id);
    auditLogger.Log("rules", $"Da xoa rule #{id}", new { id });
    return Results.Ok();
});

// --- Quarantine ---
app.MapGet("/api/quarantine", (QuarantineManager qm) => Results.Ok(qm.List()));
app.MapPost("/api/quarantine/{id}/restore", (QuarantineManager qm, string id) =>
    qm.Restore(id) ? Results.Ok() : Results.BadRequest(new { error = "Khong the khoi phuc (trang thai khong hop le hoac khong tim thay)" }));
app.MapPost("/api/quarantine/{id}/confirm", (QuarantineManager qm, string id) =>
    qm.ConfirmManualQuarantine(id) ? Results.Ok() : Results.BadRequest(new { error = "Khong the xac nhan" }));
app.MapDelete("/api/quarantine/{id}", (QuarantineManager qm, string id) =>
    qm.DeletePermanently(id) ? Results.Ok() : Results.BadRequest(new { error = "Khong tim thay ban ghi" }));

// --- Process trust: goi thu cong de demo/test (thay cho driver that);
// DriverSimulatorService goi ham nay tu dong khi bat duoc su kien tao
// tien trinh qua WMI. ---
app.MapPost("/api/trust/evaluate", async (ProcessTrustEngine trust, TrustEvaluateRequest req, CancellationToken ct) =>
{
    // [SUA LOI NGHIEM TRONG] Xem PathUtil.IsLocalDrivePath — endpoint nay
    // truoc day dua thang req.ProcessPath vao EvaluateAsync -> File.Exists
    // -> WinVerifyTrust ma khong kiem tra gi, tai mo lai dung lo hong forced-
    // authentication/NTLM-relay da vay o /api/scan/file va
    // /api/scan/full/start: mot ProcessPath dang UNC (\\attacker-host\share)
    // khien tien trinh SYSTEM tu ket noi/xac thuc SMB toi may chu attacker.
    if (!Antivirus.Service.Common.PathUtil.IsLocalDrivePath(req.ProcessPath))
    {
        return Results.BadRequest(new { error = "Chi chap nhan duong dan cuc bo tren o dia (khong ho tro UNC/duong dan mang)" });
    }
    var result = await trust.EvaluateAsync(req.ProcessPath, req.Pid, ct);
    return Results.Ok(result);
});

// Lan poll nay CHINH LA tin hieu "giao dien dang mo". ProcessTrustEngine doc
// no de quyet dinh co hoi nguoi dung hay khong — hoi khi khong ai nhin man
// hinh chi tao ra hop thoai chong dong va nhung khoang cho 30 giay vo nghia.
app.MapGet("/api/permission-requests", (PermissionRequestBroker broker) =>
{
    broker.MarkUiPolled();
    return Results.Ok(broker.ListPending());
});
app.MapPost("/api/permission-requests/{id}/respond", (PermissionRequestBroker broker, AuditLogger auditLogger, string id, RespondRequest req) =>
{
    if (!Enum.TryParse<UserPermissionChoice>(req.Choice, true, out var choice))
        return Results.BadRequest(new { error = "choice phai la AllowAlways|AllowOnce|Block" });

    // [SUA LOI CAO] TRUOC DAY endpoint nay khong ghi MOT dong audit nao.
    // AllowAlways o day khien ProcessTrustEngine luu mot rule cho-phep VINH
    // VIEN cho binary do (scope=hash hoac scope=publisher) — tuc la duong
    // NOI RONG chinh sach nhieu nhat cua san pham lai la duong duy nhat
    // khong de lai dau vet. Sau mot su co, khong the tra loi duoc cau hoi
    // "ai da cho phep cai nay chay, luc nao".
    var pending = broker.ListPending().FirstOrDefault(r => r.RequestId == id);
    bool accepted = broker.Respond(id, choice);
    if (accepted)
    {
        auditLogger.Log("process-trust",
            $"Nguoi dung tra loi yeu cau cap quyen: {choice} cho {pending?.ProcessPath ?? "(khong ro duong dan)"}"
            + (choice == UserPermissionChoice.AllowAlways ? " — se luu rule CHO PHEP VINH VIEN" : ""),
            new { requestId = id, choice = choice.ToString(), processPath = pending?.ProcessPath, sha256 = pending?.Sha256Hex });
    }
    return accepted ? Results.Ok() : Results.NotFound();
});

// --- Downloads suspicious decisions ---
app.MapGet("/api/downloads/pending", (DownloadsDecisionBroker broker) => Results.Ok(broker.ListPending()));
app.MapPost("/api/downloads/{id}/action", (DownloadsDecisionBroker broker, QuarantineManager qm, AuditLogger auditLogger, string id, DownloadActionRequest req) =>
{
    var item = broker.Get(id);
    if (item is null) return Results.NotFound();

    // [SUA LOI NGHIEM TRONG — TOCTOU, XOA FILE TUY Y BANG QUYEN SYSTEM]
    // item.FilePath duoc ghi nhan luc DownloadsWatcherService phat hien file,
    // roi nam trong danh sach cho toi khi nguoi dung bam nut. Cua so giua hai
    // thoi diem do dai bang dung thoi gian nguoi dung suy nghi — thoai mai de
    // thay chinh file do, hoac mot thu muc cha cua no, bang mot junction tro
    // toi dich dac quyen. Nhanh "delete" ben duoi goi File.Delete THANG,
    // duoi quyen LocalSystem, khong kiem tra lai gi ca.
    //
    // Cung mot bat bien nhu duong quarantine (xem QuarantineManager.
    // MoveIntoQuarantine): duong dan phai la o dia cuc bo, khong thanh phan
    // nao la reparse point, va duong di THAT SU phai trung duong di lexical.
    // Kiem tra lai NGAY TRUOC khi hanh dong, khong phai luc dua vao danh sach.
    if (!Antivirus.Service.Common.PathUtil.IsSafeRestoreTarget(item.FilePath))
    {
        auditLogger.Log("downloads",
            $"TU CHOI hanh dong '{req.Action}' tren {item.FilePath}: duong dan khong con an toan " +
            "(UNC/reparse point/junction xen vao) — nghi bi thay de ep tien trinh SYSTEM cham vao dich khac",
            new { id, action = req.Action, path = item.FilePath });
        return Results.Problem(
            detail: $"Duong dan {item.FilePath} khong con la duong dan cuc bo an toan — tu choi thao tac bang quyen SYSTEM.",
            statusCode: StatusCodes.Status409Conflict);
    }

    // [SUA LOI TRUNG BINH] TRUOC DAY nhanh "delete" nuot MOI exception
    // (try/catch rong) roi VAN goi broker.Remove(id) + tra ve 200 OK ben
    // duoi — neu File.Delete that bai (file dang bi khoa, quyen khong du...)
    // UI van duoc bao "thanh cong" trong khi file nghi ngo VAN CON tren dia
    // va muc pending da bi xoa khoi danh sach (khong con co hoi thu lai qua
    // UI). Nhanh "quarantine" thi khong bat loi gi ca — neu QuarantineFile
    // nem exception, request se that bai voi 500 nhung KHONG co thong diep
    // ro rang. Sua: bat loi rieng cho tung nhanh, tra ve loi (KHONG phai
    // 200) va KHONG xoa muc pending khi that bai — nguoi dung con co the
    // thu lai thay vi mat dau vet vinh vien.
    try
    {
        switch (req.Action.ToLowerInvariant())
        {
            case "delete":
                File.Delete(item.FilePath);
                break;
            case "quarantine":
                qm.QuarantineFile(item.FilePath, item.Sha256Hex, item.Reason);
                break;
            case "ignore":
                break;
            default:
                return Results.BadRequest(new { error = "action phai la delete|quarantine|ignore" });
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(
            detail: $"Khong thuc hien duoc hanh dong '{req.Action}' tren file {item.FilePath}: {ex.Message}",
            statusCode: StatusCodes.Status500InternalServerError);
    }
    // [SUA LOI CAO] Xoa file bang quyen SYSTEM va cach ly la hai hanh dong
    // KHONG HOAN TAC DUOC; truoc day ca hai deu khong de lai dong audit nao.
    auditLogger.Log("downloads",
        $"Nguoi dung chon '{req.Action}' cho file tai ve nghi ngo: {item.FilePath} (ly do phat hien: {item.Reason})",
        new { id, action = req.Action, path = item.FilePath, sha256 = item.Sha256Hex });

    broker.Remove(id);
    return Results.Ok();
});

// --- Full scan ---
app.MapPost("/api/scan/full/start", (FullScanService fs, StartScanRequest req) =>
{
    // [SUA LOI NGHIEM TRONG] Xem PathUtil.IsLocalDrivePath — cung lo hong
    // forced-authentication/NTLM-relay da vay o /api/scan/file nhung o day
    // qua VolumeRoot: truoc day dua thang vao Directory.EnumerateFiles/USN
    // journal ma khong kiem tra gi. Mot VolumeRoot dang UNC (\\attacker-
    // host\share) se khien tien trinh SYSTEM tu ket noi/xac thuc SMB toi may
    // chu do attacker chi dinh ngay khi enumerate, khong can dieu kien gi
    // dac biet ngoai viec goi duoc endpoint nay (chi can token API cuc bo).
    if (!Antivirus.Service.Common.PathUtil.IsLocalDrivePath(req.VolumeRoot))
    {
        return Results.BadRequest(new { error = "Chi chap nhan duong dan cuc bo tren o dia (khong ho tro UNC/duong dan mang)" });
    }
    return fs.Start(req.VolumeRoot) ? Results.Ok() : Results.BadRequest(new { error = "Da co scan dang chay" });
});
app.MapPost("/api/scan/full/pause", (FullScanService fs) =>
    fs.Pause() ? Results.Ok() : Results.BadRequest(new { error = "Khong the pause: khong co scan nao dang chay" }));
app.MapPost("/api/scan/full/resume", (FullScanService fs) =>
    fs.Resume() ? Results.Ok() : Results.BadRequest(new { error = "Khong the resume: khong co scan nao dang pause" }));
app.MapPost("/api/scan/full/cancel", (FullScanService fs) => { fs.Cancel(); return Results.Ok(); });
app.MapGet("/api/scan/full/status", (FullScanService fs) => Results.Ok(fs.GetProgress()));
app.MapGet("/api/scan/full/flagged", (FullScanService fs) => Results.Ok(fs.GetFlaggedItems()));

// --- Scan mot file thu cong (dung cho demo/manual test qua UI, vi du EICAR) ---
app.MapPost("/api/scan/file", (ScanEngineService engineSvc, ArchiveScanner archiveScanner, ScanFileRequest req) =>
{
    // [SUA LOI NGHIEM TRONG] Xem PathUtil.IsLocalDrivePath — truoc day
    // req.Path (nhan tho tu client) duoc dua thang vao File.Exists/ScanFile,
    // cho phep mot duong dan UNC (\\host\share\...) buoc tien trinh service
    // (chay quyen SYSTEM) tu ket noi/xac thuc SMB toi may chu do attacker
    // chi dinh (forced authentication / NTLM relay), du file "khong ton
    // tai". Tu choi truoc bat ky duong dan nao khong phai duong dan cuc bo
    // hop le tren o dia, TRUOC KHI cham vao he thong file.
    if (!Antivirus.Service.Common.PathUtil.IsLocalDrivePath(req.Path))
    {
        return Results.BadRequest(new { error = "Chi chap nhan duong dan cuc bo tren o dia (khong ho tro UNC/duong dan mang)" });
    }
    if (!File.Exists(req.Path)) return Results.NotFound(new { error = "File khong ton tai" });
    var result = ArchiveScanner.IsZipArchive(req.Path) ? archiveScanner.ScanZip(req.Path) : engineSvc.ScanFile(req.Path);
    return Results.Ok(result);
});

// --- Update ---
app.MapGet("/api/update/status", (UpdateClientService update) => Results.Ok(update.Status));
app.MapPost("/api/update/check-now", async (UpdateClientService update, CancellationToken ct) =>
    Results.Ok(await update.CheckAndApplyAsync(ct)));

// --- Audit log (ban tom tat, khong phai JSON tho — UI-07) ---
app.MapGet("/api/audit", (AuditLogger auditLogger, int? limit) => Results.Ok(auditLogger.GetRecentForUi(limit ?? 100)));
app.MapGet("/api/audit/file-size", (AuditLogger auditLogger) => Results.Ok(new { sizeBytes = auditLogger.GetLogFileSizeBytes() }));
// [TINH NANG THEO YEU CAU NGUOI DUNG] "co co che nao xoa log tu dong va
// thu cong khong" — day la nut THU CONG (tu dong xem AuditLogMaintenanceService).
app.MapPost("/api/audit/prune", (AuditLogger auditLogger) =>
{
    int removed = auditLogger.PruneToMaxLines(20_000);
    auditLogger.Log("system", $"Da don nhat ky thu cong — xoa {removed} dong cu, giu lai toi da 20000 dong gan nhat");
    return Results.Ok(new { removed });
});
app.MapDelete("/api/audit", (AuditLogger auditLogger) =>
{
    // Xem AuditLogger.ClearAll: khong con huy du lieu, ma LUU TRU sang mot
    // file rieng trong thu muc logs da duoc ACL bao ve.
    var archived = auditLogger.ClearAll();
    return Results.Ok(new
    {
        archivedTo = archived,
        note = archived is null
            ? "Nhat ky dang trong hoac khong luu tru duoc — khong co gi bi xoa."
            : "Nhat ky da duoc LUU TRU (khong bi xoa vinh vien) — xem duong dan tai archivedTo.",
    });
});

// --- Settings (nut bat/tat cache full scan theo yeu cau nguoi dung) ---
app.MapGet("/api/settings", (AppSettingsStore settings, ScanCacheStore cache) => Results.Ok(new
{
    fullScanCacheEnabled = settings.Current.FullScanCacheEnabled,
    cachedFileCount = cache.Count(),
}));
app.MapPost("/api/settings/full-scan-cache", (AppSettingsStore settings, AuditLogger auditLogger, SetCacheRequest req) =>
{
    settings.Update(s => s.FullScanCacheEnabled = req.Enabled);
    auditLogger.Log("system", $"Cache full scan da duoc {(req.Enabled ? "BAT" : "TAT")} tu UI");
    return Results.Ok();
});
app.MapPost("/api/settings/clear-scan-cache", (ScanCacheStore cache, AuditLogger auditLogger) =>
{
    cache.ClearAll();
    auditLogger.Log("system", "Da xoa thu cong toan bo cache full scan");
    return Results.Ok();
});

// --- Gaming/Silent mode (EXT-GAME-01/02) ---
app.MapGet("/api/gaming-mode", (GamingModeService gaming) => Results.Ok(new { active = gaming.IsActive }));
app.MapPost("/api/gaming-mode/drain-notifications", (GamingModeService gaming) =>
    Results.Ok(gaming.DrainSuppressedNotifications().Select(n => new { title = n.Title, body = n.Body })));

// --- Alert Center — Event Bus hop nhat (EXT-EVT-01/02) ---
app.MapGet("/api/alerts", (EventBus bus) => Results.Ok(bus.ListOpenAlerts()));

// --- Firewall (EXT-FW-02/03) + C2 beacon detection (EXT-FW-05) ---
// [SUA LOI NGHIEM TRONG] Xem ConnectionMonitor: rule firewall duoc luu va
// hien thi nhung CHUA duoc thuc thi o tang mang. Endpoint nay ton tai de UI
// KHONG THE ngam dinh rang "co rule = duoc bao ve" — moi man hinh firewall
// phai doc `enforced` va noi ro voi nguoi dung.
app.MapGet("/api/firewall/status", () => Results.Ok(new
{
    enforced = Antivirus.Service.Extensions.Firewall.ConnectionMonitor.RulesAreEnforced,
    note = "Rule firewall hien duoc LUU va DOI CHIEU voi ket noi dang mo (ghi audit khi khop), "
         + "nhung CHUA duoc thuc thi chan o tang mang. Ket noi khop rule Block VAN CHAY.",
}));

app.MapGet("/api/firewall/rules", (Antivirus.Service.Extensions.Firewall.FirewallRuleStore store) => Results.Ok(store.List()));
app.MapPost("/api/firewall/rules", (Antivirus.Service.Extensions.Firewall.FirewallRuleStore store, AuditLogger auditLogger, Antivirus.Service.Extensions.Firewall.FirewallRule rule) =>
{
    // Nguon goc do may chu quyet dinh — xem ghi chu tai POST /api/rules.
    rule.CreatedBy = "user";
    var id = store.Add(rule);
    auditLogger.Log("firewall",
        $"Da them rule firewall {rule.Action} {rule.Direction}/{rule.Protocol} cho app={rule.AppSha256}, cong={rule.RemotePortStart}-{rule.RemotePortEnd}",
        new { id, rule.Action, rule.Direction, rule.Protocol, rule.AppSha256, rule.RemotePortStart, rule.RemotePortEnd });
    return Results.Ok(new { id });
});
app.MapDelete("/api/firewall/rules/{id:long}", (Antivirus.Service.Extensions.Firewall.FirewallRuleStore store, AuditLogger auditLogger, long id) =>
{
    store.Delete(id);
    auditLogger.Log("firewall", $"Da xoa rule firewall #{id}", new { id });
    return Results.Ok();
});
app.MapGet("/api/firewall/beacon-suspicions", (Antivirus.Service.Extensions.Firewall.ConnectionMonitor monitor) =>
    Results.Ok(monitor.GetRecentSuspicions()));

// --- Anti-ransomware (EXT-RW-01..06) ---
app.MapGet("/api/ransomware/alerts", (Antivirus.Service.Extensions.Ransomware.RansomwareGuardService guard) =>
    Results.Ok(guard.GetRecentAlerts()));
app.MapGet("/api/ransomware/protected-folders", () =>
    Results.Ok(Antivirus.Service.Extensions.Ransomware.RansomwareGuardService.GetProtectedFolders()));
app.MapGet("/api/ransomware/version-store", (Antivirus.Service.Extensions.Ransomware.VersionStore store) =>
    Results.Ok(store.ListAllTrackedPaths()));
app.MapPost("/api/ransomware/restore", (Antivirus.Service.Extensions.Ransomware.VersionStore store, AuditLogger auditLogger, RestoreVersionRequest req) =>
{
    // Day la mot thao tac GHI FILE bang quyen SYSTEM — bat buoc phai co dau
    // vet, ca khi thanh cong lan khi bi tu choi (VersionStore tu choi khi
    // duong dan bi doi huong qua reparse point, xem PathUtil.IsSafeRestoreTarget).
    bool ok = store.RestoreLatestVersion(req.Path);
    auditLogger.Log("ransomware",
        ok ? $"Da khoi phuc phien ban gan nhat cua: {req.Path}"
           : $"ERR: khong khoi phuc duoc {req.Path} (khong co phien ban, hoac duong dan bi tu choi vi ly do an toan)",
        new { req.Path, ok });
    return ok ? Results.Ok() : Results.BadRequest(new { error = "Khong tim thay phien ban de khoi phuc" });
});

// --- Kiem soat thiet bi USB (EXT-USB-01/02) ---
app.MapGet("/api/usb/rules", (Antivirus.Service.Extensions.Usb.UsbRuleStore store) => Results.Ok(store.List()));
app.MapPost("/api/usb/rules", (Antivirus.Service.Extensions.Usb.UsbRuleStore store, AuditLogger auditLogger, Antivirus.Service.Extensions.Usb.UsbDeviceRule rule) =>
{
    var id = store.Add(rule);
    auditLogger.Log("usb", $"Da them rule USB {rule.Action} cho thiet bi VID={rule.VendorId}/PID={rule.ProductId}, serial={rule.SerialNumber}",
        new { id, rule.Action, rule.VendorId, rule.ProductId, rule.SerialNumber, rule.AutoScan });
    return Results.Ok(new { id });
});
app.MapDelete("/api/usb/rules/{id:long}", (Antivirus.Service.Extensions.Usb.UsbRuleStore store, AuditLogger auditLogger, long id) =>
{
    store.Delete(id);
    auditLogger.Log("usb", $"Da xoa rule USB #{id}", new { id });
    return Results.Ok();
});
app.MapGet("/api/usb/devices", (Antivirus.Service.Extensions.Usb.UsbMonitorService monitor) =>
    Results.Ok(monitor.GetRecentArrivals()));

// --- Quet lo hong phan mem/driver (EXT-VULN-01..03) ---
app.MapGet("/api/vulnerabilities", (Antivirus.Service.Extensions.Vulnerability.VulnerabilityScanService scanner) =>
    Results.Ok(scanner.GetLastFindings()));
app.MapPost("/api/vulnerabilities/scan-now", (Antivirus.Service.Extensions.Vulnerability.VulnerabilityScanService scanner) =>
    Results.Ok(scanner.RunScanNow()));

// --- Bao ve webcam/microphone (EXT-CAM-01/02) ---
app.MapGet("/api/cam-mic/accesses", (Antivirus.Service.Extensions.Webcam.WebcamMicMonitorService monitor) =>
    Results.Ok(monitor.GetRecentAccesses()));
app.MapGet("/api/cam-mic/whitelist", (Antivirus.Service.Extensions.Webcam.CamMicWhitelistStore store) =>
    Results.Ok(store.List()));
app.MapPost("/api/cam-mic/whitelist", (Antivirus.Service.Extensions.Webcam.CamMicWhitelistStore store, AuditLogger auditLogger, CamMicWhitelistRequest req) =>
{
    var id = store.Add(req.ProcessIdentity, "user");
    auditLogger.Log("cam-mic", $"Da whitelist truy cap webcam/mic cho: {req.ProcessIdentity}",
        new { id, req.ProcessIdentity });
    return Results.Ok(new { id });
});
app.MapDelete("/api/cam-mic/whitelist/{id:long}", (Antivirus.Service.Extensions.Webcam.CamMicWhitelistStore store, AuditLogger auditLogger, long id) =>
{
    store.Delete(id);
    auditLogger.Log("cam-mic", $"Da xoa whitelist webcam/mic #{id}", new { id });
    return Results.Ok();
});

// --- Giam sat thiet bi mang gia dinh (EXT-NET-01/02) ---
app.MapGet("/api/home-network/devices", (Antivirus.Service.Extensions.Network.HomeNetworkMonitorService monitor) =>
    Results.Ok(monitor.GetDevices()));

// --- Risk score tong hop (EXT-RISK-01/02) ---
app.MapGet("/api/risk-score", (Antivirus.Service.Extensions.RiskScore.RiskScoreService riskScore) =>
    Results.Ok(riskScore.Compute()));

// --- Task scheduler noi bo (EXT-SCHED-01) ---
app.MapGet("/api/scheduler/registrations", (Antivirus.Service.Extensions.Scheduler.BackgroundTaskScheduler scheduler) =>
    Results.Ok(scheduler.ListRegistrations()));
app.MapGet("/api/scheduler/idle", (Antivirus.Service.Extensions.Scheduler.BackgroundTaskScheduler scheduler) =>
    Results.Ok(new { idle = scheduler.IsUserIdle() }));

// --- Cloud threat intelligence (EXT-CTI-01/02) ---
app.MapPost("/api/cloud-intel/lookup", (Antivirus.Service.Extensions.CloudIntel.CloudReputationClient client, CloudLookupRequest req) =>
{
    if (!Antivirus.Service.Extensions.CloudIntel.CloudReputationClient.IsValidSha256Hex(req.Sha256))
    {
        return Results.BadRequest(new { error = "Sha256 phai la chuoi hex 64 ky tu hop le" });
    }
    return Results.Ok(client.Lookup(req.Sha256));
});

// --- Sandbox verdict aggregator (EXT-SB-03/04) ---
app.MapPost("/api/sandbox/evaluate", (Antivirus.Service.Extensions.Sandbox.SandboxVerdictAggregator aggregator, List<Antivirus.Service.Extensions.Sandbox.ObservedApiCall> calls) =>
    Results.Ok(aggregator.Evaluate(calls)));

// --- Anti-phishing (EXT-PH-02/05) ---
app.MapPost("/api/phishing/check-url", (Antivirus.Service.Extensions.Phishing.PhishingUrlChecker checker, PhishingCheckRequest req) =>
    Results.Ok(checker.CheckUrl(req.Url)));
app.MapGet("/api/phishing/stats", (Antivirus.Service.Extensions.Phishing.PhishingListStore store, Antivirus.Service.Extensions.Phishing.PhishingListUpdateService updateService) =>
{
    var (domains, ips) = store.Count();
    return Results.Ok(new { domains, ips, version = updateService.CurrentVersion });
});
app.MapPost("/api/phishing/update-now", async (Antivirus.Service.Extensions.Phishing.PhishingListUpdateService updateService, CancellationToken ct) =>
    Results.Ok(new { success = await updateService.CheckAndApplyAsync(ct) }));

// --- Phuc vu UI web tinh (HTML/CSS/JS) tu wwwroot (ASP.NET Core tu resolve
// theo ContentRootPath: thu muc du an khi `dotnet run`, thu muc publish khi
// da publish) ---
app.UseDefaultFiles();
app.UseStaticFiles();

app.Run();

record TrustEvaluateRequest(string ProcessPath, int Pid);
record RespondRequest(string Choice);
record DownloadActionRequest(string Action);
record StartScanRequest(string VolumeRoot);
record ScanFileRequest(string Path);
record SetCacheRequest(bool Enabled);
record RestoreVersionRequest(string Path);
record CamMicWhitelistRequest(string ProcessIdentity);
record CloudLookupRequest(string Sha256);
record PhishingCheckRequest(string Url);
