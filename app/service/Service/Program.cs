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
builder.Services.AddSingleton<ProcessTrustEngine>();
builder.Services.AddSingleton<DownloadsDecisionBroker>();
builder.Services.AddSingleton(new ScanCacheStore(DataPaths.ScanCacheDbPath));
builder.Services.AddSingleton(new AppSettingsStore(DataPaths.SettingsPath));

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

builder.Services.AddSingleton(
    CompanyCertificateProvider.GetOrCreateForEnvironment(builder.Environment, builder.Configuration));
builder.Services.AddSingleton<IUpdatePackageSource>(_ =>
    new LocalFolderUpdatePackageSource(Path.Combine(DataPaths.RootDir, "update-drop")));
builder.Services.AddSingleton<UpdateClientService>(sp => new UpdateClientService(
    sp.GetRequiredService<IUpdatePackageSource>(),
    sp.GetRequiredService<ScanEngineService>(),
    sp.GetRequiredService<AuditLogger>(),
    sp.GetRequiredService<ILogger<UpdateClientService>>(),
    sp.GetRequiredService<System.Security.Cryptography.X509Certificates.X509Certificate2>(),
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
    new LocalFolderUpdatePackageSource(Path.Combine(DataPaths.RootDir, "update-drop-phishing")),
    sp.GetRequiredService<Antivirus.Service.Extensions.Phishing.PhishingListStore>(),
    sp.GetRequiredService<AuditLogger>(),
    sp.GetRequiredService<ILogger<Antivirus.Service.Extensions.Phishing.PhishingListUpdateService>>(),
    sp.GetRequiredService<System.Security.Cryptography.X509Certificates.X509Certificate2>()));
builder.Services.AddHostedService(sp => sp.GetRequiredService<Antivirus.Service.Extensions.Phishing.PhishingListUpdateService>());

// --- Risk score tong hop (EXT-RISK-01/02) — dang ky sau cung vi phu thuoc
// hau het cac module khac lam nguon tin hieu ---
builder.Services.AddSingleton<Antivirus.Service.Extensions.RiskScore.RiskScoreService>();

builder.Services.AddHostedService<DownloadsWatcherService>();
builder.Services.AddHostedService<DriverSimulatorService>();

var app = builder.Build();
app.UseCors();

// [SUA LOI NGHIEM TRONG] Xac thuc bang token cho MOI request toi /api/* —
// xem Security/ApiTokenProvider.cs. Truoc day API loopback hoan toan mo,
// cho phep bat ky tien trinh cuc bo nao (ke ca malware dang bi danh gia)
// tu goi POST /api/rules de whitelist chinh no.
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
engine.Initialize(sigDb, yaraDir);

var audit = app.Services.GetRequiredService<AuditLogger>();
audit.Log("system", "Antivirus service da khoi dong");

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

app.MapGet("/api/status", (ScanEngineService _, UpdateClientService update) => Results.Ok(new
{
    protectionEnabled = true,
    updateStatus = update.Status,
    serverTimeUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
}));

// --- Rules (app_rules) ---
app.MapGet("/api/rules", (RuleStore rules) => Results.Ok(rules.List()));
app.MapPost("/api/rules", (RuleStore rules, AppRule rule) =>
{
    rule.CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var id = rules.Add(rule);
    return Results.Ok(new { id });
});
app.MapDelete("/api/rules/{id:long}", (RuleStore rules, long id) =>
{
    rules.Delete(id);
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
    var result = await trust.EvaluateAsync(req.ProcessPath, req.Pid, ct);
    return Results.Ok(result);
});

app.MapGet("/api/permission-requests", (PermissionRequestBroker broker) => Results.Ok(broker.ListPending()));
app.MapPost("/api/permission-requests/{id}/respond", (PermissionRequestBroker broker, string id, RespondRequest req) =>
{
    if (!Enum.TryParse<UserPermissionChoice>(req.Choice, true, out var choice))
        return Results.BadRequest(new { error = "choice phai la AllowAlways|AllowOnce|Block" });
    return broker.Respond(id, choice) ? Results.Ok() : Results.NotFound();
});

// --- Downloads suspicious decisions ---
app.MapGet("/api/downloads/pending", (DownloadsDecisionBroker broker) => Results.Ok(broker.ListPending()));
app.MapPost("/api/downloads/{id}/action", (DownloadsDecisionBroker broker, QuarantineManager qm, string id, DownloadActionRequest req) =>
{
    var item = broker.Get(id);
    if (item is null) return Results.NotFound();

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
app.MapPost("/api/scan/full/pause", (FullScanService fs) => { fs.Pause(); return Results.Ok(); });
app.MapPost("/api/scan/full/resume", (FullScanService fs) => { fs.Resume(); return Results.Ok(); });
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
    auditLogger.ClearAll();
    auditLogger.Log("system", "Da xoa toan bo nhat ky theo yeu cau nguoi dung");
    return Results.Ok();
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
app.MapGet("/api/firewall/rules", (Antivirus.Service.Extensions.Firewall.FirewallRuleStore store) => Results.Ok(store.List()));
app.MapPost("/api/firewall/rules", (Antivirus.Service.Extensions.Firewall.FirewallRuleStore store, Antivirus.Service.Extensions.Firewall.FirewallRule rule) =>
{
    var id = store.Add(rule);
    return Results.Ok(new { id });
});
app.MapDelete("/api/firewall/rules/{id:long}", (Antivirus.Service.Extensions.Firewall.FirewallRuleStore store, long id) =>
{
    store.Delete(id);
    return Results.Ok();
});
app.MapGet("/api/firewall/beacon-suspicions", (Antivirus.Service.Extensions.Firewall.ConnectionMonitor monitor) =>
    Results.Ok(monitor.GetRecentSuspicions()));

// --- Anti-ransomware (EXT-RW-01..06) ---
app.MapGet("/api/ransomware/alerts", (Antivirus.Service.Extensions.Ransomware.RansomwareGuardService guard) =>
    Results.Ok(guard.GetRecentAlerts()));
app.MapGet("/api/ransomware/protected-folders", () =>
    Results.Ok(Antivirus.Service.Extensions.Ransomware.RansomwareGuardService.DefaultProtectedFolders));
app.MapGet("/api/ransomware/version-store", (Antivirus.Service.Extensions.Ransomware.VersionStore store) =>
    Results.Ok(store.ListAllTrackedPaths()));
app.MapPost("/api/ransomware/restore", (Antivirus.Service.Extensions.Ransomware.VersionStore store, RestoreVersionRequest req) =>
    store.RestoreLatestVersion(req.Path) ? Results.Ok() : Results.BadRequest(new { error = "Khong tim thay phien ban de khoi phuc" }));

// --- Kiem soat thiet bi USB (EXT-USB-01/02) ---
app.MapGet("/api/usb/rules", (Antivirus.Service.Extensions.Usb.UsbRuleStore store) => Results.Ok(store.List()));
app.MapPost("/api/usb/rules", (Antivirus.Service.Extensions.Usb.UsbRuleStore store, Antivirus.Service.Extensions.Usb.UsbDeviceRule rule) =>
{
    var id = store.Add(rule);
    return Results.Ok(new { id });
});
app.MapDelete("/api/usb/rules/{id:long}", (Antivirus.Service.Extensions.Usb.UsbRuleStore store, long id) =>
{
    store.Delete(id);
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
app.MapPost("/api/cam-mic/whitelist", (Antivirus.Service.Extensions.Webcam.CamMicWhitelistStore store, CamMicWhitelistRequest req) =>
{
    var id = store.Add(req.ProcessIdentity, "user");
    return Results.Ok(new { id });
});
app.MapDelete("/api/cam-mic/whitelist/{id:long}", (Antivirus.Service.Extensions.Webcam.CamMicWhitelistStore store, long id) =>
{
    store.Delete(id);
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
    Results.Ok(client.Lookup(req.Sha256)));

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
