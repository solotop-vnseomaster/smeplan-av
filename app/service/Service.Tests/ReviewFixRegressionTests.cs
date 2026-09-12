using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Antivirus.Service.Archive;
using Antivirus.Service.Data;
using Antivirus.Service.Engine;
using Antivirus.Service.Models;
using Antivirus.Service.Trust;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// Test hoi quy cho cac loi da duoc XAC NHAN tu ban review va da sua trong lan
// nay. Tieu chi duy nhat de mot test o day co gia tri: no PHAI do neu quay
// nguoc dung dong da sua — xem muc "test khong chung minh duoc dieu no tuyen
// bo" trong chinh ban review do.
[Collection("EngineSequential")]
public class ReviewFixRegressionTests
{
    // EICAR standard test string — chuoi test chuan cong khai cua nganh.
    private const string EicarContent =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // ------------------------------------------------------------------
    // ArchiveScanner — entry bat dau bang "PK\x05\x06" (magic cua archive
    // RONG) TRUOC DAY di vao nhanh zip-long-nhau, va vi if/else loai tru nen
    // ScanBuffer (hash + YARA + heuristic) o nhanh `else` KHONG BAO GIO chay
    // cho no: mot ngo cut hoan chinh cho toan bo tang phat hien.
    // ------------------------------------------------------------------
    [Fact]
    public void EntryWithEmptyArchiveMagicPrefix_StillReachesContentScan()
    {
        var tempDir = Directory.CreateTempSubdirectory("avtest_eocd_").FullName;
        try
        {
            // Noi dung payload: 4 byte magic cua archive RONG ("PK" + 05 06)
            // dat truoc EICAR. Day chinh la cong thuc vuot tang phat hien:
            // HasZipMagic nhan 4 byte dau, ca entry di vao nhanh zip-long-nhau,
            // va TRUOC KHI SUA, ScanBuffer nam trong nhanh `else` nen khong bao
            // gio chay cho no.
            var payload = new List<byte> { 0x50, 0x4B, 0x05, 0x06 };
            payload.AddRange(System.Text.Encoding.ASCII.GetBytes(EicarContent));
            var payloadBytes = payload.ToArray();

            // Phat hien theo hash la duong ma test nay do: nap CSDL chu ky
            // chua DUNG hash cua chuoi byte tren. Neu ScanBuffer nhan duoc
            // dung noi dung nay, verdict phai la Malicious; neu noi dung
            // khong bao gio toi engine (hanh vi cu), khong the nao Malicious.
            var hashHex = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(payloadBytes)).ToLowerInvariant();
            var csvPath = Path.Combine(tempDir, "sigs.csv");
            File.WriteAllText(csvPath, $"{hashHex},1,255\n");
            var dbPath = Path.Combine(tempDir, "sigs.avsigdb");
            Assert.True(ScanEngineService.BuildSignatureDb(csvPath, dbPath));

            using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
            Assert.True(engine.Initialize(dbPath, null));
            var scanner = new ArchiveScanner(engine, NullLogger<ArchiveScanner>.Instance);

            var zipPath = Path.Combine(tempDir, "eocd_prefix.zip");
            using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("payload.dat");
                using var stream = entry.Open();
                stream.Write(payloadBytes, 0, payloadBytes.Length);
            }

            var result = scanner.ScanZip(zipPath);

            // Assert "khac Clean" la KHONG du: truoc khi sua, entry nay tra ve
            // ScanError (mo ra thanh zip hong), cung khac Clean — mot test nhu
            // vay se xanh ca truoc lan sau khi sua va khong chung minh gi ca.
            Assert.Equal(ScanVerdict.Malicious, result.Verdict);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // ------------------------------------------------------------------
    // RuleStore — nguoi dung dan hash tu VirusTotal / Get-FileHash (CHU HOA),
    // engine sinh hash CHU THUONG, SQLite so khop phan biet hoa/thuong. Truoc
    // khi sua, rule do duoc luu va hien ra trong UI nhung khong bao gio khop.
    // ------------------------------------------------------------------
    [Fact]
    public void RuleAddedWithUppercaseHash_IsFoundByLowercaseLookup()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"avtest_rulecase_{Guid.NewGuid():N}.db");
        try
        {
            var rules = new RuleStore(dbPath);
            var upper = new string('A', 64);
            rules.Add(new AppRule
            {
                Sha256Hash = upper,
                FilePath = @"C:\tmp\x.exe",
                Action = RuleAction.Block,
                Scope = RuleScope.Hash,
                CreatedAt = 1,
                CreatedBy = RuleCreatedBy.User,
            });

            var found = rules.FindByHash(upper.ToLowerInvariant());

            Assert.NotNull(found);
            Assert.Equal(RuleAction.Block, found!.Action);
        }
        finally
        {
            try { File.Delete(dbPath); } catch { }
        }
    }

    // ------------------------------------------------------------------
    // ProcessTrustEngine — rule Block TUONG MINH cua nguoi dung phai thang
    // nhanh trusted-by-default. Truoc khi sua, trusted-by-default chay TRUOC
    // moi lan tra rule, nen rule Block dat tren mot binary Microsoft trong
    // System32 (powershell.exe, certutil.exe, mshta.exe — bo LOLBin kinh
    // dien) bi bo qua hoan toan.
    // ------------------------------------------------------------------
    [Fact]
    public async Task ExplicitBlockRule_IsCheckedBeforeTrustedByDefault()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"avtest_blockfirst_{Guid.NewGuid():N}.db");
        var auditPath = Path.Combine(Path.GetTempPath(), $"avtest_audit_{Guid.NewGuid():N}.jsonl");

        // Mot binary Microsoft that, da ky, trong thu muc duoc bao ve — thoa
        // CA BA tieu chi trusted-by-default.
        var systemBinary = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "certutil.exe");
        Assert.True(File.Exists(systemBinary), $"Test can {systemBinary} ton tai");

        try
        {
            var rules = new RuleStore(dbPath);
            var audit = new Antivirus.Service.Audit.AuditLogger(auditPath);
            var engine = new ProcessTrustEngine(rules, new PermissionRequestBroker(), audit,
                NullLogger<ProcessTrustEngine>.Instance, userDecisionTimeout: TimeSpan.FromMilliseconds(200));

            var hashHex = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(systemBinary)))
                .ToLowerInvariant();

            // Kiem chung TIEN DE cua test truoc: KHONG co rule, binary nay
            // PHAI dat TrustedByDefault. Neu tien de nay sai (vi du moi truong
            // CI khong doc duoc chu ky), test duoi day se xanh vi ly do khac
            // han va khong chung minh duoc gi — dung loi ro rang thay vi im
            // lang bao pass.
            var baseline = await engine.EvaluateAsync(systemBinary, 4320, CancellationToken.None);
            Assert.Equal(ProcessTrustState.TrustedByDefault, baseline.State);

            rules.Add(new AppRule
            {
                Sha256Hash = hashHex,
                FilePath = systemBinary,
                Action = RuleAction.Block,
                Scope = RuleScope.Hash,
                CreatedAt = 1,
                CreatedBy = RuleCreatedBy.User,
            });

            var decision = await engine.EvaluateAsync(systemBinary, 4321, CancellationToken.None);

            Assert.Equal(ProcessTrustState.RuleBlock, decision.State);
            Assert.False(decision.Allowed);
        }
        finally
        {
            try { File.Delete(dbPath); } catch { }
            try { File.Delete(auditPath); } catch { }
        }
    }

    // ------------------------------------------------------------------
    // AuthenticodeVerifier — het deadline KHAC voi "chu ky khong hop le".
    // Truoc khi sua ca hai deu sup ve ChainValid=false khong phan biet duoc,
    // va DriverSimulatorService goi proc.Kill() (quyen LocalSystem) tren ket
    // qua do: mot su co mang bien thanh mot dot giet tien trinh hang loat.
    // ------------------------------------------------------------------
    [Fact]
    public async Task VerifyAsync_Timeout_MarksVerificationIncomplete_NotInvalidSignature()
    {
        var systemBinary = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "certutil.exe");

        // Deadline 0 -> chac chan het gio truoc khi WinVerifyTrust kip xong.
        var result = await AuthenticodeVerifier.VerifyAsync(
            systemBinary, TimeSpan.Zero, CancellationToken.None);

        Assert.False(result.ChainVerificationCompleted);
    }

    // ------------------------------------------------------------------
    // RiskScoreService — BAT BIEN: khong the bao "An toan" trong khi mot tang
    // phong thu dang CHET.
    //
    // Truoc khi sua, thanh phan "Real-time protection" ghi CUNG 0 diem tru voi
    // chu thich "Dang bat (khong co co che tat trong ban nay)", va risk score
    // hoan toan khong biet gi ve suc khoe cac tang. Ket qua tren mot man hinh:
    // the "Tong quan bao ve" bao "KHÔNG được bảo vệ" (do) trong khi the ngay
    // ben duoi bao "100 — An toàn — mọi lớp bảo vệ đều ổn" (xanh).
    // ------------------------------------------------------------------
    [Theory]
    [InlineData(100, true)]  // khong su co nao, nhung mot tang da chet
    [InlineData(85, true)]
    [InlineData(60, true)]
    public void RiskScore_NeverReportsSafe_WhenACriticalLayerIsDown(int rawScore, bool hasCriticalFailure)
    {
        var (score, label) = Antivirus.Service.Extensions.RiskScore.RiskScoreService
            .FinalizeScore(rawScore, hasCriticalFailure);

        Assert.NotEqual("An toan", label);
        Assert.True(score < 80, $"Diem {score} van nam trong nguong 'An toan' du mot tang bao ve da chet");
    }

    [Fact]
    public void RiskScore_ReportsSafe_WhenAllLayersHealthyAndNoIncidents()
    {
        // Chieu nguoc lai phai VAN dung — neu khong, "sua" o tren chi la lam
        // moi thu luon do, cung vo dung nhu luon xanh.
        var (score, label) = Antivirus.Service.Extensions.RiskScore.RiskScoreService
            .FinalizeScore(100, hasCriticalLayerFailure: false);

        Assert.Equal("An toan", label);
        Assert.Equal(100, score);
    }

    // ------------------------------------------------------------------
    // DriverSimulatorService — Kill() duoi quyen LocalSystem la hanh dong
    // KHONG HOAN TAC DUOC, chi duoc phep khi co KET LUAN DUT KHOAT.
    //
    // Truoc khi sua, MOI ket qua khong-Allowed deu di thang toi Kill(), ke ca
    // DeniedByTimeout. Do tren may that: moi tien trinh Chrome bi giet sau
    // dung 30 giay (5 lan lien tiep), vi hop thoai xin quyen doi dashboard
    // dang mo ma khong ai ngoi nhin. Moi ung dung KHONG PHAI Microsoft deu
    // chung so phan.
    // ------------------------------------------------------------------
    [Theory]
    [InlineData(ProcessTrustState.RuleBlock, true)]         // rule Block tuong minh -> duoc giet
    [InlineData(ProcessTrustState.Blocked, true)]           // nguoi dung bam "Chan" -> duoc giet
    [InlineData(ProcessTrustState.DeniedByTimeout, false)]  // KHONG ai tra loi -> KHONG duoc giet
    [InlineData(ProcessTrustState.PendingUserDecision, false)]
    [InlineData(ProcessTrustState.Unknown, false)]
    public void OnlyExplicitBlockDecisions_JustifyKillingAProcess(ProcessTrustState state, bool expectedKill)
    {
        Assert.Equal(expectedKill, DriverSimulatorService.IsExplicitBlockDecision(state));
    }

    // ------------------------------------------------------------------
    // AclProtection.ProtectFile — lop ACL DUY NHAT tren api-token.txt (gac
    // toan bo /api/*) va tren file PFX chua khoa rieng ky goi cap nhat, va
    // truoc lan nay no co DUNG 0 test.
    //
    // SetAccessRuleProtection(true, false) chi bo ACE KE THUA; ACE EXPLICIT da
    // co san song sot, va ProtectFile sau do chi AddAccessRule. Nguoi dung
    // thuong tao truoc file token voi mot ACE cho chinh ho -> service ghi token
    // that vao dung file do -> ho doc duoc token cua mot service LocalSystem.
    // ------------------------------------------------------------------
    [SupportedOSPlatform("windows")]
    [Fact]
    public void ProtectFile_PurgesPreExistingExplicitAce_NotJustInheritedOnes()
    {
        var path = Path.Combine(Path.GetTempPath(), $"avtest_acl_{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "token-gia-dinh");
        try
        {
            // Ke tan cong dat truoc mot ACE explicit cho "Users" tren chinh file
            // ma service sap dung lam file token.
            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var fi = new FileInfo(path);
            var before = fi.GetAccessControl();
            before.AddAccessRule(new FileSystemAccessRule(
                usersSid, FileSystemRights.FullControl, AccessControlType.Allow));
            fi.SetAccessControl(before);

            // Xac nhan tien de: ACE do that su dang co mat.
            Assert.Contains(
                new FileInfo(path).GetAccessControl()
                    .GetAccessRules(true, false, typeof(SecurityIdentifier))
                    .Cast<FileSystemAccessRule>(),
                r => r.IdentityReference.Equals(usersSid));

            Antivirus.Service.Data.AclProtection.ProtectFile(path);

            // Sau khi gia co, KHONG duoc con ACE nao cho Users.
            var after = new FileInfo(path).GetAccessControl()
                .GetAccessRules(true, false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();
            Assert.DoesNotContain(after, r => r.IdentityReference.Equals(usersSid));
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    // ------------------------------------------------------------------
    // FirewallRuleStore — hash ghi vao (CHU HOA, nguoi dung dan tu VirusTotal
    // hoac Get-FileHash) phai khop hash tra cuu (CHU THUONG, do
    // ConnectionMonitor sinh ra bang .ToLowerInvariant()).
    //
    // Bo test cu cua ca 4 store deu dung DUNG MOT literal cho ca duong ghi
    // lan duong doc, nen ve mat cau truc chung khong the phat hien lech
    // hoa/thuong. Test nay co tinh dung HAI dang khac nhau o hai dau.
    // ------------------------------------------------------------------
    [Fact]
    public void FirewallRule_WrittenUppercase_IsFoundByLowercaseLookup()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"avtest_fw_{Guid.NewGuid():N}.db");
        try
        {
            var store = new Antivirus.Service.Extensions.Firewall.FirewallRuleStore(dbPath);
            var upper = new string('A', 64);

            store.Add(new Antivirus.Service.Extensions.Firewall.FirewallRule
            {
                AppSha256 = upper,
                Direction = Antivirus.Service.Extensions.Firewall.FirewallDirection.Outbound,
                Protocol = Antivirus.Service.Extensions.Firewall.FirewallProtocol.Any,
                Action = Antivirus.Service.Extensions.Firewall.FirewallAction.Block,
                Priority = 100,
                CreatedBy = "test",
            });

            var found = store.FindBestMatch(
                upper.ToLowerInvariant(),
                Antivirus.Service.Extensions.Firewall.FirewallDirection.Outbound,
                Antivirus.Service.Extensions.Firewall.FirewallProtocol.Tcp,
                443);

            Assert.NotNull(found);
            Assert.Equal(Antivirus.Service.Extensions.Firewall.FirewallAction.Block, found!.Action);
        }
        finally
        {
            try { File.Delete(dbPath); } catch { }
        }
    }

    // ------------------------------------------------------------------
    // ProtectionStatusService — phan biet "mot tang KHONG CHAY" voi "khong tu
    // cap nhat duoc". Tron hai loai nay lam dashboard bao "KHÔNG được bảo vệ"
    // tren mot may dang chan malware binh thuong (do duoc: EICAR bi cach ly
    // trong 10 giay trong khi dashboard bao khong duoc bao ve).
    //
    // Bao dong sai kieu do khong vo hai: no day nguoi dung toi cho quen nhin
    // den chi bao trang thai, dung luc chi bao do that su can duoc chu y.
    // ------------------------------------------------------------------
    [Theory]
    [InlineData("signature-db")]    // tang phat hien theo hash KHONG chay
    [InlineData("process-trust")]   // tang danh gia tien trinh KHONG chay
    [InlineData("data-acl")]        // du lieu bao ve co the bi sua
    [InlineData("audit-trail")]     // hanh dong khong de lai dau vet
    public void LayersThatAreNotRunning_AreCritical(string id)
    {
        var d = new Antivirus.Service.Security.ProtectionDegradation(
            id, Antivirus.Service.Security.ProtectionDegradation.Critical, "x");
        Assert.True(Antivirus.Service.Security.ProtectionStatusService.HasCritical(new[] { d }));
        Assert.Equal("critical", Antivirus.Service.Security.ProtectionStatusService.LevelOf(new[] { d }));
    }

    [Fact]
    public void CannotSelfUpdate_IsDegraded_NotUnprotected()
    {
        // Chi co suy giam muc Warning -> "degraded", KHONG phai "critical".
        // protectionEnabled (= !HasCritical) van la true: cac tang van chay.
        var warnings = new[]
        {
            new Antivirus.Service.Security.ProtectionDegradation(
                "update-channel", Antivirus.Service.Security.ProtectionDegradation.Warning, "x"),
            new Antivirus.Service.Security.ProtectionDegradation(
                "kernel-driver", Antivirus.Service.Security.ProtectionDegradation.Warning, "x"),
        };

        Assert.False(Antivirus.Service.Security.ProtectionStatusService.HasCritical(warnings));
        Assert.Equal("degraded", Antivirus.Service.Security.ProtectionStatusService.LevelOf(warnings));
    }

    // ------------------------------------------------------------------
    // ConnectionMonitor — dia chi IPv6 dinh tuyen toan cau PHAI duoc theo doi.
    // Truoc khi sua, MOI dia chi khong phai AddressFamily.InterNetwork deu tra
    // ve "coi nhu mang noi bo" va bi bo qua, nen ma doc beacon qua IPv6 hoan
    // toan vo hinh voi tang phat hien nay.
    // ------------------------------------------------------------------
    [Theory]
    [InlineData("2001:4860:4860::8888", false)] // IPv6 public — phai theo doi
    [InlineData("fe80::1", true)]               // link-local
    [InlineData("fd00::1", true)]               // unique local (fc00::/7)
    [InlineData("::1", true)]                   // loopback
    [InlineData("8.8.8.8", false)]              // IPv4 public
    [InlineData("192.168.1.10", true)]          // IPv4 private
    public void IsPrivateOrLoopback_ClassifiesIpv6Correctly(string address, bool expectedPrivate)
    {
        // Ham la private static va viec no dung KHONG quan sat duoc tu ben
        // ngoai neu khong dung mot bang TCP that — goi truc tiep qua reflection.
        var method = typeof(Antivirus.Service.Extensions.Firewall.ConnectionMonitor)
            .GetMethod("IsPrivateOrLoopback",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);

        var actual = (bool)method!.Invoke(null, new object[] { address })!;
        Assert.Equal(expectedPrivate, actual);
    }
}
