using System.Diagnostics;
using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Engine;
using Antivirus.Service.Models;
using Antivirus.Service.Quarantine;

namespace Antivirus.Service.Trust;

// business-rules/05-nghiep-vu.md muc "Quyet dinh cap quyen cho tien trinh
// moi (Process Trust Decision)" — toan bo state machine BIZ-01..04.
public sealed class ProcessTrustEngine
{
    // BIZ-04: "toi da 30 giay cho truong hop can hoi nguoi dung". Co the
    // ghi de qua constructor de kiem thu (khong doi hanh vi mac dinh khi
    // chay that).
    private readonly TimeSpan _userDecisionTimeout;

    // Whitelist 3 lop: chu ky so hop le + publisher khop Microsoft + vi tri
    // thu muc duoc WRP bao ve (khong dung ten file/duong dan lam can cu
    // chinh — ERR-TRUST-01 trong so tay loi).
    private static readonly string[] TrustedDirectories =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
    };

    private readonly RuleStore _rules;
    private readonly PermissionRequestBroker _broker;
    private readonly AuditLogger _audit;
    private readonly ILogger<ProcessTrustEngine> _logger;

    public ProcessTrustEngine(RuleStore rules, PermissionRequestBroker broker, AuditLogger audit,
        ILogger<ProcessTrustEngine> logger, TimeSpan? userDecisionTimeout = null)
    {
        _rules = rules;
        _broker = broker;
        _audit = audit;
        _logger = logger;
        _userDecisionTimeout = userDecisionTimeout ?? TimeSpan.FromSeconds(30);
    }

    // [SUA LOI NGHIEM TRONG] TrustedDirectories chua NGUYEN %WINDIR%, nhung
    // ben trong %WINDIR% co nhieu thu muc ma NGUOI DUNG THUONG GHI DUOC theo
    // ACL mac dinh cua Windows — C:\Windows\Tasks va C:\Windows\Temp la hai
    // vi du kinh dien. "Nam trong thu muc duoc WRP bao ve" vi vay KHONG con
    // dung cho nhung duong dan do: ke tan cong quyen thuong tha binary vao
    // C:\Windows\Tasks la thoa mot trong ba tieu chi trusted-by-default ma
    // khong can quyen gi them. Ket hop voi mot cert tu ky mang
    // "CN=Microsoft Corporation" duoc cai vao LocalMachine\Root, du ca ba
    // tieu chi — thanh mot chuoi leo thang len SYSTEM hoan chinh.
    //
    // Sua: giu danh sach tin cay nhung LOAI TRU tuong minh cac thu muc con
    // ghi duoc. Danh sach loai tru duoc kiem tra TRUOC, va bang cung
    // IsPathUnderDirectory (da resolve reparse point) nen khong the vong
    // qua bang junction.
    private static readonly string[] UserWritableExclusions = BuildUserWritableExclusions();

    private static string[] BuildUserWritableExclusions()
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(win)) return Array.Empty<string>();
        // Cac thu muc duoi %WINDIR% co ACE ghi cho Users/Authenticated Users
        // trong cau hinh mac dinh cua Windows.
        string[] relative =
        {
            "Tasks",
            "Temp",
            "Tracing",
            "debug",
            @"System32\Tasks",
            @"System32\spool\drivers\color",
            @"System32\Microsoft\Crypto\RSA\MachineKeys",
            @"SysWOW64\Tasks",
            @"registration\CRMLog",
            @"System32\com\dmp",
            @"SysWOW64\com\dmp",
        };
        return relative.Select(r => Path.Combine(win, r)).ToArray();
    }

    private static bool IsInTrustedDirectory(string processPath)
    {
        bool inTrusted = TrustedDirectories.Where(d => !string.IsNullOrEmpty(d))
            .Any(d => Antivirus.Service.Common.PathUtil.IsPathUnderDirectory(processPath, d));
        if (!inTrusted) return false;

        bool inWritableHole = UserWritableExclusions
            .Any(d => Antivirus.Service.Common.PathUtil.IsPathUnderDirectory(processPath, d));
        return !inWritableHole;
    }

    public async Task<ProcessTrustDecision> EvaluateAsync(string processPath, int pid, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        if (!File.Exists(processPath))
        {
            return Finish(sw, processPath, pid, "", null, ProcessTrustState.Blocked, false,
                "Khong tim thay file thuc thi tren dia — tu choi mac dinh (an toan hon allow mu)");
        }

        var sha256 = ComputeSha256(processPath);
        // Xem ghi chu tai AuthenticodeVerifier.VerifyAsync: bao deadline
        // cung quanh WinVerifyTrust (revocation check qua mang khong
        // timeout) de mot process moi khoi chay khong bi treo vo thoi han
        // khi mang cham/proxy chan.
        var authenticode = await AuthenticodeVerifier.VerifyAsync(processPath, TimeSpan.FromSeconds(5), ct);
        bool isMicrosoftPublisher = AuthenticodeVerifier.IsMicrosoftPublisher(authenticode.PublisherName);
        bool inTrustedDirectory = IsInTrustedDirectory(processPath);

        // [SUA LOI CAO] TRUOC DAY nhanh TrustedByDefault ben duoi chay TRUOC
        // moi lan tra rule. Hau qua: mot rule Block do NGUOI DUNG tu dat cho
        // mot binary Microsoft trong \Windows\System32 bi bo qua hoan toan —
        // dung nhung binary ma nguoi dung co ly do chinh dang muon chan
        // (powershell.exe, certutil.exe, mshta.exe, wmic.exe... — bo LOLBin
        // kinh dien duoc dung de "living off the land"). Rule hien ra trong
        // UI nhu the dang co hieu luc, nhung khong bao gio duoc doi chieu.
        //
        // Chinh sach TUONG MINH cua nguoi dung phai thang mac dinh cua he
        // thong. Tra rule Block TRUOC; cac nhanh con lai (Allow theo rule,
        // publisher, hoi nguoi dung) van giu nguyen thu tu cu ben duoi.
        var explicitBlock = string.IsNullOrEmpty(sha256) ? null : _rules.FindByHash(sha256);
        if (explicitBlock is not null && explicitBlock.Action == RuleAction.Block)
        {
            return Finish(sw, processPath, pid, sha256, authenticode, ProcessTrustState.RuleBlock, false,
                $"Khop rule CHAN tuong minh theo hash (id={explicitBlock.Id}) — rule nguoi dung uu tien hon trusted-by-default");
        }

        // Unknown -> TrustedByDefault: ca 3 tieu chi phai dung DONG THOI
        // (khong tach roi) — SEC-01/domain invariant.
        if (authenticode.ChainValid && isMicrosoftPublisher && inTrustedDirectory)
        {
            return Finish(sw, processPath, pid, sha256, authenticode, ProcessTrustState.TrustedByDefault, true,
                "Dat du 3 tieu chi trusted-by-default: chu ky so hop le + publisher Microsoft + thu muc duoc bao ve");
        }

        // Unknown -> RuleAllow/RuleBlock: tra hash truoc, publisher sau.
        //
        // [SUA LOI NGHIEM TRONG] ComputeSha256 tra ve "" khi hash that bai
        // (file bi khoa/loi I/O — xem catch ben duoi). TRUOC DAY sha256=""
        // van duoc dua thang vao FindByHash("") nhu binh thuong: neu tung
        // co MOT rule duoc tao voi Sha256Hash="" (xem nhanh AllowAlways ben
        // duoi, cung da duoc sua), thi BAT KY file nao khac ma hash SAU NAY
        // cung that bai se khop nham vao đúng rule "cho phep" do — ke ca
        // file doc hai. Sua: KHONG tra cuu theo hash khi sha256 rong, coi
        // nhu "khong co rule theo hash" va rot xuong kiem tra publisher/
        // hoi nguoi dung nhu binh thuong.
        var ruleByHash = string.IsNullOrEmpty(sha256) ? null : _rules.FindByHash(sha256);
        if (ruleByHash is not null)
        {
            bool allow = ruleByHash.Action == RuleAction.Allow;
            return Finish(sw, processPath, pid, sha256, authenticode,
                allow ? ProcessTrustState.RuleAllow : ProcessTrustState.RuleBlock, allow,
                $"Khop rule theo hash (id={ruleByHash.Id}, action={ruleByHash.Action})");
        }
        if (authenticode.PublisherThumbprint is not null)
        {
            var ruleByPub = _rules.FindByPublisher(authenticode.PublisherThumbprint);
            if (ruleByPub is not null)
            {
                bool allow = ruleByPub.Action == RuleAction.Allow;

                // [SUA LOI NGHIEM TRONG — GUARD DUNG, TRUOC DAY AP THIEU DUONG]
                // Nhanh trusted-by-default o tren doi authenticode.ChainValid
                // truoc khi tin vao publisher. Nhanh nay thi khong — va do la
                // mot duong vong qua danh sach cho phep.
                //
                // AuthenticodeVerifier.Verify lay thumbprint bang
                // X509Certificate.CreateFromSignedFile, ham nay chi DOC
                // certificate nhung trong khoi chu ky cua file PE, KHONG xac
                // thuc gi ca (viec xac thuc do WinVerifyTrust lam rieng, va
                // ket qua nam o ChainValid). Nghia la thumbprint van duoc dien
                // day du ngay ca khi chu ky HONG hoan toan.
                // Ke tan cong chi can lay certificate cong khai cua mot nha
                // phat hanh ma nguoi dung da tung bam "Cho phep luon" (cert
                // cong khai — ai cung lay duoc tu bat ky nhi phan da ky nao
                // cua ho), nhet vao khoi chu ky cua file doc hai cua minh, va
                // rule allow-by-publisher se khop. Khong can khoa riêng, khong
                // can pha vo mat ma gi ca.
                //
                // Sua: chi cho phep theo publisher khi chuoi chung thu THAT SU
                // hop le. Huong CHAN thi giu nguyen bat ke ChainValid — mot
                // rule chan van phai chan, chu ky hong khong duoc thanh duong
                // thoat khoi lenh cam.
                if (allow && !authenticode.ChainValid)
                {
                    _audit.Log("process-trust",
                        $"KHONG ap dung rule cho-phep theo publisher cho {processPath}: chuoi chung thu " +
                        "KHONG hop le (thumbprint doc duoc tu khoi chu ky khong dam bao chu ky dung) — " +
                        "chuyen sang hoi nguoi dung",
                        new { pid, ruleId = ruleByPub.Id, thumbprint = authenticode.PublisherThumbprint });
                }
                else
                {
                    return Finish(sw, processPath, pid, sha256, authenticode,
                        allow ? ProcessTrustState.RuleAllow : ProcessTrustState.RuleBlock, allow,
                        $"Khop rule theo publisher (id={ruleByPub.Id}, action={ruleByPub.Action})");
                }
            }
        }

        // Unknown -> PendingUserDecision: khong dat trusted-by-default va
        // khong co rule nao ca hash lan publisher.
        _audit.Log("process-trust", $"Cho nguoi dung quyet dinh cho tien trinh: {processPath}",
            new { pid, sha256 });

        var choice = await _broker.RequestDecisionAsync(
            processPath, sha256, authenticode.PublisherName, authenticode.PublisherThumbprint,
            _userDecisionTimeout, ct);

        if (choice is null)
        {
            // Het timeout khong phan hoi -> deny-and-log mac dinh (BIZ-04, NFR-AVAIL-03).
            return Finish(sw, processPath, pid, sha256, authenticode, ProcessTrustState.DeniedByTimeout, false,
                "Het thoi gian cho nguoi dung (30s) — mac dinh deny-and-log, KHONG allow mu");
        }

        switch (choice.Value)
        {
            case UserPermissionChoice.AllowAlways:
                // [SUA LOI NGHIEM TRONG] Neu sha256 rong (hash that bai o
                // tren), TRUOC DAY van tao rule Scope=Hash voi Sha256Hash=""
                // — mot rule "cho phep" khop VOI BAT KY file nao khac ma
                // hash cung that bai sau nay (xem ghi chu FindByHash o tren).
                // Sua: khong bao gio luu rule voi hash rong. Neu co publisher
                // thumbprint hop le thi ha xuong scope=publisher (van la
                // mot dinh danh co nghia); neu khong co gi de dinh danh on
                // dinh (ca hash lan publisher deu khong dung duoc) thi
                // KHONG the luu rule vinh vien an toan — ha xuong hanh vi
                // AllowedOnce (chi cho phep lan nay, hoi lai lan sau) thay
                // vi tao mot rule "mo" co the bi loi dung.
                if (!string.IsNullOrEmpty(sha256))
                {
                    _rules.Add(new AppRule
                    {
                        Sha256Hash = sha256,
                        PublisherThumbprint = authenticode.PublisherThumbprint,
                        FilePath = processPath,
                        Action = RuleAction.Allow,
                        Scope = RuleScope.Hash,
                        CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        CreatedBy = RuleCreatedBy.User,
                    });
                    return Finish(sw, processPath, pid, sha256, authenticode, ProcessTrustState.AllowedAlways, true,
                        "Nguoi dung chon 'Cho phep luon' — da luu rule vinh vien theo scope=hash");
                }
                // Cung ly do nhu guard ChainValid o nhanh tra cuu rule theo
                // publisher ben tren: mot thumbprint doc duoc tu khoi chu ky
                // HONG khong dinh danh duoc ai ca. Luu no thanh rule cho-phep
                // vinh vien la ghi thang mot duong vong vao CSDL chinh sach.
                if (authenticode.PublisherThumbprint is not null && authenticode.ChainValid)
                {
                    _rules.Add(new AppRule
                    {
                        Sha256Hash = sha256,
                        PublisherThumbprint = authenticode.PublisherThumbprint,
                        FilePath = processPath,
                        Action = RuleAction.Allow,
                        Scope = RuleScope.Publisher,
                        CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        CreatedBy = RuleCreatedBy.User,
                    });
                    return Finish(sw, processPath, pid, sha256, authenticode, ProcessTrustState.AllowedAlways, true,
                        "Khong hash duoc file nhung co publisher hop le — da luu rule vinh vien theo scope=publisher thay vi hash rong");
                }
                return Finish(sw, processPath, pid, sha256, authenticode, ProcessTrustState.AllowedOnce, true,
                    "Khong hash duoc file va khong co publisher voi chuoi chung thu hop le — TU CHOI luu rule vinh vien (tranh rule voi hash rong / thumbprint tu chu ky hong bi loi dung), ha xuong 'chi lan nay'");

            case UserPermissionChoice.AllowOnce:
                return Finish(sw, processPath, pid, sha256, authenticode, ProcessTrustState.AllowedOnce, true,
                    "Nguoi dung chon 'Chi lan nay' — khong luu rule, se hoi lai lan sau");

            default:
                return Finish(sw, processPath, pid, sha256, authenticode, ProcessTrustState.Blocked, false,
                    "Nguoi dung chon 'Chan'");
        }
    }

    private string ComputeSha256(string path)
    {
        try
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Khong hash duoc {Path}", path);
            return "";
        }
    }

    private ProcessTrustDecision Finish(Stopwatch sw, string path, int pid, string sha256,
        AuthenticodeResult? auth, ProcessTrustState state, bool allowed, string reason)
    {
        sw.Stop();
        var decision = new ProcessTrustDecision
        {
            ProcessPath = path,
            Pid = pid,
            Sha256 = sha256,
            PublisherThumbprint = auth?.PublisherThumbprint,
            PublisherName = auth?.PublisherName,
            State = state,
            Allowed = allowed,
            ChainVerificationCompleted = auth?.ChainVerificationCompleted ?? true,
            Reason = reason,
            ElapsedMs = sw.ElapsedMilliseconds,
        };
        _audit.Log("process-trust",
            $"{(allowed ? "ALLOW" : "BLOCK")} [{state}] {path} ({sw.ElapsedMilliseconds}ms)",
            decision);
        return decision;
    }
}
