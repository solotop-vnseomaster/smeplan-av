using System.Security.Cryptography;
using Antivirus.Service.Data;

namespace Antivirus.Service.Security;

// [SUA LOI NGHIEM TRONG] API loopback (127.0.0.1) TRUOC DAY khong co bat
// ky xac thuc nao — bat ky tien trinh cuc bo nao (ke ca chinh malware dang
// bi danh gia) co the goi POST /api/rules de tu them rule "Allow" cho chinh
// no, bo qua toan bo Process Trust Decision va Quarantine tu dong. TCP
// loopback tren Windows KHONG tu phan biet tien trinh/nguoi dung nao duoc
// goi — day la lo hong that, khong phai suy doan.
//
// Fix: sinh MOT token ngau nhien moi lan service khoi dong (giong co che
// Jupyter/nhieu local dev server dung), ghi vao file duoc ACL bao ve, moi
// request toi /api/* phai kem token qua header X-Av-Token hoac query
// ?token=. Day KHONG phai bao mat tuyet doi (malware chay CUNG mot user
// dang nhap ve ly thuyet van doc duoc file token neu ACL cua may khong du
// manh), nhung chan dung hoan toan lop tan cong de nhat: mot tien trinh
// bat ky tu do goi thang API ma khong can biet gi ve token.
public sealed class ApiTokenProvider
{
    public string Token { get; }
    public string TokenFilePath { get; }

    // tokenFilePath la optional (mac dinh dung DataPaths.DataDir/api-token.txt
    // trong production that) — kiem thu co the truyen path rieng de co lap
    // voi ProgramData that, dung theo convention da dung o RuleStore/
    // VersionStore/ScanCacheStore/UpdateClientService trong cung project nay.
    public ApiTokenProvider(string? tokenFilePath = null)
    {
        TokenFilePath = tokenFilePath ?? Path.Combine(DataPaths.DataDir, "api-token.txt");

        // [UX FIX] Truoc day sinh token MOI moi lan service khoi dong lai —
        // dung nhu Jupyter, nhung gay phien khi dang phat trien/vá loi:
        // moi lan restart service de test, URL/tab trinh duyet nguoi dung
        // dang mo (kem token cu) lap tuc thanh vo hieu, hien 401 kho hieu.
        // Giu nguyen token qua cac lan restart (chi doi khi file bi xoa
        // thu cong, hoac chua tung ton tai) — van dam bao token la bi mat
        // ngau nhien, chi khac o cho no ON DINH giua cac lan chay, giong
        // nhieu local dev server khac (vi du VS Code Server) hay lam.
        if (File.Exists(TokenFilePath))
        {
            var existing = File.ReadAllText(TokenFilePath).Trim();
            Token = existing.Length > 0 ? existing : GenerateToken();
        }
        else
        {
            Token = GenerateToken();
        }

        File.WriteAllText(TokenFilePath, Token);

        try
        {
            // Bao ve thu muc CHUA token file thuc su (khong luon la
            // DataPaths.DataDir — khi test truyen tokenFilePath rieng, day
            // se la thu muc tam cua test, khong dung cham vao ProgramData that).
            var tokenDir = Path.GetDirectoryName(TokenFilePath);
            if (!string.IsNullOrEmpty(tokenDir)) AclProtection.ProtectDataDirectory(tokenDir);
        }
        catch
        {
            // Han che moi truong da biet (khong chay quyen SYSTEM/Administrator) —
            // van tiep tuc chay, token van co hieu luc chan tan cong "goi API vo tu",
            // chi la ACL tren file token chua duoc tang cuong them tren may dev nay.
        }
    }

    private static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    // So sanh khong ro ri thoi gian (chong timing attack don gian, du ban
    // than mo hinh de doa cua mot app loopback cuc bo it quan trong hon
    // mot dich vu mang, van lam dung cach).
    public bool Validate(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate)) return false;
        var a = System.Text.Encoding.UTF8.GetBytes(candidate);
        var b = System.Text.Encoding.UTF8.GetBytes(Token);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
}
