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

        // [SUA LOI CAO — THU TU BAT BUOC] ACL PHAI duoc ap dung TRUOC khi
        // token cham vao dia. TRUOC DAY thu tu nguoc lai: File.WriteAllText
        // ghi token ra dia roi MOI goi ProtectDataDirectory — trong cua so
        // giua hai lenh do, file bi mat gac toan bo /api/* nam trong mot thu
        // muc con ke thua ACL cua ProgramData (Users co quyen ghi). Va neu
        // ACL that bai thi catch {} nuot im lang, khong ai biet token dang
        // nam tho.
        var tokenDir = Path.GetDirectoryName(TokenFilePath);
        AclFailure = null;
        try
        {
            if (!string.IsNullOrEmpty(tokenDir))
            {
                Directory.CreateDirectory(tokenDir);
                AclProtection.ProtectDataDirectory(tokenDir);
            }
        }
        catch (Exception ex)
        {
            // KHONG nuot im lang nua: ghi lai de Program.cs bao dong ro rang.
            // Van tiep tuc chay (tren may dev khong elevate day la binh
            // thuong) nhung su viec phai hien ra, khong duoc bien mat.
            AclFailure = ex;
        }

        // [SUA LOI CAO — TOKEN FIXATION] TRUOC DAY code doc file token co
        // san va TIN NOI DUNG cua no vo dieu kien. Ke tan cong ghi truoc mot
        // file api-token.txt voi gia tri ho tu chon (de dang: thu muc chua
        // duoc ACL o lan khoi dong dau tien, xem thu tu sai o tren) la HO
        // BIET TOKEN — va service se dung dung token do lam bi mat xac thuc.
        // Do la token fixation kinh dien.
        //
        // Sua: chi tai su dung token cu khi no CO DINH DANG DUNG bang token
        // do chinh ta sinh ra (43 ky tu base64url tu 32 byte ngau nhien).
        // Gia tri sai dinh dang bi vut bo va thay bang token moi. Dieu nay
        // khong chan duoc ke tan cong ghi mot token dung dinh dang, nen
        // lop phong thu THAT SU la ACL o tren chay TRUOC — hai lop cung nhau.
        string? existing = null;
        if (File.Exists(TokenFilePath))
        {
            try { existing = File.ReadAllText(TokenFilePath).Trim(); }
            catch { existing = null; }
        }

        Token = IsWellFormedToken(existing) ? existing! : GenerateToken();

        File.WriteAllText(TokenFilePath, Token);
        try { AclProtection.ProtectFile(TokenFilePath); }
        catch (Exception ex) { AclFailure ??= ex; }
    }

    // Loi ACL (neu co) gap luc khoi tao — Program.cs doc de bao dong. null
    // nghia la thu muc/file token da duoc bao ve dung.
    public Exception? AclFailure { get; }

    // Token do GenerateToken() sinh ra luon la 32 byte ngau nhien ma hoa
    // base64url khong padding = dung 43 ky tu trong bang chu cai base64url.
    private static bool IsWellFormedToken(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate) || candidate.Length != 43) return false;
        foreach (char c in candidate)
        {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                   || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return false;
        }
        return true;
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
