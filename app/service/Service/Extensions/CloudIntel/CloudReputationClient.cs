using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Antivirus.Service.Data;

namespace Antivirus.Service.Extensions.CloudIntel;

public enum CloudVerdict { Unknown, Clean, Malicious, Suspicious }

public sealed record CloudReputationResult(CloudVerdict Verdict, int Prevalence, double Confidence);

// "tai lieu moi.txt" muc "Tich hop cloud threat intelligence":
// POST /v1/reputation { sha256, file_size, first_seen_locally }
// -> { verdict, prevalence, confidence }.
//
// [QUYET DINH TRIEN KHAI] Moi truong nay khong co ket noi toi mot backend
// cloud that tong hop du lieu tu "toan bo nguoi dung khac" — dung MOT
// NGUON LOCAL GIA LAP (SQLite), CUNG TINH THAN voi cach UpdateClientService
// da gia lap nguon CSDL qua LocalFolderUpdatePackageSource. Gia lap
// "prevalence" bang cach dem SO LAN chinh may nay tung tra cuu hash do —
// khong the tai tao that "so may khac da thay hash nay" khi chi co dung
// mot may that trong moi truong nay, nhung van giu dung Y NGHIA quan
// trong nhat cua truong nay theo tai lieu: hash MOI GAP LAN DAU (chua
// tung thay truoc do) luon tra ve prevalence = 0, dung boi canh bao "rat
// hiem, dang chu y".
// [SUA LOI HIEU NANG] Chuyen sang SqliteStoreBase (WAL + busy_timeout) —
// Lookup() vua doc vua ghi (UPDATE prevalence / INSERT) tren MOI lan goi,
// nen la nguon nghen lock contention ro nhat trong so cac store Extensions/
// chua duoc vá, giong loi ScanCacheStore.cs tung gap (xem SqliteStoreBase.cs).
public sealed class CloudReputationClient : SqliteStoreBase
{
    // [SUA LOI NHO] /api/cloud-intel/lookup truoc day dua req.Sha256 (chuoi
    // THO tu client) thang vao Lookup() ma khong kiem tra dinh dang — khong
    // phai SQL injection (da dung parameterized query) nhung mot chuoi bat
    // ky (rong, qua dai, khong phai hex...) van duoc INSERT nhu mot "hash"
    // hop le vao bang mock, lam ban ghi/thong ke prevalence vo nghia. Tac
    // dong thap vi day chi la backend mock cuc bo (khong phai cloud that),
    // nhung kiem tra dinh dang re va giup API nhat quan voi cac endpoint
    // khac (vi du /api/scan/file da validate Path).
    private static readonly Regex Sha256HexPattern = new("^[a-fA-F0-9]{64}$", RegexOptions.Compiled);

    public static bool IsValidSha256Hex(string? value) =>
        !string.IsNullOrEmpty(value) && Sha256HexPattern.IsMatch(value);

    public CloudReputationClient(string dbPath) : base(dbPath)
    {
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        // [SUA LOI CAO] Schema cua store nay TRUOC DAY chay bang
        // "CREATE TABLE IF NOT EXISTS" tran, khong co danh so phien ban —
        // nghia la mot CSDL tao boi ban cu se KHONG BAO GIO nhan duoc cot/
        // index moi khi nguoi dung cap nhat ung dung, va loi chi bung ra
        // luc chay tren may ho. Xem SqliteStoreBase.EnsureSchema.
        //
        // QUY TAC: KHONG BAO GIO sua noi dung mot phan tu da co trong mang
        // duoi day (may nguoi dung da chay no roi, sua o day khong chay lai).
        // Thay doi schema = THEM mot chuoi migration MOI vao CUOI mang.
        EnsureSchema(conn, new[]
        {
            """
            CREATE TABLE IF NOT EXISTS cloud_reputation_mock (
                sha256 TEXT PRIMARY KEY,
                verdict TEXT NOT NULL DEFAULT 'unknown',
                prevalence INTEGER NOT NULL DEFAULT 0,
                confidence REAL NOT NULL DEFAULT 0.0
            );
            """,
        });
    }

    public CloudReputationResult Lookup(string sha256Hex)
    {
        using var conn = Open();

        using (var selectCmd = conn.CreateCommand())
        {
            selectCmd.CommandText = "SELECT verdict, prevalence, confidence FROM cloud_reputation_mock WHERE sha256 = $h";
            selectCmd.Parameters.AddWithValue("$h", sha256Hex);
            using var reader = selectCmd.ExecuteReader();
            if (reader.Read())
            {
                var existingVerdict = ParseVerdict(reader.GetString(0));
                int existingPrevalence = reader.GetInt32(1) + 1;
                double existingConfidence = reader.GetDouble(2);
                reader.Close();

                using var updateCmd = conn.CreateCommand();
                updateCmd.CommandText = "UPDATE cloud_reputation_mock SET prevalence = $p WHERE sha256 = $h";
                updateCmd.Parameters.AddWithValue("$p", existingPrevalence);
                updateCmd.Parameters.AddWithValue("$h", sha256Hex);
                updateCmd.ExecuteNonQuery();

                return new CloudReputationResult(existingVerdict, existingPrevalence, existingConfidence);
            }
        }

        using (var insertCmd = conn.CreateCommand())
        {
            insertCmd.CommandText = "INSERT INTO cloud_reputation_mock (sha256, verdict, prevalence, confidence) VALUES ($h, 'unknown', 0, 0.0)";
            insertCmd.Parameters.AddWithValue("$h", sha256Hex);
            insertCmd.ExecuteNonQuery();
        }

        // "prevalence = 0 (rat hiem, dang chu y)" — dung cho hash lan dau gap.
        return new CloudReputationResult(CloudVerdict.Unknown, 0, 0.0);
    }

    private static CloudVerdict ParseVerdict(string raw) => raw switch
    {
        "clean" => CloudVerdict.Clean,
        "malicious" => CloudVerdict.Malicious,
        "suspicious" => CloudVerdict.Suspicious,
        _ => CloudVerdict.Unknown,
    };
}
