using Microsoft.Data.Sqlite;

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
public sealed class CloudReputationClient
{
    private readonly string _connectionString;

    public CloudReputationClient(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS cloud_reputation_mock (
                sha256 TEXT PRIMARY KEY,
                verdict TEXT NOT NULL DEFAULT 'unknown',
                prevalence INTEGER NOT NULL DEFAULT 0,
                confidence REAL NOT NULL DEFAULT 0.0
            );
            """;
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
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
