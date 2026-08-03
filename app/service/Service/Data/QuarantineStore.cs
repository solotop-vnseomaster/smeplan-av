using Microsoft.Data.Sqlite;
using Antivirus.Service.Models;

namespace Antivirus.Service.Data;

// DATA-03: QuarantineRecord — bang SQLite rieng, KHONG chung bang voi
// app_rules (data-models/04 muc QuarantineRecord). Da bo sung truong
// `status` theo de xuat thong nhat trong 00-doi-chieu-cheo.md.
public sealed class QuarantineStore : SqliteStoreBase
{
    public QuarantineStore(string dbPath) : base(dbPath)
    {
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS quarantine_records (
                quarantine_id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                detection_reason TEXT NOT NULL,
                quarantined_at INTEGER NOT NULL,
                file_size INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    public void Add(QuarantineRecord record)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO quarantine_records
                (quarantine_id, original_path, original_filename, sha256_hash, detection_reason, quarantined_at, file_size, status)
            VALUES ($id, $path, $name, $hash, $reason, $at, $size, $status)
            """;
        cmd.Parameters.AddWithValue("$id", record.QuarantineId);
        cmd.Parameters.AddWithValue("$path", record.OriginalPath);
        cmd.Parameters.AddWithValue("$name", record.OriginalFilename);
        cmd.Parameters.AddWithValue("$hash", record.Sha256Hash);
        cmd.Parameters.AddWithValue("$reason", record.DetectionReason);
        cmd.Parameters.AddWithValue("$at", record.QuarantinedAt);
        cmd.Parameters.AddWithValue("$size", (long)record.FileSize);
        cmd.Parameters.AddWithValue("$status", record.Status.ToString());
        cmd.ExecuteNonQuery();
    }

    public void UpdateStatus(string quarantineId, QuarantineStatus status)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE quarantine_records SET status = $status WHERE quarantine_id = $id";
        cmd.Parameters.AddWithValue("$status", status.ToString());
        cmd.Parameters.AddWithValue("$id", quarantineId);
        cmd.ExecuteNonQuery();
    }

    public QuarantineRecord? Get(string quarantineId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM quarantine_records WHERE quarantine_id = $id";
        cmd.Parameters.AddWithValue("$id", quarantineId);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? Map(reader) : null;
    }

    // [TINH NANG THEO YEU CAU NGUOI DUNG] Xoa vinh vien ban ghi quarantine
    // — truoc day CHUA CO cach nao xoa record khoi bang nay (chi Restore
    // doi status, khong bao gio xoa dong). Goi tu QuarantineManager sau
    // khi da xoa xong file .qtn tren dia (neu con).
    public void Delete(string quarantineId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM quarantine_records WHERE quarantine_id = $id";
        cmd.Parameters.AddWithValue("$id", quarantineId);
        cmd.ExecuteNonQuery();
    }

    public List<QuarantineRecord> List()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM quarantine_records ORDER BY quarantined_at DESC";
        using var reader = cmd.ExecuteReader();
        var result = new List<QuarantineRecord>();
        while (reader.Read()) result.Add(Map(reader));
        return result;
    }

    private static QuarantineRecord Map(SqliteDataReader reader) => new()
    {
        QuarantineId = reader.GetString(reader.GetOrdinal("quarantine_id")),
        OriginalPath = reader.GetString(reader.GetOrdinal("original_path")),
        OriginalFilename = reader.GetString(reader.GetOrdinal("original_filename")),
        Sha256Hash = reader.GetString(reader.GetOrdinal("sha256_hash")),
        DetectionReason = reader.GetString(reader.GetOrdinal("detection_reason")),
        QuarantinedAt = reader.GetInt64(reader.GetOrdinal("quarantined_at")),
        FileSize = (ulong)reader.GetInt64(reader.GetOrdinal("file_size")),
        Status = Enum.Parse<QuarantineStatus>(reader.GetString(reader.GetOrdinal("status"))),
    };
}
