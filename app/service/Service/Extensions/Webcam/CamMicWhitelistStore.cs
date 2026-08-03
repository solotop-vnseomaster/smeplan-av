using Microsoft.Data.Sqlite;

namespace Antivirus.Service.Extensions.Webcam;

public sealed class CamMicWhitelistEntry
{
    public long Id { get; set; }
    public required string ProcessIdentity { get; set; }
    public required string AddedBy { get; set; }
}

// "tai lieu moi.txt" muc "Bao ve webcam va microphone": "Whitelist RIENG
// cho truy cap camera/mic (khac whitelist thuc thi hay whitelist ghi thu
// muc)... khong tu dong allow chi vi da qua whitelist chu ky so chung".
public sealed class CamMicWhitelistStore
{
    private readonly string _connectionString;

    public CamMicWhitelistStore(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS cam_mic_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_identity TEXT NOT NULL UNIQUE,
                added_by TEXT NOT NULL DEFAULT 'user'
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

    public long Add(string processIdentity, string addedBy = "user")
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT OR IGNORE INTO cam_mic_whitelist (process_identity, added_by) VALUES ($id, $by);
            SELECT id FROM cam_mic_whitelist WHERE process_identity = $id;
            """;
        cmd.Parameters.AddWithValue("$id", processIdentity);
        cmd.Parameters.AddWithValue("$by", addedBy);
        return (long)cmd.ExecuteScalar()!;
    }

    public void Delete(long id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM cam_mic_whitelist WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public List<CamMicWhitelistEntry> List()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, process_identity, added_by FROM cam_mic_whitelist";
        using var reader = cmd.ExecuteReader();
        var result = new List<CamMicWhitelistEntry>();
        while (reader.Read())
        {
            result.Add(new CamMicWhitelistEntry
            {
                Id = reader.GetInt64(0),
                ProcessIdentity = reader.GetString(1),
                AddedBy = reader.GetString(2),
            });
        }
        return result;
    }

    public bool IsWhitelisted(string processIdentity)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(1) FROM cam_mic_whitelist WHERE process_identity = $id";
        cmd.Parameters.AddWithValue("$id", processIdentity);
        return (long)cmd.ExecuteScalar()! > 0;
    }
}
