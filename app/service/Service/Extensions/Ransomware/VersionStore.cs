using Microsoft.Data.Sqlite;

namespace Antivirus.Service.Extensions.Ransomware;

// "tai lieu moi.txt" muc "Tu dong backup va rollback khi phat hien
// ransomware": KHONG dung Volume Shadow Copy (qua nang cho pham vi hep),
// tu xay copy-on-write version store rieng — cau truc tuong tu quarantine
// da co (thu muc ACL bao ve, doi ten khong giu duoi goc).
public sealed class VersionStoreRecord
{
    public long Id { get; set; }
    public required string OriginalPath { get; set; }
    public long VersionTimestampUnixMs { get; set; }
    public required string StoredPath { get; set; }
    public int TriggeredByPid { get; set; }
    public long FileSize { get; set; }
}

public sealed class VersionStore
{
    // "Chi giu mot so phien ban gan nhat cho moi file (vi du 3 phien ban)"
    public const int MaxVersionsPerFile = 3;

    private readonly string _connectionString;
    private readonly string _storageDir;

    public VersionStore(string dbPath, string storageDir)
    {
        _connectionString = $"Data Source={dbPath}";
        _storageDir = storageDir;
        Directory.CreateDirectory(_storageDir);
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS version_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                version_timestamp INTEGER NOT NULL,
                stored_path TEXT NOT NULL,
                triggered_by_pid INTEGER NOT NULL,
                file_size INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vs_path ON version_store(original_path);
            """;
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    public void SnapshotFile(string originalPath, int triggeredByPid)
    {
        if (!File.Exists(originalPath)) return;

        var storedName = Guid.NewGuid().ToString("N");
        var storedPath = Path.Combine(_storageDir, storedName);
        try
        {
            File.Copy(originalPath, storedPath, overwrite: false);
        }
        catch
        {
            return; // file dang bi khoa/loi doc — bo qua snapshot lan nay, khong chan luong chinh
        }

        var size = new FileInfo(storedPath).Length;

        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO version_store (original_path, version_timestamp, stored_path, triggered_by_pid, file_size)
            VALUES ($path, $ts, $stored, $pid, $size)
            """;
        cmd.Parameters.AddWithValue("$path", originalPath);
        cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$stored", storedPath);
        cmd.Parameters.AddWithValue("$pid", triggeredByPid);
        cmd.Parameters.AddWithValue("$size", size);
        cmd.ExecuteNonQuery();

        PruneOldVersions(originalPath);
    }

    private void PruneOldVersions(string originalPath)
    {
        using var conn = Open();
        using var selectCmd = conn.CreateCommand();
        selectCmd.CommandText = "SELECT id, stored_path FROM version_store WHERE original_path = $path ORDER BY version_timestamp DESC";
        selectCmd.Parameters.AddWithValue("$path", originalPath);

        var toDelete = new List<(long Id, string StoredPath)>();
        using (var reader = selectCmd.ExecuteReader())
        {
            int index = 0;
            while (reader.Read())
            {
                index++;
                if (index > MaxVersionsPerFile)
                {
                    toDelete.Add((reader.GetInt64(0), reader.GetString(1)));
                }
            }
        }

        foreach (var (id, storedPath) in toDelete)
        {
            try { File.Delete(storedPath); } catch { }
            using var delCmd = conn.CreateCommand();
            delCmd.CommandText = "DELETE FROM version_store WHERE id = $id";
            delCmd.Parameters.AddWithValue("$id", id);
            delCmd.ExecuteNonQuery();
        }
    }

    public VersionStoreRecord? GetLatestVersion(string originalPath)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM version_store WHERE original_path = $path ORDER BY version_timestamp DESC LIMIT 1";
        cmd.Parameters.AddWithValue("$path", originalPath);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? Map(reader) : null;
    }

    // "khoi phuc toan bo file da bi tien trinh do ghi de ... dua tren
    // triggered_by_pid de xac dinh dung tap file can khoi phuc" — o day
    // dung danh sach duong dan cu the (tu cua so thoi gian phat hien, xem
    // RansomwareGuardService) vi khong co PID chinh xac tu FileSystemWatcher
    // (han che da ghi trong features.md).
    public bool RestoreLatestVersion(string originalPath)
    {
        var latest = GetLatestVersion(originalPath);
        if (latest is null || !File.Exists(latest.StoredPath)) return false;

        try
        {
            File.Copy(latest.StoredPath, originalPath, overwrite: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public List<VersionStoreRecord> ListAllTrackedPaths()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM version_store ORDER BY version_timestamp DESC LIMIT 500";
        using var reader = cmd.ExecuteReader();
        var result = new List<VersionStoreRecord>();
        while (reader.Read()) result.Add(Map(reader));
        return result;
    }

    private static VersionStoreRecord Map(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(reader.GetOrdinal("id")),
        OriginalPath = reader.GetString(reader.GetOrdinal("original_path")),
        VersionTimestampUnixMs = reader.GetInt64(reader.GetOrdinal("version_timestamp")),
        StoredPath = reader.GetString(reader.GetOrdinal("stored_path")),
        TriggeredByPid = reader.GetInt32(reader.GetOrdinal("triggered_by_pid")),
        FileSize = reader.GetInt64(reader.GetOrdinal("file_size")),
    };
}
