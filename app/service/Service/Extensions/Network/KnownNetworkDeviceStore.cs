using Microsoft.Data.Sqlite;

namespace Antivirus.Service.Extensions.Network;

// Luu MAC address da tung thay de phan biet "thiet bi la chua tung thay
// truoc do" qua CAC LAN chay service (khong chi trong 1 phien) — "hien thi
// canh bao neu phat hien thiet bi la chua tung thay truoc do" (tai lieu).
public sealed class KnownNetworkDeviceStore
{
    private readonly string _connectionString;

    public KnownNetworkDeviceStore(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS known_devices (
                mac_address TEXT PRIMARY KEY,
                first_seen_unix_ms INTEGER NOT NULL
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

    public bool IsKnown(string macAddress)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(1) FROM known_devices WHERE mac_address = $mac";
        cmd.Parameters.AddWithValue("$mac", macAddress);
        return (long)cmd.ExecuteScalar()! > 0;
    }

    public void MarkKnown(string macAddress)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT OR IGNORE INTO known_devices (mac_address, first_seen_unix_ms) VALUES ($mac, $ts)";
        cmd.Parameters.AddWithValue("$mac", macAddress);
        cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        cmd.ExecuteNonQuery();
    }
}
