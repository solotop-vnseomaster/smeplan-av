using Microsoft.Data.Sqlite;
using Antivirus.Service.Data;

namespace Antivirus.Service.Extensions.Network;

// Luu MAC address da tung thay de phan biet "thiet bi la chua tung thay
// truoc do" qua CAC LAN chay service (khong chi trong 1 phien) — "hien thi
// canh bao neu phat hien thiet bi la chua tung thay truoc do" (tai lieu).
//
// [SUA LOI HIEU NANG] Chuyen sang SqliteStoreBase (WAL + busy_timeout) —
// truoc day tu mo SqliteConnection rieng, cung mot lo hong "database is
// locked" da tung phai vá o ScanCacheStore.cs (xem SqliteStoreBase.cs).
public sealed class KnownNetworkDeviceStore : SqliteStoreBase
{
    public KnownNetworkDeviceStore(string dbPath) : base(dbPath)
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
            CREATE TABLE IF NOT EXISTS known_devices (
                mac_address TEXT PRIMARY KEY,
                first_seen_unix_ms INTEGER NOT NULL
            );
            """,
        });
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
