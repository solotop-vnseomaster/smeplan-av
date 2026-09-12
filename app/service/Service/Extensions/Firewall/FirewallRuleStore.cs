using Microsoft.Data.Sqlite;
using Antivirus.Service.Data;

namespace Antivirus.Service.Extensions.Firewall;

public enum FirewallDirection { Inbound, Outbound }
public enum FirewallProtocol { Tcp, Udp, Any }
public enum FirewallAction { Allow, Block }

public sealed class FirewallRule
{
    public long Id { get; set; }
    public required string AppSha256 { get; set; }
    public FirewallDirection Direction { get; set; }
    public FirewallProtocol Protocol { get; set; }
    public int? RemotePortStart { get; set; }
    public int? RemotePortEnd { get; set; }
    public FirewallAction Action { get; set; }
    public int Priority { get; set; } = 100;
    public required string CreatedBy { get; set; }
}

// "tai lieu moi.txt" muc "Thiet ke rule engine cho firewall" — schema va
// logic uu tien y het tai lieu mo ta: rule co PRIORITY CAO NHAT trong so
// cac rule khop dieu kien duoc ap dung, khong dung o rule khop dau tien.
// [SUA LOI HIEU NANG] Truoc day tu mo SqliteConnection rieng, khong bat
// WAL/busy_timeout (khac voi RuleStore/QuarantineStore trong Data/ da duoc
// vá) — chuyen sang SqliteStoreBase de dong bo co che chong "database is
// locked" khi nhieu luong cung truy cap (xem SqliteStoreBase.cs).
public sealed class FirewallRuleStore : SqliteStoreBase
{
    public FirewallRuleStore(string dbPath) : base(dbPath)
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
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_sha256 TEXT NOT NULL,
                direction TEXT NOT NULL CHECK(direction IN ('inbound', 'outbound')),
                protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp', 'any')),
                remote_port_start INTEGER,
                remote_port_end INTEGER,
                action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
                priority INTEGER NOT NULL DEFAULT 100,
                created_by TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_fw_app ON firewall_rules(app_sha256, direction);
            """,

            // [SUA LOI CAO — CHUAN HOA HASH] Xem FindBestMatch ben duoi.
            // Chi sua code so khop la KHONG DU: rule nguoi dung da luu tu
            // truoc van dang o dang chu HOA (dan tu VirusTotal/Get-FileHash),
            // va sau khi "sua" chung VAN khong khop — nhung luc do ai cung
            // tin la da xong. Chuan hoa du lieu da co ngay tai day.
            """
            UPDATE firewall_rules SET app_sha256 = lower(trim(app_sha256))
            WHERE app_sha256 <> lower(trim(app_sha256));
            """,
        });
    }

    // [SUA LOI CAO — LECH QUY UOC GIUA CAC MODULE] RuleStore.cs da dinh nghia
    // dung quy uoc nay (Trim + ToLowerInvariant, ap o CA duong ghi lan doc),
    // nhung store nay khong ap: FindBestMatch truoc day so sanh bang toan tu
    // == (ordinal, PHAN BIET hoa/thuong).
    //
    // Chuoi bang chung hai dau: app.js chap nhan regex [0-9a-fA-F]{64} nen
    // nguoi dung dan duoc hash CHU HOA tu VirusTotal / Get-FileHash va gui
    // nguyen ban; ConnectionMonitor tinh hash bang .ToLowerInvariant(). Hai
    // dau khong bao gio gap nhau.
    //
    // Hau qua sac nhat KHONG phai "rule khong chan" (tang nay von chua thuc
    // thi o kernel), ma la: ConnectionMonitor bo qua khi khong tim thay rule
    // khop, nen canh bao "ket noi nay le ra da bi chan" KHONG BAO GIO phat.
    // Nguoi dung doc duoc dong chu "chua thuc thi" nhung danh sach vi pham
    // luon rong — de hieu thanh "khong co gi vi pham". Lech quy uoc nay bit
    // dung kenh telemetry duy nhat con lai cua tang firewall.
    private static string NormalizeHash(string? hash) => (hash ?? string.Empty).Trim().ToLowerInvariant();

    public long Add(FirewallRule rule)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO firewall_rules (app_sha256, direction, protocol, remote_port_start, remote_port_end, action, priority, created_by)
            VALUES ($sha, $dir, $proto, $ps, $pe, $action, $prio, $by);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$sha", NormalizeHash(rule.AppSha256));
        cmd.Parameters.AddWithValue("$dir", rule.Direction == FirewallDirection.Inbound ? "inbound" : "outbound");
        cmd.Parameters.AddWithValue("$proto", rule.Protocol.ToString().ToLowerInvariant());
        cmd.Parameters.AddWithValue("$ps", (object?)rule.RemotePortStart ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$pe", (object?)rule.RemotePortEnd ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$action", rule.Action == FirewallAction.Allow ? "allow" : "block");
        cmd.Parameters.AddWithValue("$prio", rule.Priority);
        cmd.Parameters.AddWithValue("$by", rule.CreatedBy);
        return (long)cmd.ExecuteScalar()!;
    }

    public void Delete(long id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM firewall_rules WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public List<FirewallRule> List()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM firewall_rules ORDER BY priority DESC";
        using var reader = cmd.ExecuteReader();
        var result = new List<FirewallRule>();
        while (reader.Read()) result.Add(Map(reader));
        return result;
    }

    // Tra rule khop (app_sha256, direction, protocol/any, port trong khoang
    // neu co) co PRIORITY CAO NHAT — dung theo dung logic tai lieu mo ta.
    public FirewallRule? FindBestMatch(string appSha256, FirewallDirection direction, FirewallProtocol protocol, int? remotePort)
    {
        return List()
            .Where(r => NormalizeHash(r.AppSha256) == NormalizeHash(appSha256) && r.Direction == direction)
            .Where(r => r.Protocol == FirewallProtocol.Any || r.Protocol == protocol)
            .Where(r => !remotePort.HasValue || !r.RemotePortStart.HasValue ||
                        (remotePort.Value >= r.RemotePortStart && remotePort.Value <= (r.RemotePortEnd ?? r.RemotePortStart)))
            .OrderByDescending(r => r.Priority)
            .FirstOrDefault();
    }

    private static FirewallRule Map(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(reader.GetOrdinal("id")),
        AppSha256 = reader.GetString(reader.GetOrdinal("app_sha256")),
        Direction = reader.GetString(reader.GetOrdinal("direction")) == "inbound" ? FirewallDirection.Inbound : FirewallDirection.Outbound,
        Protocol = reader.GetString(reader.GetOrdinal("protocol")) switch { "tcp" => FirewallProtocol.Tcp, "udp" => FirewallProtocol.Udp, _ => FirewallProtocol.Any },
        RemotePortStart = reader.IsDBNull(reader.GetOrdinal("remote_port_start")) ? null : reader.GetInt32(reader.GetOrdinal("remote_port_start")),
        RemotePortEnd = reader.IsDBNull(reader.GetOrdinal("remote_port_end")) ? null : reader.GetInt32(reader.GetOrdinal("remote_port_end")),
        Action = reader.GetString(reader.GetOrdinal("action")) == "allow" ? FirewallAction.Allow : FirewallAction.Block,
        Priority = reader.GetInt32(reader.GetOrdinal("priority")),
        CreatedBy = reader.GetString(reader.GetOrdinal("created_by")),
    };
}
