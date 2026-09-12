using Microsoft.Data.Sqlite;
using Antivirus.Service.Data;

namespace Antivirus.Service.Extensions.Usb;

public enum UsbAction { Allow, Block, Ask }

public sealed class UsbDeviceRule
{
    public long Id { get; set; }
    public required string VendorId { get; set; }
    public required string ProductId { get; set; }
    public string? SerialNumber { get; set; }
    public UsbAction Action { get; set; }
    public bool AutoScan { get; set; } = true;
}

// "tai lieu moi.txt" muc "Chinh sach allow/block theo VID/PID thiet bi":
// tra rule khop CA VID/PID LAN serial truoc, khong co moi tim rule chi
// khop VID/PID, khong co nua moi roi ve mac dinh (ask + auto_scan=1) —
// giu nhat quan voi thu tu tra rule cua app_rules (hash truoc, publisher sau).
// [SUA LOI HIEU NANG] Chuyen sang SqliteStoreBase (WAL + busy_timeout tren
// moi Open()) — truoc day tu mo SqliteConnection rieng khong co co che
// chong "database is locked" khi nhieu luong cung truy cap (xem
// SqliteStoreBase.cs va ScanCacheStore.cs cho boi canh loi da tung xay ra).
public sealed class UsbRuleStore : SqliteStoreBase
{
    public UsbRuleStore(string dbPath) : base(dbPath)
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
            CREATE TABLE IF NOT EXISTS usb_device_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                serial_number TEXT,
                action TEXT NOT NULL CHECK(action IN ('allow', 'block', 'ask')),
                auto_scan BOOLEAN NOT NULL DEFAULT 1
            );
            """,
        });
    }

    public long Add(UsbDeviceRule rule)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO usb_device_rules (vendor_id, product_id, serial_number, action, auto_scan)
            VALUES ($vid, $pid, $serial, $action, $scan);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$vid", rule.VendorId);
        cmd.Parameters.AddWithValue("$pid", rule.ProductId);
        cmd.Parameters.AddWithValue("$serial", (object?)rule.SerialNumber ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$action", rule.Action.ToString().ToLowerInvariant());
        cmd.Parameters.AddWithValue("$scan", rule.AutoScan);
        return (long)cmd.ExecuteScalar()!;
    }

    public void Delete(long id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM usb_device_rules WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public List<UsbDeviceRule> List()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM usb_device_rules";
        using var reader = cmd.ExecuteReader();
        var result = new List<UsbDeviceRule>();
        while (reader.Read()) result.Add(Map(reader));
        return result;
    }

    // [HAN CHE DA BIET] VendorId/ProductId/SerialNumber o day la du lieu do
    // CHINH THIET BI USB tu khai bao trong USB descriptor (GET_DESCRIPTOR)
    // luc enumerate — giao thuc USB KHONG co co che nao de host xac thuc
    // tinh xac thuc cua cac gia tri nay. Mot thiet bi BadUSB (vi du firmware
    // bi flash lai, hoac thiet bi HID gia danh) co the tu khai VID/PID/serial
    // TRUNG KHOP voi mot rule Allow da cau hinh de bypass hoan toan rule
    // Block/Ask ben duoi — day la gioi han KIEN TRUC cua chinh chuan USB
    // (thiet bi tu khai bao danh tinh, khong co chu ky/chung thuc phan
    // cung), khong phai loi logic co the sua o tang phan mem nay. Khong co
    // fix nao trong ResolvePolicy/UsbRuleStore co the dong hoan toan lo hong
    // nay; giam thieu thuc su (vi du: whitelist theo lop giao thuc + canh
    // bao khi mot thiet bi HID/Storage doi vai tro bat thuong) can du lieu
    // tu tang driver/kernel USB that, hien chua co trong pham vi chay duoc
    // cua phien nay (xem app/drivers/README.md).
    public UsbDeviceRule ResolvePolicy(string vendorId, string productId, string? serialNumber)
    {
        var all = List();

        if (serialNumber is not null)
        {
            var exact = all.FirstOrDefault(r => r.VendorId == vendorId && r.ProductId == productId && r.SerialNumber == serialNumber);
            if (exact is not null) return exact;
        }

        var byModel = all.FirstOrDefault(r => r.VendorId == vendorId && r.ProductId == productId && r.SerialNumber is null);
        if (byModel is not null) return byModel;

        // Mac dinh: "ask kem auto_scan = 1" — "vua khong chan cung gay bat
        // tien ngay lan dau, vua dam bao thiet bi la luon duoc quet truoc
        // khi nguoi dung thao tac voi noi dung ben trong".
        return new UsbDeviceRule { VendorId = vendorId, ProductId = productId, SerialNumber = serialNumber, Action = UsbAction.Ask, AutoScan = true };
    }

    private static UsbDeviceRule Map(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(reader.GetOrdinal("id")),
        VendorId = reader.GetString(reader.GetOrdinal("vendor_id")),
        ProductId = reader.GetString(reader.GetOrdinal("product_id")),
        SerialNumber = reader.IsDBNull(reader.GetOrdinal("serial_number")) ? null : reader.GetString(reader.GetOrdinal("serial_number")),
        Action = reader.GetString(reader.GetOrdinal("action")) switch { "allow" => UsbAction.Allow, "block" => UsbAction.Block, _ => UsbAction.Ask },
        AutoScan = reader.GetBoolean(reader.GetOrdinal("auto_scan")),
    };
}
