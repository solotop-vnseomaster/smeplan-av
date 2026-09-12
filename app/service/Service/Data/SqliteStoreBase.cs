using Microsoft.Data.Sqlite;

namespace Antivirus.Service.Data;

// [TAI CAU TRUC] RuleStore va QuarantineStore truoc day tu lap lai y het
// logic mo SqliteConnection (field _connectionString + ham Open() rieng),
// khong co lop co so chung — de quen bat mot cross-cutting concern (WAL,
// busy_timeout, retry...) o MOT file ma khong sua file kia khi can sua dong
// thoi ca hai. ScanCacheStore.cs (FullScan/) tung phai vá rieng loi hieu
// nang chinh vi thieu WAL + busy_timeout (xem ghi chu "[SUA LOI HIEU NANG]"
// trong file do) — RuleStore/QuarantineStore van chua co cung co che do.
// Lop co so nay duoc dung chung boi ca store trong Data/ (RuleStore,
// QuarantineStore) LAN cac store SqliteConnection duoi Extensions/
// (Firewall, Usb, Phishing, Ransomware/VersionStore, Webcam, Network,
// CloudIntel) — giong cach DataPaths.cs/AclProtection.cs (cung nam trong
// Data/) da duoc dung chung tu truoc. Doi Open() o day anh huong toi TAT
// CA cac store ke thua, khong chi rieng Data/.
public abstract class SqliteStoreBase
{
    private readonly string _connectionString;

    protected SqliteStoreBase(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
    }

    // Bat WAL (cho phep nhieu doc dong thoi voi 1 ghi, giam khoa toan bo file
    // DB moi lan ghi) + dat busy_timeout — giam nghen co chai lock contention
    // khi nhieu luong/tien trinh cung truy cap CSDL, cung ly do da tung sua
    // rieng le trong ScanCacheStore.cs.
    //
    // Hai pragma nay KHAC NHAU ve pham vi hieu luc, du cung chay lai moi lan
    // Open(): journal_mode=WAL duoc GHI VAO CHINH FILE DB (chi can set MOT
    // LAN trong doi database, cac lan Open() sau chi la truy van/no-op re
    // vi mode da la WAL san — khong ton hai gi ve hieu nang khi chay lai).
    // busy_timeout NGUOC LAI la thuoc tinh THEO TUNG CONNECTION rieng (Sqlite
    // khong luu no vao file DB) — BAT BUOC phai dat lai o MOI Open(), neu
    // khong connection moi se dung gia tri mac dinh (0ms) va nem
    // SQLITE_BUSY ngay lap tuc thay vi cho toi 5s khi gap lock.
    protected SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using (var pragmaCmd = conn.CreateCommand())
        {
            pragmaCmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;";
            pragmaCmd.ExecuteNonQuery();
        }
        return conn;
    }

    // [SUA LOI CAO] TRUOC DAY khong MOT store nao trong 12 store SQLite cua
    // san pham co danh so phien ban schema: 0 PRAGMA user_version, 0 ALTER
    // TABLE, 0 migration runner, 0 duong lui. Moi store chi chay
    // "CREATE TABLE IF NOT EXISTS ..." moi lan khoi tao, nghia la:
    //   - DB tao boi ban CU gap ban MOI: bang da ton tai nen CREATE ... IF
    //     NOT EXISTS khong lam gi ca; cot moi KHONG BAO GIO duoc them; moi
    //     truy van cham cot do nem luc chay, tren may nguoi dung, sau khi
    //     cap nhat — chinh la kich ban da lam RuleStore chan service khoi
    //     dong (xem ghi chu UNIQUE INDEX trong RuleStore.cs);
    //   - DB tao boi ban MOI gap ban CU (ha cap/rollback): ban cu doc mot
    //     schema no khong hieu va am tham lam sai.
    // Khong co danh so thi khong the phat hien duoc ca hai truong hop.
    //
    // Ham nay them lop danh so + migration cho MOI store ke thua:
    //   - DB moi tinh (user_version = 0): chay toan bo migrations, dat
    //     user_version = migrations.Count;
    //   - DB cu hon: chi chay cac migration con thieu, theo thu tu;
    //   - DB MOI HON ban code nay biet: TU CHOI (nem) — mot binary cu mo
    //     schema tuong lai la duong ngan nhat toi hong du lieu, va no phai
    //     that bai TO va SOM chu khong am tham.
    // Toan bo chay trong MOT transaction de khong bao gio ket thuc o trang
    // thai "da chay nua chung".
    protected void EnsureSchema(SqliteConnection conn, IReadOnlyList<string> migrations)
    {
        int current = GetSchemaVersion(conn);

        if (current > migrations.Count)
        {
            throw new InvalidOperationException(
                $"CSDL '{_connectionString}' co schema phien ban {current}, nhung ban code nay chi biet toi phien ban {migrations.Count}. " +
                "Rat co the CSDL da duoc mot ban cai MOI HON ghi. Tu choi mo de tranh lam hong du lieu — hay cap nhat ung dung.");
        }

        if (current == migrations.Count) return; // da dung phien ban

        using var tx = conn.BeginTransaction();
        for (int v = current; v < migrations.Count; v++)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = migrations[v];
            cmd.ExecuteNonQuery();
        }

        // PRAGMA user_version khong nhan tham so binding, va gia tri o day
        // luon la mot int do CHINH code nay sinh ra (khong phai dau vao
        // ngoai) nen noi suy la an toan.
        using (var versionCmd = conn.CreateCommand())
        {
            versionCmd.Transaction = tx;
            versionCmd.CommandText = $"PRAGMA user_version = {migrations.Count};";
            versionCmd.ExecuteNonQuery();
        }

        tx.Commit();
    }

    protected static int GetSchemaVersion(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA user_version;";
        var result = cmd.ExecuteScalar();
        return result is null ? 0 : Convert.ToInt32(result);
    }
}
