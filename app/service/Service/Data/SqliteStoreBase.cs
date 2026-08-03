using Microsoft.Data.Sqlite;

namespace Antivirus.Service.Data;

// [TAI CAU TRUC] RuleStore va QuarantineStore truoc day tu lap lai y het
// logic mo SqliteConnection (field _connectionString + ham Open() rieng),
// khong co lop co so chung — de quen bat mot cross-cutting concern (WAL,
// busy_timeout, retry...) o MOT file ma khong sua file kia khi can sua dong
// thoi ca hai. ScanCacheStore.cs (FullScan/) tung phai vá rieng loi hieu
// nang chinh vi thieu WAL + busy_timeout (xem ghi chu "[SUA LOI HIEU NANG]"
// trong file do) — RuleStore/QuarantineStore van chua co cung co che do.
// Lop co so nay CHI ap dung cho cac store trong Data/ (pham vi cua lan sua
// nay); KHONG dong den cac SqliteConnection store khac duoi Extensions/
// (thuoc pham vi mot agent khac dang sua song song).
public abstract class SqliteStoreBase
{
    private readonly string _connectionString;

    protected SqliteStoreBase(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
    }

    // Bat WAL (cho phep nhieu doc dong thoi voi 1 ghi, giam khoa toan bo
    // file DB moi lan ghi) + dat busy_timeout TREN MOI CONNECTION (day la
    // pragma theo tung ket noi, khong luu trong file DB nen phai dat lai
    // moi lan Open()) — giam nghen co chai lock contention khi nhieu
    // luong/tien trinh cung truy cap CSDL, cung ly do da tung sua rieng le
    // trong ScanCacheStore.cs.
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
}
