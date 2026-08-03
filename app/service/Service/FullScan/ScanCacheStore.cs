using Microsoft.Data.Sqlite;
using Antivirus.Service.Models;

namespace Antivirus.Service.FullScan;

// [TINH NANG THEO YEU CAU NGUOI DUNG] Cache ket qua full scan giua cac lan
// chay: neu mot file KHONG DOI (cung duong dan + mtime + kich thuoc) VA
// CSDL signature KHONG DOI (cung version) so voi lan quet truoc, bo qua
// quet lai, dung thang ket qua da luu — giam thoi gian cho lan quet lap
// lai tu hang gio xuong con vai phut (chi quet file moi/da doi).
//
// DIEM AN TOAN BAT BUOC: cache PHAI gan voi signature_db_version. Neu chi
// dung (path, mtime, size) ma khong kiem tra version CSDL, mot file tung
// duoc ket luan Clean duoi CSDL CU se bi bo qua VINH VIEN ke ca sau khi
// CSDL MOI da co chu ky nhan dien no la ma doc — day la lo hong bao mat
// that, khong chi la toi uu sai. UpdateClientService goi ClearAll() moi
// khi ap dung CSDL moi thanh cong de dam bao khong bao gio xay ra truong
// hop nay.
public sealed class ScanCacheStore
{
    private readonly string _connectionString;

    public ScanCacheStore(string dbPath)
    {
        // [SUA LOI HIEU NANG] TRUOC DAY busy_timeout duoc dat lai bang mot
        // lenh PRAGMA THUC THI RIENG tren MOI Open() (xem lich su ham Open()
        // duoi day) — ke ca tren duong CACHE-HIT nong nhat (TryGetCached goi
        // MOI file duoc quet trong full scan), moi lan nhu vay ton them mot
        // round-trip prepare/step/finalize khong can thiet. Microsoft.Data.
        // Sqlite ho tro dat busy timeout NGAY TRONG connection string qua
        // "Default Timeout" (giay) — provider tu ap dung sqlite3_busy_timeout
        // luc mo ket noi, KHONG can lenh PRAGMA thu cong nao nua. Sua: chuyen
        // sang co che nay, loai bo hoan toan chi phi PRAGMA lap lai tren
        // duong nong.
        _connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            DefaultTimeout = 5, // giay — tuong duong PRAGMA busy_timeout=5000 truoc day
        }.ToString();
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS scan_cache (
                file_path TEXT PRIMARY KEY,
                last_write_ticks INTEGER NOT NULL,
                file_size INTEGER NOT NULL,
                signature_db_version INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                stage TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                reason TEXT NOT NULL,
                cached_at INTEGER NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    // [SUA LOI HIEU NANG] TRUOC DAY moi lan doc/ghi cache (TryGetCached/
    // Upsert) mo MOT connection + transaction rieng, goi tu NHIEU worker
    // thread song song (moi file trong full scan mot lan), KHONG bat WAL
    // (mac dinh rollback journal khoa TOAN BO file DB moi lan ghi, chan ca
    // doc dong thoi) VA khong dat busy_timeout (SQLite nem loi "database is
    // locked" ngay lap tuc thay vi doi) — tren may co hang tram nghin file,
    // day la nghen co chai I/O/lock contention nghiem trong, lam scan cham
    // han hoac loi giua chung. Sua: bat WAL mode (cho phep nhieu doc gia
    // dong thoi voi 1 ghi, giam khoa) trong Initialize(), va dat busy_timeout
    // qua "Default Timeout" TRONG CONNECTION STRING (xem constructor) — day
    // la thiet lap provider ap dung TU DONG luc Open(), khong con can thuc
    // thi mot lenh PRAGMA rieng tren MOI Open() nua (truoc day dieu nay lap
    // lai ke ca tren duong cache-hit nong nhat, xem [SUA LOI HIEU NANG #2]
    // tai constructor).
    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    // Chi cho ket qua khop CA BA: duong dan, mtime, kich thuoc — VA cung
    // dung signature_db_version hien tai. Khac bat ky dieu kien nao -> coi
    // nhu cache miss, quet lai that.
    public ScanResultDto? TryGetCached(string path, long lastWriteTicks, long fileSize, int currentSignatureDbVersion)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT verdict, stage, sha256_hash, reason FROM scan_cache
            WHERE file_path = $path AND last_write_ticks = $ticks AND file_size = $size AND signature_db_version = $ver
            """;
        cmd.Parameters.AddWithValue("$path", path);
        cmd.Parameters.AddWithValue("$ticks", lastWriteTicks);
        cmd.Parameters.AddWithValue("$size", fileSize);
        cmd.Parameters.AddWithValue("$ver", currentSignatureDbVersion);

        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;

        return new ScanResultDto
        {
            Verdict = Enum.Parse<ScanVerdict>(reader.GetString(0)),
            Stage = Enum.Parse<DetectionStage>(reader.GetString(1)),
            Sha256Hex = reader.GetString(2),
            Reason = reader.GetString(3) + " [tu cache — file khong doi tu lan quet truoc, cung phien ban CSDL]",
        };
    }

    public void Upsert(string path, long lastWriteTicks, long fileSize, int signatureDbVersion, ScanResultDto result)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scan_cache (file_path, last_write_ticks, file_size, signature_db_version, verdict, stage, sha256_hash, reason, cached_at)
            VALUES ($path, $ticks, $size, $ver, $verdict, $stage, $hash, $reason, $now)
            ON CONFLICT(file_path) DO UPDATE SET
                last_write_ticks = excluded.last_write_ticks,
                file_size = excluded.file_size,
                signature_db_version = excluded.signature_db_version,
                verdict = excluded.verdict,
                stage = excluded.stage,
                sha256_hash = excluded.sha256_hash,
                reason = excluded.reason,
                cached_at = excluded.cached_at
            """;
        cmd.Parameters.AddWithValue("$path", path);
        cmd.Parameters.AddWithValue("$ticks", lastWriteTicks);
        cmd.Parameters.AddWithValue("$size", fileSize);
        cmd.Parameters.AddWithValue("$ver", signatureDbVersion);
        cmd.Parameters.AddWithValue("$verdict", result.Verdict.ToString());
        cmd.Parameters.AddWithValue("$stage", result.Stage.ToString());
        cmd.Parameters.AddWithValue("$hash", result.Sha256Hex);
        cmd.Parameters.AddWithValue("$reason", result.Reason);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    // Goi tu UpdateClientService sau MOI lan ap dung CSDL moi thanh cong —
    // xem ghi chu bao mat o dau file.
    public void ClearAll()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM scan_cache";
        cmd.ExecuteNonQuery();
    }

    public long Count()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM scan_cache";
        return (long)cmd.ExecuteScalar()!;
    }
}
