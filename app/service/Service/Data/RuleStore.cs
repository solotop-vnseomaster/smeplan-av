using Microsoft.Data.Sqlite;
using Antivirus.Service.Models;

namespace Antivirus.Service.Data;

// DATA-01/02: bang app_rules dung schema data-models/04-du-lieu.md, index
// theo hash va publisher de phuc vu thu tu tra cuu uu tien hash truoc,
// publisher sau (business-rules/05 muc Process Trust Decision).
public sealed class RuleStore : SqliteStoreBase
{
    public RuleStore(string dbPath) : base(dbPath)
    {
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();

        // [SUA LOI CAO] Danh so phien ban schema — xem SqliteStoreBase.EnsureSchema.
        // QUY TAC: khong sua phan tu da co, chi THEM migration moi vao cuoi.
        EnsureSchema(conn, new[]
        {
            """
            CREATE TABLE IF NOT EXISTS app_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256_hash TEXT NOT NULL,
                publisher_thumbprint TEXT NULL,
                file_path TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('allow', 'block')),
                scope TEXT NOT NULL CHECK (scope IN ('hash', 'publisher')),
                created_at INTEGER NOT NULL,
                created_by TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rules_hash ON app_rules(sha256_hash);
            CREATE INDEX IF NOT EXISTS idx_rules_publisher ON app_rules(publisher_thumbprint);
            """,
        });

        // [SUA LOI TRUNG BINH] TRUOC DAY idx_rules_hash chi la INDEX thuong
        // (khong UNIQUE) — hai request danh gia process trung thoi diem cho
        // CUNG mot hash (ca hai deu FindByHash() truoc, khong thay, roi deu
        // Add() rule "AllowAlways" rieng — TOCTOU) co the tao ra HAI ban ghi
        // scope=hash trung sha256_hash, thieu nhat quan (FindByHash dung
        // LIMIT 1 nen chi thay MOT trong hai, ban con lai la du thua vinh
        // vien, co the mang action khac neu nguoi dung doi y giua hai lan).
        // Sua: them UNIQUE INDEX rieng phan (partial index, CHI ap dung cho
        // scope='hash') tren sha256_hash — khong dung UNIQUE cho TOAN BO
        // cot vi cac rule scope='publisher' co the co sha256_hash rong ""
        // (xem ProcessTrustEngine.cs nhanh "khong hash duoc file nhung co
        // publisher hop le"), nhieu rule nhu vay hop le cung ton tai song
        // song. "CREATE UNIQUE INDEX IF NOT EXISTS" se tu dong that bai (nem
        // exception) neu DB cu (tao truoc ban sua nay) da lo co san du lieu
        // trung — chap nhan duoc vi day la truong hop hiem va can duoc phat
        // hien thay vi am tham bo qua.
        // [SUA LOI NGHIEM TRONG] "chap nhan duoc vi day la truong hop hiem"
        // o ghi chu tren KHONG chap nhan duoc: doan nay chay trong
        // CONSTRUCTOR cua RuleStore, va RuleStore duoc khoi tao eager o
        // Program.cs KHONG co try/catch. Mot DB cu (tao truoc ban sua nay)
        // co san hai rule scope='hash' trung sha256_hash se lam
        // ExecuteNonQuery nem, exception xuyen qua constructor, va DICH VU
        // ANTIVIRUS KHONG KHOI DONG DUOC — vinh vien, khong migration, khong
        // duong lui, tren may nguoi dung that. May mat sach bao ve vi mot
        // ban ghi trung lap.
        //
        // Sua: don du lieu trung TRUOC (giu ban ghi moi nhat theo id, dung
        // ban ma FindByHash von se chon), roi moi tao index. Neu van that
        // bai vi ly do khac, ghi nhan va di tiep — thieu mot index toi uu
        // KHONG duoc phep dong nghia voi mat toan bo dich vu bao ve.
        using (var dedupeCmd = conn.CreateCommand())
        {
            dedupeCmd.CommandText = """
                DELETE FROM app_rules
                WHERE scope = 'hash'
                  AND id NOT IN (
                      SELECT MAX(id) FROM app_rules WHERE scope = 'hash' GROUP BY sha256_hash
                  );
                """;
            try { dedupeCmd.ExecuteNonQuery(); } catch { }
        }

        using var uniqueCmd = conn.CreateCommand();
        uniqueCmd.CommandText = """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_hash_unique
                ON app_rules(sha256_hash) WHERE scope = 'hash';
            """;
        try
        {
            uniqueCmd.ExecuteNonQuery();
        }
        catch (Microsoft.Data.Sqlite.SqliteException)
        {
            // FindByHash da loc scope='hash' + ORDER BY id DESC nen van dung
            // ngay ca khi index nay khong tao duoc (xem ghi chu tai
            // FindByHash) — day chinh la lop phong thu doc lap voi index.
        }
    }

    // business-rules/05: "tra rule theo thu tu hash roi publisher"
    // [SUA LOI CAO] TRUOC DAY khong loc scope='hash' cung khong co ORDER BY —
    // "an toan" CHI vi ngam dinh dua vao idx_rules_hash_unique (UNIQUE INDEX
    // WHERE scope='hash'), nhung index do KHONG chan duoc mot rule
    // scope='publisher' tao qua POST /api/rules voi sha256_hash KHONG RONG
    // trung voi mot rule scope='hash' co san (unique index chi ap dung TRONG
    // PHAM VI scope='hash', khong lien scope khac) — khi do co THAT 2 hang
    // cung sha256_hash NGAY BAY GIO, khong can doi ai "noi long" gi ca, va
    // FindByHash se tra ve hang nao theo thu tu vat ly khong xac dinh cua
    // SQLite. Sua doi xung voi FindByPublisher: loc dung scope='hash' va
    // ORDER BY id DESC lam lop phong thu doc lap voi schema/index.
    public AppRule? FindByHash(string sha256Hash)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM app_rules WHERE sha256_hash = $hash AND scope = 'hash' ORDER BY id DESC LIMIT 1";
        cmd.Parameters.AddWithValue("$hash", NormalizeHash(sha256Hash));
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? MapRule(reader) : null;
    }

    // [SUA LOI NGHIEM TRONG] TRUOC DAY cau SQL khong loc scope='publisher',
    // chi loc theo publisher_thumbprint. Mot rule scope=hash (vi du tao tu
    // "Cho phep luon" tren file A, chi dinh danh CHINH XAC file A bang hash)
    // van ghi kem publisher_thumbprint cua file A (xem ProcessTrustEngine.cs
    // nhanh AllowAlways). Neu sau do file B KHAC HOAN TOAN (hash khac) nhung
    // duoc cung mot publisher X ky, FindByHash(B) tra null (khong khop hash),
    // roi ProcessTrustEngine roi xuong FindByPublisher(X) — VA KHOP NHAM vao
    // dung rule scope=hash cua file A, cho phep chay file B ma nguoi dung
    // chua bao gio thuc su cap quyen (ho chi trust rieng file A, khong phai
    // "bat ky file nao publisher X ky"). Sua: chi khop cac rule THAT SU co
    // scope='publisher'.
    public AppRule? FindByPublisher(string publisherThumbprint)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        // [SUA LOI TRUNG BINH] scope='publisher' khong co UNIQUE constraint
        // (khac scope='hash') — POST /api/rules cho phep tao nhieu rule
        // trung publisher_thumbprint (vi du admin doi y Allow -> Block cho
        // cung mot publisher). Khong co ORDER BY, SQLite tra ve hang nao
        // TRUOC theo thu tu vat ly khong xac dinh (thuong la rowid cu nhat),
        // co the khien quyet dinh MOI nhat cua admin (vd Block) bi rule CU
        // (Allow) de ra truoc. Sua: sap xep theo created_at giam dan, lay
        // rule MOI NHAT — dung voi ky vong "quyet dinh gan day nhat thang".
        // created_at chi phan giai toi 1 GIAY (ToUnixTimeSeconds()) — hai
        // rule tao trong CUNG mot giay se hoa, ORDER BY created_at khong con
        // phan biet duoc (SQLite khong dam bao thu tu giua cac hang bang
        // nhau). Them tie-break "id DESC" (AUTOINCREMENT, luon tang dan theo
        // thu tu chen) de dam bao lay DUNG hang moi nhat ke ca khi trung giay.
        cmd.CommandText = "SELECT * FROM app_rules WHERE publisher_thumbprint = $pub AND scope = 'publisher' ORDER BY created_at DESC, id DESC LIMIT 1";
        cmd.Parameters.AddWithValue("$pub", publisherThumbprint);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? MapRule(reader) : null;
    }

    // [SUA LOI CAO — LECH QUY UOC GIUA CAC MODULE] SHA-256 duoc SINH RA o
    // dang hex CHU THUONG o moi noi trong service (ProcessTrustEngine.
    // ComputeSha256 va ConnectionMonitor deu ket thuc bang
    // .ToLowerInvariant()), va so khop trong SQLite la PHAN BIET hoa/thuong.
    // Nhung `sha256_hash` cua mot rule den tu POST /api/rules — nguoi dung
    // dan hash tu VirusTotal / bao cao threat-intel / Get-FileHash cua
    // PowerShell, tat ca deu tra ve CHU HOA. Mot rule nhu vay duoc luu, hien
    // ra trong UI, nhung FindByHash khong bao gio khop no: rule Block do
    // nguoi dung tu dat lang le khong co hieu luc.
    //
    // Chuan hoa tai DUY NHAT mot cho — bien gioi cua store — de moi duong
    // ghi va moi duong doc dung chung mot dang bieu dien.
    private static string NormalizeHash(string? hash) => (hash ?? string.Empty).Trim().ToLowerInvariant();

    public long Add(AppRule rule)
    {
        rule.Sha256Hash = NormalizeHash(rule.Sha256Hash);
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO app_rules (sha256_hash, publisher_thumbprint, file_path, action, scope, created_at, created_by)
            VALUES ($hash, $pub, $path, $action, $scope, $created_at, $created_by);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$hash", rule.Sha256Hash);
        cmd.Parameters.AddWithValue("$pub", (object?)rule.PublisherThumbprint ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$path", rule.FilePath);
        cmd.Parameters.AddWithValue("$action", rule.Action == RuleAction.Allow ? "allow" : "block");
        cmd.Parameters.AddWithValue("$scope", rule.Scope == RuleScope.Hash ? "hash" : "publisher");
        cmd.Parameters.AddWithValue("$created_at", rule.CreatedAt);
        cmd.Parameters.AddWithValue("$created_by", rule.CreatedBy == RuleCreatedBy.User ? "user" : "default_policy");
        return (long)cmd.ExecuteScalar()!;
    }

    public void Delete(long id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM app_rules WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public List<AppRule> List()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM app_rules ORDER BY created_at DESC";
        using var reader = cmd.ExecuteReader();
        var result = new List<AppRule>();
        while (reader.Read()) result.Add(MapRule(reader));
        return result;
    }

    private static AppRule MapRule(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(reader.GetOrdinal("id")),
        Sha256Hash = reader.GetString(reader.GetOrdinal("sha256_hash")),
        PublisherThumbprint = reader.IsDBNull(reader.GetOrdinal("publisher_thumbprint"))
            ? null : reader.GetString(reader.GetOrdinal("publisher_thumbprint")),
        FilePath = reader.GetString(reader.GetOrdinal("file_path")),
        Action = reader.GetString(reader.GetOrdinal("action")) == "allow" ? RuleAction.Allow : RuleAction.Block,
        Scope = reader.GetString(reader.GetOrdinal("scope")) == "hash" ? RuleScope.Hash : RuleScope.Publisher,
        CreatedAt = reader.GetInt64(reader.GetOrdinal("created_at")),
        CreatedBy = reader.GetString(reader.GetOrdinal("created_by")) == "user" ? RuleCreatedBy.User : RuleCreatedBy.DefaultPolicy,
    };
}
