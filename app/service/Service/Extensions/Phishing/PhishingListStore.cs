using Microsoft.Data.Sqlite;
using Antivirus.Service.Data;

namespace Antivirus.Service.Extensions.Phishing;

// "tai lieu moi.txt" muc "Chan URL va domain phishing o tang mang": danh
// sach domain/IP phishing phai den tu nguon CAP NHAT THUONG XUYEN, khong
// phai danh sach tinh dong goi san.
// [SUA LOI HIEU NANG] Chuyen sang SqliteStoreBase (WAL + busy_timeout) —
// truoc day tu mo SqliteConnection rieng, cung mot lo hong "database is
// locked" ma ScanCacheStore.cs tung phai vá rieng (xem SqliteStoreBase.cs).
// ReplaceAll() dung transaction ghi toan bo danh sach — dac biet de bi
// nghen neu co request doc (FindMostSpecificListedDomain/IsIpListed) dong
// thoi ma khong co WAL.
public sealed class PhishingListStore : SqliteStoreBase
{
    public PhishingListStore(string dbPath) : base(dbPath)
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
            CREATE TABLE IF NOT EXISTS phishing_domains (domain TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS phishing_ips (ip TEXT PRIMARY KEY);
            """,
        });
    }

    public void ReplaceAll(IEnumerable<string> domains, IEnumerable<string> ips)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();

        using (var clearCmd = conn.CreateCommand())
        {
            clearCmd.Transaction = tx;
            clearCmd.CommandText = "DELETE FROM phishing_domains; DELETE FROM phishing_ips;";
            clearCmd.ExecuteNonQuery();
        }

        using (var insertDomain = conn.CreateCommand())
        {
            insertDomain.Transaction = tx;
            insertDomain.CommandText = "INSERT OR IGNORE INTO phishing_domains (domain) VALUES ($d)";
            var param = insertDomain.CreateParameter();
            param.ParameterName = "$d";
            insertDomain.Parameters.Add(param);
            foreach (var domain in domains)
            {
                param.Value = domain.Trim().ToLowerInvariant();
                insertDomain.ExecuteNonQuery();
            }
        }

        using (var insertIp = conn.CreateCommand())
        {
            insertIp.Transaction = tx;
            insertIp.CommandText = "INSERT OR IGNORE INTO phishing_ips (ip) VALUES ($ip)";
            var param = insertIp.CreateParameter();
            param.ParameterName = "$ip";
            insertIp.Parameters.Add(param);
            foreach (var ip in ips)
            {
                param.Value = ip.Trim();
                insertIp.ExecuteNonQuery();
            }
        }

        tx.Commit();
    }

    // [SUA LOI HIEU NANG] PhishingUrlChecker.CheckUrl truoc day goi
    // IsDomainListed() RIENG BIET cho MOI domain-label cha (vi du
    // "a.b.evil.com" -> toi da 3 lan goi rieng: "a.b.evil.com", "b.evil.com",
    // "evil.com") — moi lan la MOT connection SQLite rieng (Open() moi lan)
    // + MOT round-trip rieng, tren hot path THAT SU (extension trinh duyet
    // goi API nay MOI LAN dieu huong trang). Ham nay kiem tra TAT CA cac
    // ung vien trong MOT connection + MOT cau lenh SQL (IN (...)) thay vi N
    // lan mo/dong connection + N truy van rieng le.
    public string? FindMostSpecificListedDomain(IReadOnlyList<string> candidatesByPriority)
    {
        if (candidatesByPriority.Count == 0) return null;

        var normalized = candidatesByPriority.Select(c => c.Trim().ToLowerInvariant()).ToList();

        using var conn = Open();
        using var cmd = conn.CreateCommand();
        var paramNames = new string[normalized.Count];
        for (int i = 0; i < normalized.Count; i++)
        {
            paramNames[i] = $"$d{i}";
            cmd.Parameters.AddWithValue(paramNames[i], normalized[i]);
        }
        cmd.CommandText = $"SELECT domain FROM phishing_domains WHERE domain IN ({string.Join(",", paramNames)})";

        var matched = new HashSet<string>(StringComparer.Ordinal);
        using (var reader = cmd.ExecuteReader())
        {
            while (reader.Read()) matched.Add(reader.GetString(0));
        }

        // Tra ve theo dung thu tu uu tien cua candidatesByPriority (tu cu
        // the nhat den chung nhat), khong phai thu tu tra ve tu SQLite.
        return normalized.FirstOrDefault(c => matched.Contains(c));
    }

    public bool IsIpListed(string ip)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(1) FROM phishing_ips WHERE ip = $ip";
        cmd.Parameters.AddWithValue("$ip", ip.Trim());
        return (long)cmd.ExecuteScalar()! > 0;
    }

    public (int Domains, int Ips) Count()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT (SELECT COUNT(1) FROM phishing_domains), (SELECT COUNT(1) FROM phishing_ips)";
        using var reader = cmd.ExecuteReader();
        reader.Read();
        return (reader.GetInt32(0), reader.GetInt32(1));
    }
}
