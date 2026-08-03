using Microsoft.Data.Sqlite;

namespace Antivirus.Service.Extensions.Phishing;

// "tai lieu moi.txt" muc "Chan URL va domain phishing o tang mang": danh
// sach domain/IP phishing phai den tu nguon CAP NHAT THUONG XUYEN, khong
// phai danh sach tinh dong goi san.
public sealed class PhishingListStore
{
    private readonly string _connectionString;

    public PhishingListStore(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS phishing_domains (domain TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS phishing_ips (ip TEXT PRIMARY KEY);
            """;
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
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

    public bool IsDomainListed(string domain)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(1) FROM phishing_domains WHERE domain = $d";
        cmd.Parameters.AddWithValue("$d", domain.Trim().ToLowerInvariant());
        return (long)cmd.ExecuteScalar()! > 0;
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
