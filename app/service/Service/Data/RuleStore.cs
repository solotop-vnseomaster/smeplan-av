using Microsoft.Data.Sqlite;
using Antivirus.Service.Models;

namespace Antivirus.Service.Data;

// DATA-01/02: bang app_rules dung schema data-models/04-du-lieu.md, index
// theo hash va publisher de phuc vu thu tu tra cuu uu tien hash truoc,
// publisher sau (business-rules/05 muc Process Trust Decision).
public sealed class RuleStore
{
    private readonly string _connectionString;

    public RuleStore(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
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
            """;
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    // business-rules/05: "tra rule theo thu tu hash roi publisher"
    public AppRule? FindByHash(string sha256Hash)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM app_rules WHERE sha256_hash = $hash LIMIT 1";
        cmd.Parameters.AddWithValue("$hash", sha256Hash);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? MapRule(reader) : null;
    }

    public AppRule? FindByPublisher(string publisherThumbprint)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM app_rules WHERE publisher_thumbprint = $pub LIMIT 1";
        cmd.Parameters.AddWithValue("$pub", publisherThumbprint);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? MapRule(reader) : null;
    }

    public long Add(AppRule rule)
    {
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
