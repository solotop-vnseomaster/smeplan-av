namespace Antivirus.Service.Models;

// data-models/04-du-lieu.md muc app_rules
public sealed class AppRule
{
    public long Id { get; set; }
    public required string Sha256Hash { get; set; }
    public string? PublisherThumbprint { get; set; }
    public required string FilePath { get; set; }
    public RuleAction Action { get; set; }
    public RuleScope Scope { get; set; }
    public long CreatedAt { get; set; }
    public RuleCreatedBy CreatedBy { get; set; }
}

// data-models/04-du-lieu.md muc QuarantineRecord — bo sung truong Status
// theo de xuat thong nhat trong 00-doi-chieu-cheo.md (xem features.md DATA-03).
public sealed class QuarantineRecord
{
    public required string QuarantineId { get; set; }
    public required string OriginalPath { get; set; }
    public required string OriginalFilename { get; set; }
    public required string Sha256Hash { get; set; }
    public required string DetectionReason { get; set; }
    public long QuarantinedAt { get; set; }
    public ulong FileSize { get; set; }
    public QuarantineStatus Status { get; set; }
}

public sealed class ScanResultDto
{
    public ScanVerdict Verdict { get; set; }
    public DetectionStage Stage { get; set; }
    public uint ThreatId { get; set; }
    public byte Severity { get; set; }
    public uint HeuristicScore { get; set; }
    public string Sha256Hex { get; set; } = "";
    public string Reason { get; set; } = "";
}

// business-rules/05: ket qua quyet dinh Process Trust cho mot tien trinh moi.
public sealed class ProcessTrustDecision
{
    public required string ProcessPath { get; set; }
    public int Pid { get; set; }
    public required string Sha256 { get; set; }
    public string? PublisherThumbprint { get; set; }
    public string? PublisherName { get; set; }
    public ProcessTrustState State { get; set; }
    public bool Allowed { get; set; }
    public required string Reason { get; set; }
    public long ElapsedMs { get; set; }
}

// Ban ghi audit trail ky thuat (structured JSON lines) — modules/02-kien-truc.md
// muc 3 "Luong ghi log": "khong hien thi truc tiep cho nguoi dung; mot ban tom
// tat duoc loc va dien giai lai tu audit trail de hien thi tren UI".
public sealed class AuditEvent
{
    public required string EventId { get; set; }
    public long TimestampUnixMs { get; set; }
    public required string Category { get; set; } // "process-trust" | "scan" | "quarantine" | "rule" | "update"
    public required string Summary { get; set; }
    public object? Detail { get; set; }
}
