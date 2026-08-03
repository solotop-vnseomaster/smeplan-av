namespace Antivirus.Service.Models;

// business-rules/05-nghiep-vu.md muc "Ket qua quet file (Scan Verdict)"
public enum ScanVerdict
{
    Clean = 0,
    Malicious = 1,
    Suspicious = 2,
    ScanError = 3
}

public enum DetectionStage
{
    None = 0,
    HashSignature = 1,
    Yara = 2,
    Heuristic = 3,
    ZipBombGuard = 4,
    IoError = 5
}

// business-rules/05-nghiep-vu.md muc "Quyet dinh cap quyen cho tien trinh moi
// (Process Trust Decision)" — day du 9 trang thai dung nhu spec.
public enum ProcessTrustState
{
    Unknown = 0,
    TrustedByDefault = 1,
    RuleAllow = 2,
    RuleBlock = 3,
    PendingUserDecision = 4,
    AllowedAlways = 5,
    AllowedOnce = 6,
    Blocked = 7,
    DeniedByTimeout = 8
}

// business-rules/05-nghiep-vu.md muc "File trong Quarantine"
public enum QuarantineStatus
{
    Active = 0,
    PendingManualConfirmation = 1,
    Quarantined = 2,
    Restored = 3
}

// data-models/04-du-lieu.md muc app_rules
public enum RuleAction
{
    Allow,
    Block
}

public enum RuleScope
{
    Hash,
    Publisher
}

public enum RuleCreatedBy
{
    User,
    DefaultPolicy
}

// business-rules/05-nghiep-vu.md muc "Rule heuristic/YARA (Log-only -> Enforce)"
public enum RuleLifecycleState
{
    LogOnly,
    Enforce
}
