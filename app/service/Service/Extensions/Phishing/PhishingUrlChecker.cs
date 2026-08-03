namespace Antivirus.Service.Extensions.Phishing;

public sealed record PhishingCheckResult(bool Malicious, string? MatchedOn, string? MatchedValue);

// "tai lieu moi.txt" muc "Tich hop canh bao phishing vao trinh duyet":
// "logic kiem tra (doi chieu danh sach phishing, goi cloud threat
// intelligence) nam o service, extension chi la lop chuyen tiep mong" —
// day chinh la logic do, lo ra qua API-05 cho native host/extension goi.
public sealed class PhishingUrlChecker
{
    private readonly PhishingListStore _store;

    public PhishingUrlChecker(PhishingListStore store)
    {
        _store = store;
    }

    public PhishingCheckResult CheckUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return new PhishingCheckResult(false, null, null);
        }

        var host = uri.Host;

        // [SUA LOI NGHIEM TRONG] DNS cho phep mot dau cham "goc" o cuoi FQDN
        // (vi du "evil.com." — trinh duyet/resolver phan giai HOAN TOAN
        // giong "evil.com"), nhung uri.Host GIU NGUYEN dau cham nay va
        // IsDomainListed/IsIpListed ben duoi so sanh chuoi TUYET DOI — URL
        // "http://evil.com./..." vi vay khong khop bat ky entry nao trong
        // blocklist (vi du "evil.com"), bypass hoan toan kiem tra du trinh
        // duyet van mo dung site bi chan. Sua: bo dau cham cuoi truoc khi
        // so sanh, dung ky thuat evasion pho bien nay khong con tac dung.
        host = host.TrimEnd('.');

        if (Uri.CheckHostName(host) == UriHostNameType.IPv4 || Uri.CheckHostName(host) == UriHostNameType.IPv6)
        {
            if (_store.IsIpListed(host)) return new PhishingCheckResult(true, "ip", host);
            return new PhishingCheckResult(false, null, null);
        }

        // Kiem tra ca domain day du LAN domain cha (vi du "login.evil.com"
        // khop neu danh sach chi co "evil.com") — domain phishing thuong
        // dung them subdomain ngau nhien de ne cac danh sach chi khop tuyet doi.
        var labels = host.Split('.');
        for (int i = 0; i < labels.Length - 1; i++)
        {
            var candidate = string.Join('.', labels[i..]);
            if (_store.IsDomainListed(candidate))
            {
                return new PhishingCheckResult(true, "domain", candidate);
            }
        }

        return new PhishingCheckResult(false, null, null);
    }
}
